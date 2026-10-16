// SPDX-License-Identifier: GPL-2.0
/*
 * ringbuf - character devices backed by kernel ring buffers.
 *
 * Each /dev/ringbufN is an independent byte FIFO with pipe-like semantics:
 *  - read() returns whatever is available and blocks only while empty;
 *  - write() blocks until everything is written, and writes no larger than
 *    the capacity are atomic, so concurrent writers never interleave them
 *    (the same guarantee pipe(7) gives for PIPE_BUF);
 *  - O_NONBLOCK, poll/select/epoll and signal interruption are supported;
 *  - ioctl() reads statistics, clears and resizes the buffer, and the same
 *    counters are exported under /sys/class/ringbuf/ringbufN/.
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/minmax.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/poll.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/wait.h>

#include "ringbuf_ioctl.h"

#define RINGBUF_MAX_DEVICES	16

static unsigned int ndevices = 2;
module_param(ndevices, uint, 0444);
MODULE_PARM_DESC(ndevices, "Number of /dev/ringbufN devices (1-16, default 2)");

static unsigned int bufsize = 4096;
module_param(bufsize, uint, 0444);
MODULE_PARM_DESC(bufsize, "Initial capacity in bytes (16-1048576, default 4096)");

struct ringbuf_dev {
	/*
	 * Protects all fields below. @count and @size are also read without
	 * the lock in wait conditions, so they are updated with WRITE_ONCE();
	 * every decision is re-checked under the lock afterwards.
	 */
	struct mutex lock;
	char *buf;
	size_t size;			/* capacity in bytes */
	size_t head;			/* next byte to write */
	size_t tail;			/* next byte to read */
	size_t count;			/* bytes stored */
	u64 bytes_written;
	u64 bytes_read;
	unsigned int open_count;

	wait_queue_head_t readq;	/* readers waiting for data */
	wait_queue_head_t writeq;	/* writers waiting for space */
	struct cdev cdev;
	struct device *dev;
};

static dev_t ringbuf_devt;
static struct class *ringbuf_class;
static struct ringbuf_dev *ringbuf_devs;

/* ---------------------------------------------------------------------- */
/* Ring buffer helpers. Callers of the copy helpers hold rb->lock.          */

static bool rb_readable(const struct ringbuf_dev *rb)
{
	return READ_ONCE(rb->count) > 0;
}

/*
 * A write of @len bytes may proceed when the whole write fits (if it is no
 * larger than the capacity, so it stays atomic), or when any space is free
 * (if it is larger, and will be split anyway).
 */
static bool rb_writable(const struct ringbuf_dev *rb, size_t len)
{
	size_t size = READ_ONCE(rb->size);
	size_t count = READ_ONCE(rb->count);
	size_t space = count < size ? size - count : 0;

	return len <= size ? space >= len : space > 0;
}

/*
 * The wait helpers are entered with rb->lock held. They return 0 with the
 * lock still held once the operation can proceed, or an error with the lock
 * released (-EAGAIN for O_NONBLOCK, -ERESTARTSYS if a signal arrived).
 */
static int rb_wait_readable(struct ringbuf_dev *rb, struct file *filp)
{
	while (!rb->count) {
		mutex_unlock(&rb->lock);
		if (filp->f_flags & O_NONBLOCK)
			return -EAGAIN;
		if (wait_event_interruptible(rb->readq, rb_readable(rb)))
			return -ERESTARTSYS;
		if (mutex_lock_interruptible(&rb->lock))
			return -ERESTARTSYS;
	}
	return 0;
}

static int rb_wait_writable(struct ringbuf_dev *rb, struct file *filp,
			    size_t len)
{
	while (!rb_writable(rb, len)) {
		mutex_unlock(&rb->lock);
		if (filp->f_flags & O_NONBLOCK)
			return -EAGAIN;
		if (wait_event_interruptible(rb->writeq, rb_writable(rb, len)))
			return -ERESTARTSYS;
		if (mutex_lock_interruptible(&rb->lock))
			return -ERESTARTSYS;
	}
	return 0;
}

/* Copy @len stored bytes to user space. Nothing is consumed on -EFAULT. */
static int rb_copy_out(struct ringbuf_dev *rb, char __user *ubuf, size_t len)
{
	size_t first = min(len, rb->size - rb->tail);

	if (copy_to_user(ubuf, rb->buf + rb->tail, first) ||
	    copy_to_user(ubuf + first, rb->buf, len - first))
		return -EFAULT;

	rb->tail = (rb->tail + len) % rb->size;
	WRITE_ONCE(rb->count, rb->count - len);
	rb->bytes_read += len;
	return 0;
}

/* Append @len bytes from user space. Nothing is committed on -EFAULT. */
static int rb_copy_in(struct ringbuf_dev *rb, const char __user *ubuf,
		      size_t len)
{
	size_t first = min(len, rb->size - rb->head);

	if (copy_from_user(rb->buf + rb->head, ubuf, first) ||
	    copy_from_user(rb->buf, ubuf + first, len - first))
		return -EFAULT;

	rb->head = (rb->head + len) % rb->size;
	WRITE_ONCE(rb->count, rb->count + len);
	rb->bytes_written += len;
	return 0;
}

static void rb_get_stats(struct ringbuf_dev *rb, struct ringbuf_stats *st)
{
	memset(st, 0, sizeof(*st));	/* no stack bytes leak through padding */
	mutex_lock(&rb->lock);
	st->capacity = rb->size;
	st->used = rb->count;
	st->bytes_written = rb->bytes_written;
	st->bytes_read = rb->bytes_read;
	st->open_count = rb->open_count;
	mutex_unlock(&rb->lock);
}

static int rb_resize(struct ringbuf_dev *rb, u32 newsize)
{
	size_t first;
	char *nbuf, *old;

	if (newsize < RINGBUF_MIN_SIZE || newsize > RINGBUF_MAX_SIZE)
		return -EINVAL;

	/* Allocate before taking the lock: the allocation may sleep. */
	nbuf = kvzalloc(newsize, GFP_KERNEL);
	if (!nbuf)
		return -ENOMEM;

	if (mutex_lock_interruptible(&rb->lock)) {
		kvfree(nbuf);
		return -ERESTARTSYS;
	}
	if (rb->count > newsize) {
		mutex_unlock(&rb->lock);
		kvfree(nbuf);
		return -ENOSPC;
	}

	/* Keep the stored bytes, moved to the start of the new buffer. */
	first = min(rb->count, rb->size - rb->tail);
	memcpy(nbuf, rb->buf + rb->tail, first);
	memcpy(nbuf + first, rb->buf, rb->count - first);

	old = rb->buf;
	rb->buf = nbuf;
	rb->tail = 0;
	rb->head = rb->count % newsize;
	WRITE_ONCE(rb->size, newsize);
	mutex_unlock(&rb->lock);

	kvfree(old);
	/* More room, or a lower atomic-write limit: blocked writers re-check. */
	wake_up_interruptible_poll(&rb->writeq, EPOLLOUT | EPOLLWRNORM);
	return 0;
}

/* ---------------------------------------------------------------------- */
/* File operations                                                          */

static int ringbuf_open(struct inode *inode, struct file *filp)
{
	struct ringbuf_dev *rb = container_of(inode->i_cdev,
					      struct ringbuf_dev, cdev);

	/* A FIFO has no file position: lseek/pread/pwrite get -ESPIPE. */
	stream_open(inode, filp);
	filp->private_data = rb;

	mutex_lock(&rb->lock);
	rb->open_count++;
	mutex_unlock(&rb->lock);
	return 0;
}

static int ringbuf_release(struct inode *inode, struct file *filp)
{
	struct ringbuf_dev *rb = filp->private_data;

	mutex_lock(&rb->lock);
	rb->open_count--;
	mutex_unlock(&rb->lock);
	return 0;
}

static ssize_t ringbuf_read(struct file *filp, char __user *ubuf, size_t len,
			    loff_t *ppos)
{
	struct ringbuf_dev *rb = filp->private_data;
	int ret;

	if (!len)
		return 0;

	if (mutex_lock_interruptible(&rb->lock))
		return -ERESTARTSYS;
	ret = rb_wait_readable(rb, filp);
	if (ret)
		return ret;

	len = min(len, rb->count);
	ret = rb_copy_out(rb, ubuf, len);
	mutex_unlock(&rb->lock);
	if (ret)
		return ret;

	wake_up_interruptible_poll(&rb->writeq, EPOLLOUT | EPOLLWRNORM);
	return len;
}

static ssize_t ringbuf_write(struct file *filp, const char __user *ubuf,
			     size_t len, loff_t *ppos)
{
	struct ringbuf_dev *rb = filp->private_data;
	size_t written = 0;
	int ret = 0;

	while (written < len) {
		size_t remaining = len - written;
		size_t n;

		if (mutex_lock_interruptible(&rb->lock)) {
			ret = -ERESTARTSYS;
			break;
		}
		ret = rb_wait_writable(rb, filp, remaining);
		if (ret)
			break;

		n = min(remaining, rb->size - rb->count);
		ret = rb_copy_in(rb, ubuf + written, n);
		mutex_unlock(&rb->lock);
		if (ret)
			break;

		written += n;
		wake_up_interruptible_poll(&rb->readq, EPOLLIN | EPOLLRDNORM);
	}
	/* Like a pipe: report partial progress before any error. */
	return written ? written : ret;
}

static __poll_t ringbuf_poll(struct file *filp, poll_table *wait)
{
	struct ringbuf_dev *rb = filp->private_data;
	__poll_t mask = 0;

	poll_wait(filp, &rb->readq, wait);
	poll_wait(filp, &rb->writeq, wait);

	mutex_lock(&rb->lock);
	if (rb->count)
		mask |= EPOLLIN | EPOLLRDNORM;
	if (rb->count < rb->size)
		mask |= EPOLLOUT | EPOLLWRNORM;
	mutex_unlock(&rb->lock);

	return mask;
}

static long ringbuf_ioctl(struct file *filp, unsigned int cmd,
			  unsigned long arg)
{
	struct ringbuf_dev *rb = filp->private_data;
	void __user *uarg = (void __user *)arg;
	struct ringbuf_stats st;
	u32 newsize;

	switch (cmd) {
	case RINGBUF_IOC_GET_STATS:
		rb_get_stats(rb, &st);
		return copy_to_user(uarg, &st, sizeof(st)) ? -EFAULT : 0;

	case RINGBUF_IOC_CLEAR:
		if (mutex_lock_interruptible(&rb->lock))
			return -ERESTARTSYS;
		rb->head = 0;
		rb->tail = 0;
		WRITE_ONCE(rb->count, 0);
		rb->bytes_written = 0;
		rb->bytes_read = 0;
		mutex_unlock(&rb->lock);
		wake_up_interruptible_poll(&rb->writeq, EPOLLOUT | EPOLLWRNORM);
		return 0;

	case RINGBUF_IOC_RESIZE:
		if (get_user(newsize, (u32 __user *)uarg))
			return -EFAULT;
		return rb_resize(rb, newsize);

	default:
		return -ENOTTY;
	}
}

static const struct file_operations ringbuf_fops = {
	.owner		= THIS_MODULE,
	.open		= ringbuf_open,
	.release	= ringbuf_release,
	.read		= ringbuf_read,
	.write		= ringbuf_write,
	.poll		= ringbuf_poll,
	.unlocked_ioctl	= ringbuf_ioctl,
	.compat_ioctl	= compat_ptr_ioctl,
};

/* ---------------------------------------------------------------------- */
/* sysfs: /sys/class/ringbuf/ringbufN/{capacity,used,bytes_written,...}    */

#define RINGBUF_STAT_ATTR(field)					\
static ssize_t field##_show(struct device *dev,				\
			    struct device_attribute *attr, char *buf)	\
{									\
	struct ringbuf_stats st;					\
									\
	rb_get_stats(dev_get_drvdata(dev), &st);			\
	return sysfs_emit(buf, "%llu\n", (unsigned long long)st.field);	\
}									\
static DEVICE_ATTR_RO(field)

RINGBUF_STAT_ATTR(capacity);
RINGBUF_STAT_ATTR(used);
RINGBUF_STAT_ATTR(bytes_written);
RINGBUF_STAT_ATTR(bytes_read);
RINGBUF_STAT_ATTR(open_count);

static struct attribute *ringbuf_attrs[] = {
	&dev_attr_capacity.attr,
	&dev_attr_used.attr,
	&dev_attr_bytes_written.attr,
	&dev_attr_bytes_read.attr,
	&dev_attr_open_count.attr,
	NULL,
};
ATTRIBUTE_GROUPS(ringbuf);

/* ---------------------------------------------------------------------- */
/* Module load / unload                                                     */

static int ringbuf_setup(struct ringbuf_dev *rb, unsigned int index)
{
	dev_t devt = MKDEV(MAJOR(ringbuf_devt), MINOR(ringbuf_devt) + index);
	int ret;

	mutex_init(&rb->lock);
	init_waitqueue_head(&rb->readq);
	init_waitqueue_head(&rb->writeq);

	rb->size = bufsize;
	rb->buf = kvzalloc(bufsize, GFP_KERNEL);
	if (!rb->buf)
		return -ENOMEM;

	cdev_init(&rb->cdev, &ringbuf_fops);
	rb->cdev.owner = THIS_MODULE;
	ret = cdev_add(&rb->cdev, devt, 1);
	if (ret)
		goto err_buf;

	rb->dev = device_create_with_groups(ringbuf_class, NULL, devt, rb,
					    ringbuf_groups,
					    KBUILD_MODNAME "%u", index);
	if (IS_ERR(rb->dev)) {
		ret = PTR_ERR(rb->dev);
		goto err_cdev;
	}
	return 0;

err_cdev:
	cdev_del(&rb->cdev);
err_buf:
	kvfree(rb->buf);
	return ret;
}

static void ringbuf_teardown(struct ringbuf_dev *rb)
{
	device_destroy(ringbuf_class, rb->cdev.dev);
	cdev_del(&rb->cdev);
	kvfree(rb->buf);
	mutex_destroy(&rb->lock);
}

static int __init ringbuf_init(void)
{
	unsigned int i;
	int ret;

	if (!ndevices || ndevices > RINGBUF_MAX_DEVICES) {
		pr_err("ndevices must be between 1 and %d\n",
		       RINGBUF_MAX_DEVICES);
		return -EINVAL;
	}
	if (bufsize < RINGBUF_MIN_SIZE || bufsize > RINGBUF_MAX_SIZE) {
		pr_err("bufsize must be between %u and %u\n",
		       RINGBUF_MIN_SIZE, RINGBUF_MAX_SIZE);
		return -EINVAL;
	}

	ret = alloc_chrdev_region(&ringbuf_devt, 0, ndevices, KBUILD_MODNAME);
	if (ret)
		return ret;

	ringbuf_class = class_create(KBUILD_MODNAME);
	if (IS_ERR(ringbuf_class)) {
		ret = PTR_ERR(ringbuf_class);
		goto err_region;
	}

	ringbuf_devs = kcalloc(ndevices, sizeof(*ringbuf_devs), GFP_KERNEL);
	if (!ringbuf_devs) {
		ret = -ENOMEM;
		goto err_class;
	}

	for (i = 0; i < ndevices; i++) {
		ret = ringbuf_setup(&ringbuf_devs[i], i);
		if (ret)
			goto err_devs;
	}

	pr_info("%u device(s), %u bytes each, major %d\n",
		ndevices, bufsize, MAJOR(ringbuf_devt));
	return 0;

err_devs:
	while (i--)
		ringbuf_teardown(&ringbuf_devs[i]);
	kfree(ringbuf_devs);
err_class:
	class_destroy(ringbuf_class);
err_region:
	unregister_chrdev_region(ringbuf_devt, ndevices);
	return ret;
}

static void __exit ringbuf_exit(void)
{
	unsigned int i;

	for (i = 0; i < ndevices; i++)
		ringbuf_teardown(&ringbuf_devs[i]);
	kfree(ringbuf_devs);
	class_destroy(ringbuf_class);
	unregister_chrdev_region(ringbuf_devt, ndevices);
	pr_info("unloaded\n");
}

module_init(ringbuf_init);
module_exit(ringbuf_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Yuval Tarnopolsky");
MODULE_DESCRIPTION("Character devices backed by kernel ring buffers");
