/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * ringbuf - user-space ABI shared by the driver, the tests and ringbufctl.
 */
#ifndef _UAPI_RINGBUF_IOCTL_H
#define _UAPI_RINGBUF_IOCTL_H

#include <linux/ioctl.h>
#include <linux/types.h>

#define RINGBUF_MIN_SIZE	16U
#define RINGBUF_MAX_SIZE	(1U << 20)	/* 1 MiB */

/*
 * Fixed-width fields and explicit padding keep the layout identical for
 * 32-bit and 64-bit user space, so no compat_ioctl translation is needed.
 */
struct ringbuf_stats {
	__u64 capacity;		/* buffer size in bytes */
	__u64 used;		/* bytes currently stored */
	__u64 bytes_written;	/* total bytes accepted since load or clear */
	__u64 bytes_read;	/* total bytes returned since load or clear */
	__u32 open_count;	/* open file descriptors on this device */
	__u32 reserved;		/* must be zero */
};

#define RINGBUF_IOC_MAGIC	'r'

/* Read a snapshot of the device statistics. */
#define RINGBUF_IOC_GET_STATS	_IOR(RINGBUF_IOC_MAGIC, 1, struct ringbuf_stats)
/* Drop all buffered data and reset the counters; wakes blocked writers. */
#define RINGBUF_IOC_CLEAR	_IO(RINGBUF_IOC_MAGIC, 2)
/*
 * Change the capacity, keeping buffered data. Fails with ENOSPC if the
 * data does not fit and EINVAL if outside [RINGBUF_MIN_SIZE, RINGBUF_MAX_SIZE].
 */
#define RINGBUF_IOC_RESIZE	_IOW(RINGBUF_IOC_MAGIC, 3, __u32)

#endif /* _UAPI_RINGBUF_IOCTL_H */
