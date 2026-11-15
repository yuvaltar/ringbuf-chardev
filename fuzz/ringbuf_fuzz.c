// SPDX-License-Identifier: GPL-2.0
/*
 * ringbuf_fuzz - fuzzer for the ringbuf driver's user-facing interface.
 *
 * Meant to run inside a sanitizer kernel (KASAN, UBSAN, lockdep, kmemleak;
 * see fuzz/kernel/debug.config), which catches memory and locking bugs. On
 * top of that the fuzzer has its own oracles:
 *
 *   model   one thread drives random open/close/dup/read/write/ioctl/poll/
 *           seek/mmap/fcntl/sysfs operations against /dev/ringbuf0 and
 *           compares every return value, errno, byte read and statistic with
 *           a reference model of the specification. User pointers are valid,
 *           NULL, kernel addresses, or straddle an unmapped guard page so a
 *           copy faults half-way. Never blocks: a blocking call is issued
 *           only when the model says it can complete.
 *
 *   stress  N threads hit all devices at once with the same operations,
 *           blocking calls included, while a signal thread interrupts them;
 *           checks return values and statistics invariants. Tolerates the
 *           module being unloaded and reloaded underneath (ENOENT/ENXIO).
 *
 * Runs are reproducible from the seed; a failure prints the seed, the
 * operation number and the last operations.
 *
 * usage: ringbuf_fuzz model  [-s SEED] [-n OPS]
 *        ringbuf_fuzz stress [-s SEED] [-t SECONDS] [-j THREADS] [-d NDEV] [-c]
 *
 * -c (churn) closes descriptors after most operations so that a concurrent
 * rmmod/insmod loop can actually unload the module mid-run.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#include "ringbuf_ioctl.h"

#define MAX_FDS		8
#define DEFAULT_CAP	4096u
#define LOG_LINES	32

/* ---------------------------------------------------------------------- */
/* PRNG (xorshift64*), one state per thread                                 */

struct rng { uint64_t s; };

static uint64_t rnd(struct rng *r)
{
	r->s ^= r->s >> 12;
	r->s ^= r->s << 25;
	r->s ^= r->s >> 27;
	return r->s * 0x2545F4914F6CDD1DULL;
}

static uint64_t below(struct rng *r, uint64_t n)	/* uniform-ish in [0, n) */
{
	return n ? rnd(r) % n : 0;
}

static bool chance(struct rng *r, unsigned int pct)
{
	return below(r, 100) < pct;
}

/* ---------------------------------------------------------------------- */
/* Operation log, printed on failure                                        */

static char oplog[LOG_LINES][160];
static uint64_t opno;
static uint64_t seed;

static void logop(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(oplog[opno % LOG_LINES], sizeof(oplog[0]), fmt, ap);
	va_end(ap);
}

static void __attribute__((noreturn, format(printf, 1, 2))) die(const char *fmt, ...)
{
	va_list ap;
	uint64_t first = opno >= LOG_LINES ? opno - LOG_LINES + 1 : 0;

	fprintf(stderr, "\nFUZZ FAILURE (seed %" PRIu64 ", op %" PRIu64 "): ", seed, opno);
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	fprintf(stderr, "\nlast operations:\n");
	for (uint64_t i = first; i <= opno; i++)
		if (oplog[i % LOG_LINES][0])
			fprintf(stderr, "  #%" PRIu64 " %s\n", i, oplog[i % LOG_LINES]);
	exit(1);
}

/* ---------------------------------------------------------------------- */
/* User pointers: valid, NULL, kernel, or running into an unmapped page     */

/*
 * arena: RINGBUF_MAX_SIZE * 2 bytes of read/write memory followed by one
 * PROT_NONE guard page. A buffer of @len bytes whose first @valid bytes are
 * mapped starts at guard - valid.
 */
static unsigned char *arena, *guard;
static size_t arena_len;

static void setup_arena(void)
{
	long pg = sysconf(_SC_PAGESIZE);

	arena_len = 2 * (size_t)RINGBUF_MAX_SIZE;
	arena = mmap(NULL, arena_len + pg, PROT_READ | PROT_WRITE,
		     MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (arena == MAP_FAILED)
		die("mmap arena: %s", strerror(errno));
	guard = arena + arena_len;
	if (mprotect(guard, pg, PROT_NONE))
		die("mprotect guard: %s", strerror(errno));
}

enum ptr_kind { PTR_OK, PTR_PARTIAL, PTR_NULL, PTR_KERNEL, PTR_NONCANON };

struct uptr {
	enum ptr_kind kind;
	unsigned char *p;
	size_t valid;		/* bytes accessible from p (PTR_OK: all) */
};

static const char *ptr_name(enum ptr_kind k)
{
	static const char *const names[] = { "ok", "partial", "null", "kernel", "noncanon" };

	return names[k];
}

static void fill_random(struct rng *r, unsigned char *p, size_t n)
{
	while (n) {
		uint64_t v = rnd(r);
		size_t k = n < sizeof(v) ? n : sizeof(v);

		memcpy(p, &v, k);
		p += k;
		n -= k;
	}
}

/* Pick a user buffer for an access of @len bytes. */
static struct uptr pick_ptr(struct rng *r, size_t len)
{
	struct uptr u = { .kind = PTR_OK };
	unsigned int c = below(r, 100);

	if (c < 82 || len == 0) {
		/* Random alignment anywhere in the arena. */
		u.p = arena + below(r, arena_len - len + 1);
		u.valid = len;
	} else if (c < 92) {
		u.kind = PTR_PARTIAL;
		u.valid = below(r, len);	/* 0 .. len-1 bytes mapped */
		u.p = guard - u.valid;
	} else if (c < 95) {
		u.kind = PTR_NULL;
	} else if (c < 98) {
		u.kind = PTR_KERNEL;		/* direct map: access_ok must refuse */
		u.p = (unsigned char *)0xffff888000000000ULL + below(r, 1 << 20);
	} else {
		u.kind = PTR_NONCANON;
		u.p = (unsigned char *)0x8000000000000000ULL;
	}
	return u;
}

/* ---------------------------------------------------------------------- */
/* sysfs helpers                                                            */

static const char *const sysfs_attrs[] = {
	"capacity", "used", "bytes_written", "bytes_read", "open_count",
};

static int sysfs_read(unsigned int dev, const char *attr, unsigned long long *val)
{
	char path[96], buf[64];
	ssize_t n;
	int fd;

	snprintf(path, sizeof(path), "/sys/class/ringbuf/ringbuf%u/%s", dev, attr);
	fd = open(path, O_RDONLY);
	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = '\0';
	*val = strtoull(buf, NULL, 10);
	return 0;
}

/* ---------------------------------------------------------------------- */
/* Model mode                                                               */

/* Reference model of one device. */
struct model {
	uint32_t size;
	unsigned char *data;	/* stored bytes, oldest first */
	size_t count;
	uint64_t bytes_written, bytes_read;
	unsigned int open_count;
};

/* An open file description; several fds may share one after dup(). */
struct ofile {
	int refs;
	int accmode;		/* O_RDONLY / O_WRONLY / O_RDWR */
	bool nonblock;
};

struct slot {
	int fd;			/* -1 if unused */
	struct ofile *of;
};

static struct model m;
static struct slot slots[MAX_FDS];
static const char *dev0 = "/dev/ringbuf0";

#define EXPECT(cond, ...)	do { if (!(cond)) die(__VA_ARGS__); } while (0)

static void expect_ret(long got, int got_errno, long want, int want_errno,
		       const char *what)
{
	if (want < 0) {
		EXPECT(got == -1 && got_errno == want_errno,
		       "%s: got %ld (errno %s), want -1 (errno %s)", what, got,
		       got < 0 ? strerror(got_errno) : "-", strerror(want_errno));
	} else {
		EXPECT(got == want, "%s: got %ld (errno %s), want %ld", what, got,
		       got < 0 ? strerror(got_errno) : "-", want);
	}
}

static bool can_read(const struct ofile *of)
{
	return of->accmode != O_WRONLY;
}

static bool can_write(const struct ofile *of)
{
	return of->accmode != O_RDONLY;
}

static int pick_slot(struct rng *r, bool used)
{
	int start = below(r, MAX_FDS);

	for (int i = 0; i < MAX_FDS; i++) {
		int s = (start + i) % MAX_FDS;

		if ((slots[s].fd >= 0) == used)
			return s;
	}
	return -1;
}

static void check_stats_now(const char *when)
{
	struct ringbuf_stats st;
	int s = pick_slot(&(struct rng){ .s = opno + 1 }, true);
	int fd = s >= 0 ? slots[s].fd : -1;

	if (fd < 0)
		return;
	memset(&st, 0xa5, sizeof(st));
	EXPECT(ioctl(fd, RINGBUF_IOC_GET_STATS, &st) == 0, "%s: GET_STATS: %s",
	       when, strerror(errno));
	EXPECT(st.capacity == m.size && st.used == m.count &&
	       st.bytes_written == m.bytes_written && st.bytes_read == m.bytes_read &&
	       st.open_count == m.open_count && st.reserved == 0,
	       "%s: stats {cap %llu used %llu w %llu r %llu open %u res %u} != model "
	       "{cap %u used %zu w %" PRIu64 " r %" PRIu64 " open %u}", when,
	       (unsigned long long)st.capacity, (unsigned long long)st.used,
	       (unsigned long long)st.bytes_written, (unsigned long long)st.bytes_read,
	       st.open_count, st.reserved, m.size, m.count, m.bytes_written,
	       m.bytes_read, m.open_count);
}

static void op_open(struct rng *r)
{
	static const int modes[] = { O_RDONLY, O_WRONLY, O_RDWR };
	int s = pick_slot(r, false);
	struct ofile *of;
	int flags, fd;

	if (s < 0)
		return;
	of = calloc(1, sizeof(*of));
	of->accmode = modes[below(r, 3)];
	of->nonblock = chance(r, 50);
	of->refs = 1;
	flags = of->accmode | (of->nonblock ? O_NONBLOCK : 0) | O_CLOEXEC;
	logop("open(%s, acc=%d nb=%d)", dev0, of->accmode, of->nonblock);
	fd = open(dev0, flags);
	EXPECT(fd >= 0, "open: %s", strerror(errno));
	slots[s] = (struct slot){ .fd = fd, .of = of };
	m.open_count++;
}

static void op_dup(struct rng *r)
{
	int from = pick_slot(r, true), to = pick_slot(r, false);
	int fd;

	if (from < 0 || to < 0)
		return;
	logop("dup(fd %d)", slots[from].fd);
	fd = fcntl(slots[from].fd, F_DUPFD_CLOEXEC, 0);
	EXPECT(fd >= 0, "dup: %s", strerror(errno));
	slots[to] = (struct slot){ .fd = fd, .of = slots[from].of };
	slots[from].of->refs++;		/* same file: open_count unchanged */
}

static void op_close(struct rng *r)
{
	int s = pick_slot(r, true);

	if (s < 0)
		return;
	logop("close(fd %d)", slots[s].fd);
	EXPECT(close(slots[s].fd) == 0, "close: %s", strerror(errno));
	if (--slots[s].of->refs == 0) {
		free(slots[s].of);
		m.open_count--;		/* ->release runs on the last close */
	}
	slots[s].fd = -1;
	slots[s].of = NULL;
}

static size_t pick_len(struct rng *r)
{
	switch (below(r, 10)) {
	case 0: return 0;
	case 1: return 1;
	case 2: return m.size;
	case 3: return m.size - 1;
	case 4: return m.size + 1;
	case 5: return m.size - m.count;	/* exactly the free space */
	case 6: return m.count;			/* exactly what is stored */
	case 7: return below(r, 2 * m.size + 2);
	case 8: return below(r, 64);
	default: return below(r, 3 * (size_t)RINGBUF_MAX_SIZE / 2);
	}
}

static void op_write(struct rng *r)
{
	int s = pick_slot(r, true);
	size_t len = pick_len(r), space = m.size - m.count, n;
	const struct ofile *of;
	struct uptr u;
	long want;
	int want_errno = 0;
	ssize_t got;

	if (s < 0)
		return;
	of = slots[s].of;
	u = pick_ptr(r, len);

	/* Model: one chunk of n bytes goes in, then a full buffer stops it. */
	if (len == 0)
		n = 0;
	else if (len <= m.size)
		n = space >= len ? len : 0;	/* atomic: all or nothing */
	else
		n = len < space ? len : space;	/* streams: whatever fits */

	if (!can_write(of)) {
		want = -1; want_errno = EBADF;
	} else if (len == 0) {
		want = 0;
	} else if (u.kind == PTR_KERNEL || u.kind == PTR_NONCANON) {
		want = -1; want_errno = EFAULT;	/* vfs_write's access_ok() */
	} else if (n == 0) {
		if (!of->nonblock)
			return;			/* would sleep forever */
		want = -1; want_errno = EAGAIN;
	} else if (n < len && !of->nonblock) {
		return;				/* rest would sleep forever */
	} else if (u.kind != PTR_OK && u.valid < n) {
		want = -1; want_errno = EFAULT;	/* nothing committed */
	} else {
		want = n;
	}

	if (u.kind == PTR_OK)
		fill_random(r, u.p, n);

	logop("write(fd %d, %s+%zu valid, len %zu) [cap %u used %zu] -> want %ld %s",
	      slots[s].fd, ptr_name(u.kind), u.valid, len, m.size, m.count,
	      want, want_errno ? strerror(want_errno) : "");
	errno = 0;
	got = write(slots[s].fd, u.p, len);
	expect_ret(got, errno, want, want_errno, "write");

	if (want > 0) {
		memcpy(m.data + m.count, u.p, n);
		m.count += n;
		m.bytes_written += n;
	}
}

static void op_read(struct rng *r)
{
	int s = pick_slot(r, true);
	size_t len = pick_len(r), n;
	const struct ofile *of;
	struct uptr u;
	long want;
	int want_errno = 0;
	ssize_t got;

	if (s < 0)
		return;
	of = slots[s].of;
	u = pick_ptr(r, len);
	n = len < m.count ? len : m.count;

	if (!can_read(of)) {
		want = -1; want_errno = EBADF;
	} else if (len == 0) {
		want = 0;
	} else if (u.kind == PTR_KERNEL || u.kind == PTR_NONCANON) {
		want = -1; want_errno = EFAULT;	/* vfs_read's access_ok() */
	} else if (m.count == 0) {
		if (!of->nonblock)
			return;
		want = -1; want_errno = EAGAIN;
	} else if (u.kind != PTR_OK && u.valid < n) {
		want = -1; want_errno = EFAULT;	/* nothing consumed */
	} else {
		want = n;
	}

	logop("read(fd %d, %s+%zu valid, len %zu) [cap %u used %zu] -> want %ld %s",
	      slots[s].fd, ptr_name(u.kind), u.valid, len, m.size, m.count,
	      want, want_errno ? strerror(want_errno) : "");
	errno = 0;
	got = read(slots[s].fd, u.p, len);
	expect_ret(got, errno, want, want_errno, "read");

	if (want > 0) {
		for (size_t i = 0; i < n; i++)
			EXPECT(u.p[i] == m.data[i],
			       "read: byte %zu of %zu is 0x%02x, model has 0x%02x",
			       i, n, u.p[i], m.data[i]);
		memmove(m.data, m.data + n, m.count - n);
		m.count -= n;
		m.bytes_read += n;
	}
}

static uint32_t pick_size(struct rng *r)
{
	switch (below(r, 10)) {
	case 0: return 0;
	case 1: return RINGBUF_MIN_SIZE - 1;
	case 2: return RINGBUF_MIN_SIZE;
	case 3: return RINGBUF_MAX_SIZE;
	case 4: return RINGBUF_MAX_SIZE + 1;
	case 5: return UINT32_MAX;
	case 6: return m.count;			/* exactly fits */
	case 7: return m.count ? m.count - 1 : 0;	/* one byte short */
	case 8: return RINGBUF_MIN_SIZE + below(r, 8192);
	default: return RINGBUF_MIN_SIZE + below(r, RINGBUF_MAX_SIZE - RINGBUF_MIN_SIZE + 1);
	}
}

static void op_ioctl(struct rng *r)
{
	int s = pick_slot(r, true);
	const struct ofile *of;
	struct uptr u;
	long want = 0;
	int want_errno = 0, got;
	unsigned int which = below(r, 100);

	if (s < 0)
		return;
	of = slots[s].of;

	if (which < 35) {				/* GET_STATS */
		struct ringbuf_stats st;

		u = pick_ptr(r, sizeof(st));
		if (u.kind != PTR_OK && u.valid < sizeof(st)) {
			want = -1; want_errno = EFAULT;
		}
		logop("ioctl(fd %d, GET_STATS, %s+%zu) -> want %ld", slots[s].fd,
		      ptr_name(u.kind), u.valid, want);
		errno = 0;
		got = ioctl(slots[s].fd, RINGBUF_IOC_GET_STATS, u.p);
		expect_ret(got, errno, want, want_errno, "GET_STATS");
		if (got == 0) {
			memcpy(&st, u.p, sizeof(st));
			EXPECT(st.capacity == m.size && st.used == m.count &&
			       st.bytes_written == m.bytes_written &&
			       st.bytes_read == m.bytes_read &&
			       st.open_count == m.open_count && st.reserved == 0,
			       "GET_STATS differs from model");
		}
	} else if (which < 50) {			/* CLEAR */
		if (!can_write(of)) {
			want = -1; want_errno = EBADF;
		}
		logop("ioctl(fd %d acc %d, CLEAR) -> want %ld", slots[s].fd,
		      of->accmode, want);
		errno = 0;
		got = ioctl(slots[s].fd, RINGBUF_IOC_CLEAR);
		expect_ret(got, errno, want, want_errno, "CLEAR");
		if (got == 0) {
			m.count = 0;
			m.bytes_written = 0;
			m.bytes_read = 0;
		}
	} else if (which < 80) {			/* RESIZE */
		uint32_t newsize = pick_size(r);

		u = pick_ptr(r, sizeof(newsize));
		if (!can_write(of)) {
			want = -1; want_errno = EBADF;
		} else if (u.kind != PTR_OK && u.valid < sizeof(newsize)) {
			want = -1; want_errno = EFAULT;
		} else if (newsize < RINGBUF_MIN_SIZE || newsize > RINGBUF_MAX_SIZE) {
			want = -1; want_errno = EINVAL;
		} else if (m.count > newsize) {
			want = -1; want_errno = ENOSPC;
		}
		if (u.kind == PTR_OK)
			memcpy(u.p, &newsize, sizeof(newsize));
		logop("ioctl(fd %d acc %d, RESIZE %u, %s+%zu) [used %zu] -> want %ld %s",
		      slots[s].fd, of->accmode, newsize, ptr_name(u.kind), u.valid,
		      m.count, want, want_errno ? strerror(want_errno) : "");
		errno = 0;
		got = ioctl(slots[s].fd, RINGBUF_IOC_RESIZE, u.p);
		expect_ret(got, errno, want, want_errno, "RESIZE");
		if (got == 0)
			m.size = newsize;
	} else {					/* unknown command */
		static const unsigned int known[] = {
			RINGBUF_IOC_GET_STATS, RINGBUF_IOC_CLEAR, RINGBUF_IOC_RESIZE,
		};
		unsigned int cmd;

		/*
		 * Near-misses of real commands (other nr, size or direction)
		 * and random numbers in our magic. Generic VFS ioctls such as
		 * FIONBIO use magic 'T' or 'f' and never reach the driver.
		 */
		do {
			cmd = known[below(r, 3)];
			switch (below(r, 4)) {
			case 0: cmd ^= 1u << below(r, 8); break;		/* nr */
			case 1: cmd ^= 1u << (16 + below(r, 14)); break;	/* size */
			case 2: cmd ^= 1u << (30 + below(r, 2)); break;	/* dir */
			default: cmd = (cmd & 0xff00) | (uint32_t)rnd(r) << 16 | below(r, 256);
			}
		} while (cmd == known[0] || cmd == known[1] || cmd == known[2] ||
			 ((cmd >> 8) & 0xff) != RINGBUF_IOC_MAGIC);
		logop("ioctl(fd %d, unknown 0x%08x) -> want ENOTTY", slots[s].fd, cmd);
		errno = 0;
		got = ioctl(slots[s].fd, cmd, arena);
		expect_ret(got, errno, -1, ENOTTY, "unknown ioctl");
	}
}

static void op_poll(struct rng *r)
{
	int s = pick_slot(r, true);
	struct pollfd p;
	short want = 0;

	if (s < 0)
		return;
	if (m.count)
		want |= POLLIN | POLLRDNORM;
	if (m.count < m.size)
		want |= POLLOUT | POLLWRNORM;
	p = (struct pollfd){ .fd = slots[s].fd,
			     .events = POLLIN | POLLOUT | POLLRDNORM | POLLWRNORM };
	logop("poll(fd %d) [cap %u used %zu]", slots[s].fd, m.size, m.count);
	EXPECT(poll(&p, 1, 0) == (want ? 1 : 0), "poll: %s", strerror(errno));
	EXPECT(p.revents == want, "poll revents 0x%x, want 0x%x", p.revents, want);
}

static void op_misc(struct rng *r)
{
	int s = pick_slot(r, true);
	int fd, got;

	if (s < 0)
		return;
	fd = slots[s].fd;
	switch (below(r, 4)) {
	case 0:
		logop("lseek(fd %d)", fd);
		errno = 0;
		got = lseek(fd, below(r, 100), below(r, 3));
		expect_ret(got, errno, -1, ESPIPE, "lseek");
		break;
	case 1: {
		void *p;

		/* No ->mmap: ENODEV, unless the fd cannot be mapped for reading. */
		int want = can_read(slots[s].of) ? ENODEV : EACCES;

		logop("mmap(fd %d acc %d)", fd, slots[s].of->accmode);
		errno = 0;
		p = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
		EXPECT(p == MAP_FAILED && errno == want, "mmap: got %p (%s), want %s",
		       p, strerror(errno), strerror(want));
		break;
	}
	case 2: {
		struct ofile *of = slots[s].of;	/* shared by every dup */
		int fl = fcntl(fd, F_GETFL);

		of->nonblock = !of->nonblock;
		fl = of->nonblock ? fl | O_NONBLOCK : fl & ~O_NONBLOCK;
		logop("fcntl(fd %d, nonblock=%d)", fd, of->nonblock);
		EXPECT(fcntl(fd, F_SETFL, fl) == 0, "fcntl: %s", strerror(errno));
		break;
	}
	default: {
		unsigned long long v, want[5] = {
			m.size, m.count, m.bytes_written, m.bytes_read, m.open_count,
		};
		unsigned int a = below(r, 5);

		logop("sysfs %s", sysfs_attrs[a]);
		EXPECT(sysfs_read(0, sysfs_attrs[a], &v) == 0, "sysfs read");
		EXPECT(v == want[a], "sysfs %s = %llu, model %llu",
		       sysfs_attrs[a], v, want[a]);
	}
	}
}

static int run_model(uint64_t ops)
{
	struct rng r = { .s = seed * 2654435761ULL + 1 };
	uint32_t cap = DEFAULT_CAP;
	struct ringbuf_stats st;
	int fd;

	setup_arena();
	m.data = malloc(RINGBUF_MAX_SIZE);
	for (int i = 0; i < MAX_FDS; i++)
		slots[i].fd = -1;

	/* Start from a known state. */
	fd = open(dev0, O_RDWR);
	if (fd < 0 || ioctl(fd, RINGBUF_IOC_CLEAR) ||
	    ioctl(fd, RINGBUF_IOC_RESIZE, &cap) ||
	    ioctl(fd, RINGBUF_IOC_GET_STATS, &st)) {
		perror("model: initial state");
		return 1;
	}
	m.size = cap;
	m.open_count = st.open_count - 1;	/* not counting fd, closed next */
	close(fd);

	for (opno = 0; opno < ops; opno++) {
		unsigned int c = below(&r, 100);

		oplog[opno % LOG_LINES][0] = '\0';	/* skipped ops log nothing */

		if (c < 6)
			op_open(&r);
		else if (c < 9)
			op_dup(&r);
		else if (c < 14)
			op_close(&r);
		else if (c < 42)
			op_write(&r);
		else if (c < 68)
			op_read(&r);
		else if (c < 88)
			op_ioctl(&r);
		else if (c < 94)
			op_poll(&r);
		else
			op_misc(&r);
		if (opno % 64 == 0)
			check_stats_now("periodic check");
	}

	while (pick_slot(&r, true) >= 0)
		op_close(&r);
	{
		unsigned long long oc;	/* every release must have been counted */

		EXPECT(sysfs_read(0, "open_count", &oc) == 0 && oc == m.open_count,
		       "open_count after closing everything is %llu, model %u",
		       oc, m.open_count);
	}
	printf("model: %" PRIu64 " operations, seed %" PRIu64 ", no divergence\n",
	       ops, seed);
	return 0;
}

/* ---------------------------------------------------------------------- */
/* Stress mode                                                              */

static atomic_bool stop;
static atomic_ulong stress_ops, stress_eintr, stress_gone;
static unsigned int ndev = 2;
static bool churn;		/* close after most operations, so rmmod can win */

static void on_sigusr1(int sig) { (void)sig; }

static bool allowed_errno(int e)
{
	switch (e) {
	case EAGAIN: case EINTR: case EFAULT: case EBADF: case EINVAL:
	case ENOSPC: case ENOTTY: case ESPIPE: case ENODEV: case ENOMEM:
	case ENOENT: case ENXIO:	/* module unloaded under us */
		return true;
	}
	return false;
}

#define SCHECK(cond, ...)						\
	do {								\
		if (!(cond)) {						\
			fprintf(stderr, "STRESS FAILURE (seed %" PRIu64 "): ", seed); \
			fprintf(stderr, __VA_ARGS__);			\
			fprintf(stderr, "\n");				\
			exit(1);					\
		}							\
	} while (0)

static void *stress_worker(void *arg)
{
	struct rng r = { .s = (seed + (uintptr_t)arg) * 0x9E3779B97F4A7C15ULL | 1 };
	unsigned char *buf = calloc(3, RINGBUF_MAX_SIZE);
	int fds[4] = { -1, -1, -1, -1 };

	while (!atomic_load(&stop)) {
		int i = below(&r, 4), fd = fds[i], ret = 0;
		unsigned int op = below(&r, 100);
		size_t len = chance(&r, 70) ? below(&r, 4096) : below(&r, 2 * RINGBUF_MAX_SIZE);
		struct uptr u = pick_ptr(&r, len);
		unsigned char *p = u.kind == PTR_OK ? buf + below(&r, RINGBUF_MAX_SIZE) : u.p;

		if (fd < 0 || op < 5) {
			char path[32];
			int fl = (int[]){ O_RDONLY, O_WRONLY, O_RDWR }[below(&r, 3)];

			if (fd >= 0)
				close(fd);
			snprintf(path, sizeof(path), "/dev/ringbuf%u",
				 (unsigned int)below(&r, ndev));
			fds[i] = open(path, fl | (chance(&r, 50) ? O_NONBLOCK : 0));
			if (fds[i] < 0) {
				SCHECK(allowed_errno(errno), "open: %s", strerror(errno));
				atomic_fetch_add(&stress_gone, 1);
			}
			continue;
		}

		errno = 0;
		if (op < 35) {
			ssize_t n = write(fd, p, len);

			ret = n < 0 ? -1 : 0;
			SCHECK(n < 0 || (size_t)n <= len, "write returned %zd > %zu", n, len);
		} else if (op < 65) {
			ssize_t n = read(fd, p, len);

			ret = n < 0 ? -1 : 0;
			SCHECK(n < 0 || (size_t)n <= len, "read returned %zd > %zu", n, len);
		} else if (op < 75) {
			struct ringbuf_stats st;

			ret = ioctl(fd, RINGBUF_IOC_GET_STATS, &st);
			if (ret == 0)
				SCHECK(st.used <= st.capacity && st.reserved == 0 &&
				       st.capacity >= RINGBUF_MIN_SIZE &&
				       st.capacity <= RINGBUF_MAX_SIZE && st.open_count > 0,
				       "inconsistent stats: used %llu cap %llu open %u",
				       (unsigned long long)st.used,
				       (unsigned long long)st.capacity, st.open_count);
		} else if (op < 80) {
			ret = ioctl(fd, RINGBUF_IOC_CLEAR);
		} else if (op < 88) {
			uint32_t sz = chance(&r, 50) ? RINGBUF_MIN_SIZE + below(&r, 8192)
						     : (uint32_t)rnd(&r) % (RINGBUF_MAX_SIZE + 2);

			ret = ioctl(fd, RINGBUF_IOC_RESIZE, u.kind == PTR_OK ? &sz : (void *)u.p);
		} else if (op < 94) {
			struct pollfd pf = { .fd = fd, .events = POLLIN | POLLOUT };

			ret = poll(&pf, 1, below(&r, 3)) < 0 ? -1 : 0;
		} else if (op < 97) {
			unsigned long long v;

			sysfs_read(below(&r, ndev), sysfs_attrs[below(&r, 5)], &v);
		} else {
			int fl = fcntl(fd, F_GETFL);

			ret = fcntl(fd, F_SETFL, fl ^ O_NONBLOCK);
		}
		if (churn && chance(&r, 50)) {
			close(fd);
			fds[i] = -1;
		}
		if (ret < 0) {
			SCHECK(allowed_errno(errno), "op %u: unexpected errno %s", op,
			       strerror(errno));
			if (errno == EINTR)
				atomic_fetch_add(&stress_eintr, 1);
		}
		atomic_fetch_add(&stress_ops, 1);
	}
	for (int i = 0; i < 4; i++)
		if (fds[i] >= 0)
			close(fds[i]);
	free(buf);
	return NULL;
}

static int run_stress(unsigned int seconds, unsigned int nthreads)
{
	struct sigaction sa = { .sa_handler = on_sigusr1 };	/* no SA_RESTART */
	pthread_t *t = calloc(nthreads, sizeof(*t));
	struct rng r = { .s = seed | 1 };
	struct timespec start, now;
	atomic_int done = 0;

	sigaction(SIGUSR1, &sa, NULL);
	setup_arena();
	for (uintptr_t i = 0; i < nthreads; i++)
		pthread_create(&t[i], NULL, stress_worker, (void *)i);

	clock_gettime(CLOCK_MONOTONIC, &start);
	do {
		/* Kick a random thread out of whatever it is blocked in. */
		pthread_kill(t[below(&r, nthreads)], SIGUSR1);
		usleep(200 + below(&r, 2000));
		clock_gettime(CLOCK_MONOTONIC, &now);
	} while (now.tv_sec - start.tv_sec < (time_t)seconds);

	atomic_store(&stop, true);
	for (unsigned int i = 0; i < nthreads; i++) {
		/* Keep signalling until it notices the stop flag. */
		while (pthread_tryjoin_np(t[i], NULL) == EBUSY) {
			pthread_kill(t[i], SIGUSR1);
			usleep(1000);
		}
		done++;
	}
	printf("stress: %d threads, %u s, %lu operations, %lu interrupted, "
	       "%lu opens while unloaded, seed %" PRIu64 "\n", done, seconds,
	       atomic_load(&stress_ops), atomic_load(&stress_eintr),
	       atomic_load(&stress_gone), seed);
	return 0;
}

/* ---------------------------------------------------------------------- */

int main(int argc, char **argv)
{
	uint64_t ops = 200000;
	unsigned int seconds = 30, threads = 8;
	int opt;

	if (argc < 2 || (strcmp(argv[1], "model") && strcmp(argv[1], "stress"))) {
		fprintf(stderr, "usage: %s model|stress [-s seed] [-n ops] "
			"[-t seconds] [-j threads] [-d ndevices]\n", argv[0]);
		return 2;
	}
	seed = (uint64_t)time(NULL) ^ (uint64_t)getpid() << 16;
	optind = 2;
	while ((opt = getopt(argc, argv, "s:n:t:j:d:c")) != -1) {
		switch (opt) {
		case 's': seed = strtoull(optarg, NULL, 0); break;
		case 'n': ops = strtoull(optarg, NULL, 0); break;
		case 't': seconds = strtoul(optarg, NULL, 0); break;
		case 'j': threads = strtoul(optarg, NULL, 0); break;
		case 'd': ndev = strtoul(optarg, NULL, 0); break;
		case 'c': churn = true; break;
		default: return 2;
		}
	}
	setvbuf(stdout, NULL, _IOLBF, 0);
	if (!strcmp(argv[1], "model"))
		return run_model(ops);
	return run_stress(seconds, threads ? threads : 1);
}
