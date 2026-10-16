// SPDX-License-Identifier: GPL-2.0
/*
 * User-space test suite for the ringbuf driver.
 *
 * Run as root with the module loaded (ndevices >= 2). An optional argument
 * runs only the tests whose name contains it. Exits non-zero on failure.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
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

#define DEV0	"/dev/ringbuf0"
#define DEV1	"/dev/ringbuf1"
#define SYSFS0	"/sys/class/ringbuf/ringbuf0/"
#define CAP	4096u		/* capacity every test starts from */

static int failed;		/* set by CHECK() in the running test */

#define CHECK(cond)							\
	do {								\
		if (!(cond)) {						\
			int e_ = errno;					\
			fprintf(stderr, "    %s:%d: CHECK(%s) failed"	\
				" (errno %d: %s)\n", __FILE__, __LINE__,\
				#cond, e_, strerror(e_));		\
			failed = 1;					\
			return;						\
		}							\
	} while (0)

/* ---------------------------------------------------------------------- */
/* Helpers                                                                  */

/* Deterministic byte stream: the byte at stream offset @off. */
static unsigned char pattern(uint64_t off)
{
	return (unsigned char)(off * 131 + (off >> 8) * 7 + 3);
}

static void fill(unsigned char *p, size_t n, uint64_t off)
{
	for (size_t i = 0; i < n; i++)
		p[i] = pattern(off + i);
}

static bool verify(const unsigned char *p, size_t n, uint64_t off)
{
	for (size_t i = 0; i < n; i++)
		if (p[i] != pattern(off + i))
			return false;
	return true;
}

/* Open ringbuf0, empty it and restore the default capacity. */
static int open_fresh(int flags)
{
	uint32_t cap = CAP;
	int fd = open(DEV0, O_RDWR | flags);

	if (fd < 0)
		return -1;
	if (ioctl(fd, RINGBUF_IOC_CLEAR) || ioctl(fd, RINGBUF_IOC_RESIZE, &cap)) {
		close(fd);
		return -1;
	}
	return fd;
}

static struct ringbuf_stats stats(int fd)
{
	struct ringbuf_stats st;

	memset(&st, 0xff, sizeof(st));
	if (ioctl(fd, RINGBUF_IOC_GET_STATS, &st))
		perror("RINGBUF_IOC_GET_STATS");
	return st;
}

static long long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return ts.tv_sec * 1000LL + ts.tv_nsec / 1000000;
}

static void sleep_ms(int ms)
{
	struct timespec ts = { ms / 1000, (ms % 1000) * 1000000L };

	while (nanosleep(&ts, &ts) && errno == EINTR)
		;
}

/* Write a pattern chunk at stream offset @off. */
static ssize_t write_pattern(int fd, size_t len, uint64_t off)
{
	unsigned char *buf = malloc(len ? len : 1);
	ssize_t r;

	fill(buf, len, off);
	r = write(fd, buf, len);
	free(buf);
	return r;
}

/* Blocking read of exactly @len bytes; returns bytes read or -1. */
static ssize_t read_full(int fd, unsigned char *buf, size_t len)
{
	size_t got = 0;

	while (got < len) {
		ssize_t r = read(fd, buf + got, len - got);

		if (r < 0)
			return got ? (ssize_t)got : -1;
		got += r;
	}
	return got;
}

/* Read exactly @len bytes and check they continue the pattern at @off. */
static bool read_and_verify(int fd, size_t len, uint64_t off)
{
	unsigned char *buf = malloc(len);
	bool ok = read_full(fd, buf, len) == (ssize_t)len && verify(buf, len, off);

	free(buf);
	return ok;
}

static unsigned long long sysfs_u64(const char *attr)
{
	char path[128];
	unsigned long long v = ~0ULL;
	FILE *f;

	snprintf(path, sizeof(path), SYSFS0 "%s", attr);
	f = fopen(path, "r");
	if (!f)
		return v;
	if (fscanf(f, "%llu", &v) != 1)
		v = ~0ULL;
	fclose(f);
	return v;
}

/* Background I/O, optionally after a delay. */
struct bg_io {
	pthread_t thread;
	int fd;
	int delay_ms;
	size_t len;
	uint64_t off;
	ssize_t ret;
	bool ok;		/* reader: data matched the pattern */
	atomic_bool done;
};

static void *bg_writer(void *arg)
{
	struct bg_io *io = arg;

	sleep_ms(io->delay_ms);
	io->ret = write_pattern(io->fd, io->len, io->off);
	atomic_store(&io->done, true);
	return NULL;
}

static void *bg_reader(void *arg)
{
	struct bg_io *io = arg;
	unsigned char *buf = malloc(io->len);

	sleep_ms(io->delay_ms);
	io->ret = read_full(io->fd, buf, io->len);
	io->ok = io->ret == (ssize_t)io->len && verify(buf, io->len, io->off);
	free(buf);
	atomic_store(&io->done, true);
	return NULL;
}

static void bg_start(struct bg_io *io, void *(*fn)(void *), int fd,
		     int delay_ms, size_t len, uint64_t off)
{
	memset(io, 0, sizeof(*io));
	io->fd = fd;
	io->delay_ms = delay_ms;
	io->len = len;
	io->off = off;
	pthread_create(&io->thread, NULL, fn, io);
}

/* ---------------------------------------------------------------------- */
/* Basic I/O                                                                */

static void test_write_then_read_roundtrip(void)
{
	unsigned char out[100];
	int fd = open_fresh(0);

	CHECK(fd >= 0);
	CHECK(write_pattern(fd, 100, 0) == 100);
	CHECK(read(fd, out, sizeof(out)) == 100);
	CHECK(verify(out, 100, 0));
	close(fd);
}

static void test_read_returns_only_available_bytes(void)
{
	unsigned char out[1000];
	int fd = open_fresh(0);

	CHECK(fd >= 0);
	CHECK(write_pattern(fd, 10, 0) == 10);
	CHECK(read(fd, out, sizeof(out)) == 10);
	CHECK(verify(out, 10, 0));
	close(fd);
}

static void test_zero_length_io_does_not_block(void)
{
	unsigned char b;
	int fd = open_fresh(0);

	CHECK(fd >= 0);
	CHECK(read(fd, &b, 0) == 0);	/* empty buffer, still no block */
	CHECK(write(fd, &b, 0) == 0);
	CHECK(stats(fd).used == 0);
	close(fd);
}

static void test_fifo_order_across_wraparound(void)
{
	unsigned char *buf = malloc(CAP);
	uint64_t woff = 0, roff = 0;
	unsigned int seed = 1;
	int fd = open_fresh(O_NONBLOCK);

	CHECK(fd >= 0 && buf);
	/* Push 1 MiB through the 4 KiB ring in random-sized pieces. */
	while (roff < (1u << 20)) {
		size_t space = CAP - (woff - roff);
		size_t n = rand_r(&seed) % (space + 1);
		size_t m = rand_r(&seed) % CAP + 1;
		size_t avail;
		ssize_t r;

		if (n) {
			fill(buf, n, woff);
			CHECK(write(fd, buf, n) == (ssize_t)n);
			woff += n;
		}
		avail = woff - roff;
		r = read(fd, buf, m);
		if (!avail) {
			CHECK(r == -1 && errno == EAGAIN);
			continue;
		}
		CHECK(r == (ssize_t)(m < avail ? m : avail));
		CHECK(verify(buf, r, roff));
		roff += r;
	}
	free(buf);
	close(fd);
}

/* ---------------------------------------------------------------------- */
/* Non-blocking I/O                                                         */

static void test_nonblock_read_on_empty_returns_eagain(void)
{
	unsigned char b[8];
	int fd = open_fresh(O_NONBLOCK);

	CHECK(fd >= 0);
	CHECK(read(fd, b, sizeof(b)) == -1 && errno == EAGAIN);
	close(fd);
}

static void test_nonblock_small_write_is_all_or_nothing(void)
{
	int fd = open_fresh(O_NONBLOCK);

	CHECK(fd >= 0);
	CHECK(write_pattern(fd, CAP - 10, 0) == CAP - 10);
	/* 20 bytes fit in the capacity, so they are written whole or not. */
	CHECK(write_pattern(fd, 20, 0) == -1 && errno == EAGAIN);
	CHECK(stats(fd).used == CAP - 10);
	CHECK(write_pattern(fd, 10, CAP - 10) == 10);
	CHECK(write_pattern(fd, 1, 0) == -1 && errno == EAGAIN);
	CHECK(read_and_verify(fd, CAP, 0));
	close(fd);
}

static void test_nonblock_large_write_is_partial(void)
{
	int fd = open_fresh(O_NONBLOCK);

	CHECK(fd >= 0);
	CHECK(write_pattern(fd, 2 * CAP, 0) == CAP);
	CHECK(write_pattern(fd, 2 * CAP, 0) == -1 && errno == EAGAIN);
	CHECK(read_and_verify(fd, CAP, 0));
	close(fd);
}

/* ---------------------------------------------------------------------- */
/* Blocking I/O                                                             */

static void test_blocking_read_waits_for_writer(void)
{
	unsigned char out[64];
	struct bg_io w;
	long long t0;
	int fd = open_fresh(0);

	CHECK(fd >= 0);
	bg_start(&w, bg_writer, fd, 150, sizeof(out), 0);
	t0 = now_ms();
	CHECK(read(fd, out, sizeof(out)) == sizeof(out));
	CHECK(now_ms() - t0 >= 100);
	pthread_join(w.thread, NULL);
	CHECK(w.ret == sizeof(out));
	CHECK(verify(out, sizeof(out), 0));
	close(fd);
}

static void test_blocking_write_waits_for_space(void)
{
	struct bg_io r;
	long long t0;
	int fd = open_fresh(0);

	CHECK(fd >= 0);
	CHECK(write_pattern(fd, CAP, 0) == CAP);
	bg_start(&r, bg_reader, fd, 150, 100, 0);
	t0 = now_ms();
	CHECK(write_pattern(fd, 100, CAP) == 100);
	CHECK(now_ms() - t0 >= 100);
	pthread_join(r.thread, NULL);
	CHECK(r.ok);
	CHECK(stats(fd).used == CAP);
	CHECK(read_and_verify(fd, CAP, 100));
	close(fd);
}

static void test_large_write_streams_through_small_buffer(void)
{
	const size_t len = 64 * 1024;
	struct bg_io r;
	int fd = open_fresh(0);

	CHECK(fd >= 0);
	bg_start(&r, bg_reader, fd, 0, len, 0);
	CHECK(write_pattern(fd, len, 0) == (ssize_t)len);
	pthread_join(r.thread, NULL);
	CHECK(r.ok);
	close(fd);
}

/* ---------------------------------------------------------------------- */
/* poll()                                                                   */

static void test_poll_reports_readiness(void)
{
	struct pollfd p;
	int fd = open_fresh(O_NONBLOCK);

	CHECK(fd >= 0);
	p = (struct pollfd){ .fd = fd, .events = POLLIN | POLLOUT };
	CHECK(poll(&p, 1, 0) == 1 && p.revents == POLLOUT);	/* empty */

	CHECK(write_pattern(fd, 10, 0) == 10);
	CHECK(poll(&p, 1, 0) == 1 && p.revents == (POLLIN | POLLOUT));

	CHECK(write_pattern(fd, CAP - 10, 10) == CAP - 10);
	CHECK(poll(&p, 1, 0) == 1 && p.revents == POLLIN);	/* full */
	close(fd);
}

static void test_poll_wakes_when_data_arrives(void)
{
	struct pollfd p;
	struct bg_io w;
	long long t0;
	int fd = open_fresh(0);

	CHECK(fd >= 0);
	p = (struct pollfd){ .fd = fd, .events = POLLIN };
	bg_start(&w, bg_writer, fd, 150, 10, 0);
	t0 = now_ms();
	CHECK(poll(&p, 1, 10000) == 1 && (p.revents & POLLIN));
	CHECK(now_ms() - t0 >= 100);
	pthread_join(w.thread, NULL);
	close(fd);
}

/* ---------------------------------------------------------------------- */
/* ioctl()                                                                  */

static void test_stats_count_bytes(void)
{
	unsigned char out[40];
	struct ringbuf_stats st;
	int fd = open_fresh(0);

	CHECK(fd >= 0);
	CHECK(write_pattern(fd, 100, 0) == 100);
	CHECK(read(fd, out, sizeof(out)) == sizeof(out));
	st = stats(fd);
	CHECK(st.capacity == CAP);
	CHECK(st.used == 60);
	CHECK(st.bytes_written == 100);
	CHECK(st.bytes_read == 40);
	CHECK(st.open_count >= 1);
	CHECK(st.reserved == 0);
	close(fd);
}

static void test_clear_discards_data_and_wakes_writer(void)
{
	struct ringbuf_stats st;
	struct bg_io w;
	int fd = open_fresh(0);

	CHECK(fd >= 0);
	CHECK(write_pattern(fd, CAP, 0) == CAP);
	bg_start(&w, bg_writer, fd, 0, 100, 0);
	sleep_ms(100);
	CHECK(!atomic_load(&w.done));		/* blocked on a full buffer */
	CHECK(ioctl(fd, RINGBUF_IOC_CLEAR) == 0);
	pthread_join(w.thread, NULL);
	CHECK(w.ret == 100);
	st = stats(fd);
	CHECK(st.used == 100);
	CHECK(st.bytes_written == 100 && st.bytes_read == 0);
	CHECK(read_and_verify(fd, 100, 0));
	close(fd);
}

static void test_resize_preserves_wrapped_data(void)
{
	uint32_t size;
	int fd = open_fresh(O_NONBLOCK);

	CHECK(fd >= 0);
	/* Leave 3500 bytes that wrap around the end of the ring. */
	CHECK(write_pattern(fd, 3000, 0) == 3000);
	CHECK(read_and_verify(fd, 2000, 0));
	CHECK(write_pattern(fd, 2500, 3000) == 2500);

	size = 8192;
	CHECK(ioctl(fd, RINGBUF_IOC_RESIZE, &size) == 0);
	CHECK(stats(fd).capacity == 8192 && stats(fd).used == 3500);

	size = 3500;				/* shrink to exactly full */
	CHECK(ioctl(fd, RINGBUF_IOC_RESIZE, &size) == 0);
	CHECK(write_pattern(fd, 1, 0) == -1 && errno == EAGAIN);

	size = 64;				/* too small for the data */
	CHECK(ioctl(fd, RINGBUF_IOC_RESIZE, &size) == -1 && errno == ENOSPC);
	CHECK(stats(fd).capacity == 3500);

	CHECK(read_and_verify(fd, 3500, 2000));
	close(fd);
}

static void test_resize_rejects_invalid_sizes(void)
{
	const uint32_t bad[] = { 0, RINGBUF_MIN_SIZE - 1, RINGBUF_MAX_SIZE + 1 };
	uint32_t size;
	int fd = open_fresh(0);

	CHECK(fd >= 0);
	for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
		size = bad[i];
		CHECK(ioctl(fd, RINGBUF_IOC_RESIZE, &size) == -1 &&
		      errno == EINVAL);
	}
	size = RINGBUF_MIN_SIZE;
	CHECK(ioctl(fd, RINGBUF_IOC_RESIZE, &size) == 0);
	size = RINGBUF_MAX_SIZE;
	CHECK(ioctl(fd, RINGBUF_IOC_RESIZE, &size) == 0);
	CHECK(stats(fd).capacity == RINGBUF_MAX_SIZE);
	close(fd);
}

static void test_unknown_ioctl_returns_enotty(void)
{
	int fd = open_fresh(0);

	CHECK(fd >= 0);
	CHECK(ioctl(fd, _IO(RINGBUF_IOC_MAGIC, 99)) == -1 && errno == ENOTTY);
	CHECK(ioctl(fd, _IO('x', 1)) == -1 && errno == ENOTTY);
	close(fd);
}

static void test_bad_user_pointers_return_efault(void)
{
	void *bad = mmap(NULL, 4096, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS,
			 -1, 0);
	int fd = open_fresh(O_NONBLOCK);

	CHECK(fd >= 0 && bad != MAP_FAILED);
	CHECK(ioctl(fd, RINGBUF_IOC_GET_STATS, bad) == -1 && errno == EFAULT);
	CHECK(ioctl(fd, RINGBUF_IOC_RESIZE, bad) == -1 && errno == EFAULT);

	CHECK(write_pattern(fd, 10, 0) == 10);
	CHECK(read(fd, bad, 10) == -1 && errno == EFAULT);
	CHECK(write(fd, bad, 10) == -1 && errno == EFAULT);
	CHECK(stats(fd).used == 10);		/* nothing lost or added */
	CHECK(read_and_verify(fd, 10, 0));
	munmap(bad, 4096);
	close(fd);
}

/* ---------------------------------------------------------------------- */
/* Device model                                                             */

static void test_seeking_is_rejected(void)
{
	unsigned char b[4] = { 0 };
	int fd = open_fresh(0);

	CHECK(fd >= 0);
	CHECK(lseek(fd, 0, SEEK_SET) == -1 && errno == ESPIPE);
	CHECK(pwrite(fd, b, sizeof(b), 0) == -1 && errno == ESPIPE);
	CHECK(pread(fd, b, sizeof(b), 0) == -1 && errno == ESPIPE);
	close(fd);
}

static void test_devices_are_independent(void)
{
	unsigned char b[8];
	int fd0 = open_fresh(0);
	int fd1 = open(DEV1, O_RDWR | O_NONBLOCK);

	CHECK(fd0 >= 0 && fd1 >= 0);
	CHECK(ioctl(fd1, RINGBUF_IOC_CLEAR) == 0);
	CHECK(write_pattern(fd0, 10, 0) == 10);
	CHECK(read(fd1, b, sizeof(b)) == -1 && errno == EAGAIN);
	CHECK(stats(fd1).used == 0);
	CHECK(stats(fd0).used == 10);
	close(fd0);
	close(fd1);
}

static void test_sysfs_matches_ioctl(void)
{
	unsigned char out[23];
	struct ringbuf_stats st;
	int fd = open_fresh(0);

	CHECK(fd >= 0);
	CHECK(write_pattern(fd, 123, 0) == 123);
	CHECK(read(fd, out, sizeof(out)) == sizeof(out));
	st = stats(fd);
	CHECK(sysfs_u64("capacity") == CAP);
	CHECK(sysfs_u64("used") == 100);
	CHECK(sysfs_u64("bytes_written") == 123);
	CHECK(sysfs_u64("bytes_read") == 23);
	CHECK(sysfs_u64("open_count") == st.open_count);
	close(fd);
}

static void test_open_count_tracks_descriptors(void)
{
	int fds[3];
	int fd = open_fresh(0);
	uint32_t base;

	CHECK(fd >= 0);
	base = stats(fd).open_count;
	for (int i = 0; i < 3; i++) {
		fds[i] = open(DEV0, O_RDONLY);
		CHECK(fds[i] >= 0);
	}
	CHECK(stats(fd).open_count == base + 3);
	for (int i = 0; i < 3; i++)
		close(fds[i]);
	CHECK(stats(fd).open_count == base);
	close(fd);
}

/* ---------------------------------------------------------------------- */
/* Signals                                                                  */

static void on_sigusr1(int sig)
{
	(void)sig;
}

struct kicker {
	pthread_t thread;
	pthread_t target;
	int delay_ms;
};

static void *kick(void *arg)
{
	struct kicker *k = arg;

	sleep_ms(k->delay_ms);
	pthread_kill(k->target, SIGUSR1);
	return NULL;
}

/* Deliver SIGUSR1 (installed without SA_RESTART) to this thread later. */
static void kick_me(struct kicker *k, int delay_ms)
{
	struct sigaction sa = { .sa_handler = on_sigusr1 };

	sigaction(SIGUSR1, &sa, NULL);
	k->target = pthread_self();
	k->delay_ms = delay_ms;
	pthread_create(&k->thread, NULL, kick, k);
}

static void test_signal_interrupts_blocking_read(void)
{
	unsigned char b[8];
	struct kicker k;
	int fd = open_fresh(0);

	CHECK(fd >= 0);
	kick_me(&k, 150);
	CHECK(read(fd, b, sizeof(b)) == -1 && errno == EINTR);
	pthread_join(k.thread, NULL);
	close(fd);
}

static void test_signal_interrupts_blocking_write(void)
{
	struct kicker k;
	int fd = open_fresh(0);

	CHECK(fd >= 0);
	CHECK(write_pattern(fd, CAP, 0) == CAP);
	kick_me(&k, 150);
	CHECK(write_pattern(fd, 10, 0) == -1 && errno == EINTR);
	pthread_join(k.thread, NULL);
	CHECK(stats(fd).used == CAP);
	close(fd);
}

static void test_signal_after_partial_write_returns_count(void)
{
	struct kicker k;
	int fd = open_fresh(0);

	CHECK(fd >= 0);
	/* Twice the capacity with no reader: CAP bytes go in, then it blocks. */
	kick_me(&k, 150);
	CHECK(write_pattern(fd, 2 * CAP, 0) == CAP);
	pthread_join(k.thread, NULL);
	CHECK(read_and_verify(fd, CAP, 0));
	close(fd);
}

/* ---------------------------------------------------------------------- */
/* Resize vs. blocked writers                                               */

static void test_growing_wakes_blocked_writer(void)
{
	struct bg_io w;
	uint32_t size = 8192;
	int fd = open_fresh(0);

	CHECK(fd >= 0);
	CHECK(write_pattern(fd, 2000, 0) == 2000);
	/* 3000 bytes must go in atomically but only 2096 are free. */
	bg_start(&w, bg_writer, fd, 0, 3000, 2000);
	sleep_ms(100);
	CHECK(!atomic_load(&w.done));
	CHECK(ioctl(fd, RINGBUF_IOC_RESIZE, &size) == 0);
	pthread_join(w.thread, NULL);
	CHECK(w.ret == 3000);
	CHECK(read_and_verify(fd, 5000, 0));
	close(fd);
}

static void test_shrinking_does_not_strand_writer(void)
{
	struct bg_io w;
	uint32_t size = 2048;
	int fd = open_fresh(0);

	CHECK(fd >= 0);
	CHECK(write_pattern(fd, 100, 0) == 100);
	/*
	 * A CAP-byte write needs the whole ring free, so it blocks. After the
	 * shrink it is larger than the capacity and must stream instead of
	 * waiting forever for 4096 free bytes in a 2048-byte ring.
	 */
	bg_start(&w, bg_writer, fd, 0, CAP, 100);
	sleep_ms(100);
	CHECK(ioctl(fd, RINGBUF_IOC_RESIZE, &size) == 0);
	CHECK(read_and_verify(fd, 100 + CAP, 0));
	pthread_join(w.thread, NULL);
	CHECK(w.ret == CAP);
	close(fd);
}

/* ---------------------------------------------------------------------- */
/* Concurrency                                                              */

#define NPROD		4
#define NRECORDS	2000

struct record {
	uint32_t producer;
	uint32_t seq;
	uint32_t checksum;
	unsigned char payload[52];
};

static uint32_t record_sum(const struct record *r)
{
	uint32_t s = r->producer * 2654435761u ^ r->seq;

	for (size_t i = 0; i < sizeof(r->payload); i++)
		s = s * 31 + r->payload[i];
	return s;
}

static void *record_producer(void *arg)
{
	uint32_t id = (uint32_t)(uintptr_t)arg;
	int fd = open(DEV0, O_WRONLY);

	for (uint32_t seq = 0; fd >= 0 && seq < NRECORDS; seq++) {
		struct record r = { .producer = id, .seq = seq };

		memset(r.payload, (int)(id * 16 + seq), sizeof(r.payload));
		r.checksum = record_sum(&r);
		if (write(fd, &r, sizeof(r)) != sizeof(r))
			break;
	}
	if (fd >= 0)
		close(fd);
	return NULL;
}

static void test_concurrent_small_writes_are_atomic(void)
{
	const size_t total = (size_t)NPROD * NRECORDS * sizeof(struct record);
	unsigned char *stream = malloc(total);
	uint32_t next_seq[NPROD] = { 0 };
	pthread_t prod[NPROD];
	unsigned int seed = 7;
	size_t got = 0;
	int fd = open_fresh(0);

	CHECK(fd >= 0 && stream);
	for (uintptr_t i = 0; i < NPROD; i++)
		pthread_create(&prod[i], NULL, record_producer, (void *)i);

	/* Read with random sizes so record boundaries never line up. */
	while (got < total) {
		size_t want = rand_r(&seed) % 1000 + 1;
		ssize_t r;

		if (want > total - got)
			want = total - got;
		r = read(fd, stream + got, want);
		CHECK(r > 0);
		got += r;
	}
	for (int i = 0; i < NPROD; i++)
		pthread_join(prod[i], NULL);

	/* Every record must be intact and in order for its producer. */
	for (size_t off = 0; off < total; off += sizeof(struct record)) {
		struct record r;

		memcpy(&r, stream + off, sizeof(r));
		CHECK(r.producer < NPROD);
		CHECK(r.checksum == record_sum(&r));
		CHECK(r.seq == next_seq[r.producer]);
		next_seq[r.producer]++;
	}
	free(stream);
	close(fd);
}

#define STRESS_THREADS	4
#define STRESS_BYTES	(256 * 1024)	/* per producer */

static atomic_ullong produced_sum, consumed_sum, consumed_bytes;

static void *stress_producer(void *arg)
{
	unsigned int seed = (unsigned int)(uintptr_t)arg + 100;
	unsigned char *buf = malloc(3 * CAP);
	int fd = open(DEV0, O_WRONLY);
	size_t left = STRESS_BYTES;

	while (fd >= 0 && left) {
		/* Sizes up to 3x the capacity mix atomic and streamed writes. */
		size_t n = rand_r(&seed) % (3 * CAP) + 1;
		unsigned long long sum = 0;
		ssize_t w;

		if (n > left)
			n = left;
		for (size_t i = 0; i < n; i++) {
			buf[i] = (unsigned char)rand_r(&seed);
			sum += buf[i];
		}
		w = write(fd, buf, n);
		if (w != (ssize_t)n)
			break;
		atomic_fetch_add(&produced_sum, sum);
		left -= n;
	}
	free(buf);
	if (fd >= 0)
		close(fd);
	return NULL;
}

static void *stress_consumer(void *arg)
{
	const unsigned long long total = STRESS_THREADS * STRESS_BYTES;
	unsigned int seed = (unsigned int)(uintptr_t)arg + 200;
	unsigned char *buf = malloc(2 * CAP);
	int fd = open(DEV0, O_RDONLY | O_NONBLOCK);
	struct pollfd p = { .fd = fd, .events = POLLIN };

	while (fd >= 0 && atomic_load(&consumed_bytes) < total) {
		size_t want = rand_r(&seed) % (2 * CAP) + 1;
		unsigned long long sum = 0;
		ssize_t r;

		if (poll(&p, 1, 20) <= 0)
			continue;
		r = read(fd, buf, want);
		if (r <= 0)
			continue;	/* another consumer won the race */
		for (ssize_t i = 0; i < r; i++)
			sum += buf[i];
		atomic_fetch_add(&consumed_sum, sum);
		atomic_fetch_add(&consumed_bytes, (unsigned long long)r);
	}
	free(buf);
	if (fd >= 0)
		close(fd);
	return NULL;
}

static void test_stress_producers_and_consumers(void)
{
	const unsigned long long total = STRESS_THREADS * STRESS_BYTES;
	pthread_t prod[STRESS_THREADS], cons[STRESS_THREADS];
	struct ringbuf_stats st;
	int fd = open_fresh(0);

	CHECK(fd >= 0);
	atomic_store(&produced_sum, 0);
	atomic_store(&consumed_sum, 0);
	atomic_store(&consumed_bytes, 0);
	for (uintptr_t i = 0; i < STRESS_THREADS; i++) {
		pthread_create(&cons[i], NULL, stress_consumer, (void *)i);
		pthread_create(&prod[i], NULL, stress_producer, (void *)i);
	}
	for (int i = 0; i < STRESS_THREADS; i++) {
		pthread_join(prod[i], NULL);
		pthread_join(cons[i], NULL);
	}
	CHECK(atomic_load(&consumed_bytes) == total);
	CHECK(atomic_load(&consumed_sum) == atomic_load(&produced_sum));
	st = stats(fd);
	CHECK(st.used == 0);
	CHECK(st.bytes_written == total && st.bytes_read == total);
	close(fd);
}

/* ---------------------------------------------------------------------- */

struct test {
	const char *name;
	void (*fn)(void);
};

#define TEST(fn) { #fn + 5, fn }	/* drop the "test_" prefix */

static const struct test tests[] = {
	TEST(test_write_then_read_roundtrip),
	TEST(test_read_returns_only_available_bytes),
	TEST(test_zero_length_io_does_not_block),
	TEST(test_fifo_order_across_wraparound),
	TEST(test_nonblock_read_on_empty_returns_eagain),
	TEST(test_nonblock_small_write_is_all_or_nothing),
	TEST(test_nonblock_large_write_is_partial),
	TEST(test_blocking_read_waits_for_writer),
	TEST(test_blocking_write_waits_for_space),
	TEST(test_large_write_streams_through_small_buffer),
	TEST(test_poll_reports_readiness),
	TEST(test_poll_wakes_when_data_arrives),
	TEST(test_stats_count_bytes),
	TEST(test_clear_discards_data_and_wakes_writer),
	TEST(test_resize_preserves_wrapped_data),
	TEST(test_resize_rejects_invalid_sizes),
	TEST(test_unknown_ioctl_returns_enotty),
	TEST(test_bad_user_pointers_return_efault),
	TEST(test_seeking_is_rejected),
	TEST(test_devices_are_independent),
	TEST(test_sysfs_matches_ioctl),
	TEST(test_open_count_tracks_descriptors),
	TEST(test_signal_interrupts_blocking_read),
	TEST(test_signal_interrupts_blocking_write),
	TEST(test_signal_after_partial_write_returns_count),
	TEST(test_growing_wakes_blocked_writer),
	TEST(test_shrinking_does_not_strand_writer),
	TEST(test_concurrent_small_writes_are_atomic),
	TEST(test_stress_producers_and_consumers),
};

static const char *current;

static void on_timeout(int sig)
{
	(void)sig;
	fprintf(stderr, "[ TIMEOUT ] %s hung, aborting\n", current);
	_exit(2);
}

int main(int argc, char **argv)
{
	const size_t n = sizeof(tests) / sizeof(tests[0]);
	size_t ran = 0, passed = 0;

	setvbuf(stdout, NULL, _IOLBF, 0);
	signal(SIGALRM, on_timeout);

	for (size_t i = 0; i < n; i++) {
		if (argc > 1 && !strstr(tests[i].name, argv[1]))
			continue;
		current = tests[i].name;
		failed = 0;
		alarm(120);
		tests[i].fn();
		alarm(0);
		ran++;
		passed += !failed;
		printf("[ %s ] %s\n", failed ? "FAIL" : " OK ", tests[i].name);
	}
	printf("%zu/%zu tests passed\n", passed, ran);
	return passed == ran && ran ? 0 : 1;
}
