// SPDX-License-Identifier: GPL-2.0
/*
 * ringbufctl - inspect and control a ringbuf device from the shell.
 *
 *   ringbufctl /dev/ringbuf0 stats
 *   ringbufctl /dev/ringbuf0 clear
 *   ringbufctl /dev/ringbuf0 resize 65536
 */
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "ringbuf_ioctl.h"

static int usage(const char *prog)
{
	fprintf(stderr, "usage: %s DEVICE stats|clear|resize BYTES\n", prog);
	return 2;
}

int main(int argc, char **argv)
{
	struct ringbuf_stats st;
	int fd, ret = 0;

	if (argc < 3)
		return usage(argv[0]);

	fd = open(argv[1], O_RDONLY | O_NONBLOCK);
	if (fd < 0) {
		fprintf(stderr, "%s: %s\n", argv[1], strerror(errno));
		return 1;
	}

	if (!strcmp(argv[2], "stats")) {
		ret = ioctl(fd, RINGBUF_IOC_GET_STATS, &st);
		if (!ret)
			printf("capacity      %" PRIu64 "\n"
			       "used          %" PRIu64 "\n"
			       "bytes_written %" PRIu64 "\n"
			       "bytes_read    %" PRIu64 "\n"
			       "open_count    %" PRIu32 "\n",
			       (uint64_t)st.capacity, (uint64_t)st.used,
			       (uint64_t)st.bytes_written,
			       (uint64_t)st.bytes_read, (uint32_t)st.open_count);
	} else if (!strcmp(argv[2], "clear")) {
		ret = ioctl(fd, RINGBUF_IOC_CLEAR);
	} else if (!strcmp(argv[2], "resize") && argc == 4) {
		char *end;
		unsigned long v = strtoul(argv[3], &end, 0);
		uint32_t size = (uint32_t)v;

		if (*end || v != size) {
			fprintf(stderr, "invalid size: %s\n", argv[3]);
			close(fd);
			return 2;
		}
		ret = ioctl(fd, RINGBUF_IOC_RESIZE, &size);
	} else {
		close(fd);
		return usage(argv[0]);
	}

	if (ret)
		fprintf(stderr, "%s %s: %s\n", argv[1], argv[2], strerror(errno));
	close(fd);
	return ret ? 1 : 0;
}
