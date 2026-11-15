# Build the kernel module against KDIR (default: the running kernel) and
# the user-space test suite and CLI tool.
#
#   make                  module + tests + tool
#   make check            static analysis: checkpatch, sparse, cppcheck,
#                         gcc -fanalyzer (user space)
#   make qemu-test        boot KERNEL_IMAGE in QEMU, load the module, run tests
#   make qemu-fuzz        boot KERNEL_IMAGE in QEMU and fuzz the module
#   make debug-kernel     build a KASAN/UBSAN/lockdep/kmemleak/gcov kernel
#                         (DEBUG_KDIR) from KERNEL_SRC for fuzzing
#   make fuzz-debug       build the module against it and fuzz with coverage
#   sudo make test        run the tests on this machine (module must be loaded)

KVER         ?= $(shell uname -r)
KDIR         ?= /lib/modules/$(KVER)/build
KERNEL_IMAGE ?= /boot/vmlinuz-$(KVER)
KERNEL_SRC   ?= $(firstword $(wildcard /usr/src/linux-source-*/linux-source-*.tar.bz2))
DEBUG_KDIR   ?= $(CURDIR)/build/debug-kernel
COVERAGE_DIR ?= $(CURDIR)/build/coverage
# Distro header packages often keep checkpatch.pl in the shared (non-flavour)
# headers directory, e.g. linux-headers-6.8.0-147 next to ...-147-generic.
CHECKPATCH   ?= $(firstword $(wildcard $(KDIR)/scripts/checkpatch.pl \
		$(patsubst %-generic,%,$(realpath $(KDIR)))/scripts/checkpatch.pl) \
		checkpatch.pl)

CC      ?= gcc
CFLAGS  := -O2 -g -Wall -Wextra -Werror -std=gnu11 -Iinclude/uapi
LDFLAGS := -pthread -static

DRIVER := driver/ringbuf.ko
TESTS  := tests/test_ringbuf
TOOL   := tools/ringbufctl
FUZZER := fuzz/ringbuf_fuzz

.PHONY: all module userspace fuzzer check test qemu-test qemu-fuzz \
	debug-kernel fuzz-debug clean

all: module userspace fuzzer

module:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/driver W=1 modules

userspace: $(TESTS) $(TOOL)

$(TESTS): tests/test_ringbuf.c include/uapi/ringbuf_ioctl.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(TOOL): tools/ringbufctl.c include/uapi/ringbuf_ioctl.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

fuzzer: $(FUZZER)

$(FUZZER): fuzz/ringbuf_fuzz.c include/uapi/ringbuf_ioctl.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

check:
	perl $(CHECKPATCH) --no-tree --strict --terse --ignore MACRO_ARG_REUSE \
		-f driver/ringbuf.c include/uapi/ringbuf_ioctl.h
	$(MAKE) -C $(KDIR) M=$(CURDIR)/driver C=2 W=1 KCFLAGS=-Werror modules
	cppcheck --error-exitcode=1 --enable=warning,portability,performance \
		--inline-suppr --std=c11 --quiet -Iinclude/uapi \
		driver/ringbuf.c tests/test_ringbuf.c tools/ringbufctl.c fuzz/ringbuf_fuzz.c
	$(CC) $(CFLAGS) -fanalyzer -fsyntax-only tests/test_ringbuf.c tools/ringbufctl.c \
		fuzz/ringbuf_fuzz.c

test: $(TESTS)
	./$(TESTS)

qemu-test: module userspace
	scripts/qemu-test.sh $(KERNEL_IMAGE) $(DRIVER) $(TESTS) $(TOOL)

qemu-fuzz: module fuzzer
	scripts/qemu-fuzz.sh $(KERNEL_IMAGE) $(DRIVER) $(FUZZER)

debug-kernel:
	scripts/build-debug-kernel.sh $(KERNEL_SRC) $(DEBUG_KDIR)

# Module with gcov instrumentation, sanitizer kernel, coverage report.
fuzz-debug: fuzzer
	$(MAKE) -C $(DEBUG_KDIR) M=$(CURDIR)/driver GCOV_PROFILE=y modules
	GCOV_OUT=$(COVERAGE_DIR) scripts/qemu-fuzz.sh \
		$(DEBUG_KDIR)/arch/x86/boot/bzImage $(DRIVER) $(FUZZER)
	scripts/coverage-report.sh $(COVERAGE_DIR) driver

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/driver clean
	rm -f $(TESTS) $(TOOL) $(FUZZER)
