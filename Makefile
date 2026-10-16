# Build the kernel module against KDIR (default: the running kernel) and
# the user-space test suite and CLI tool.
#
#   make                  module + tests + tool
#   make check            checkpatch + sparse static analysis
#   make qemu-test        boot KERNEL_IMAGE in QEMU, load the module, run tests
#   sudo make test        run the tests on this machine (module must be loaded)

KVER         ?= $(shell uname -r)
KDIR         ?= /lib/modules/$(KVER)/build
KERNEL_IMAGE ?= /boot/vmlinuz-$(KVER)
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

.PHONY: all module userspace check test qemu-test clean

all: module userspace

module:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/driver W=1 modules

userspace: $(TESTS) $(TOOL)

$(TESTS): tests/test_ringbuf.c include/uapi/ringbuf_ioctl.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

$(TOOL): tools/ringbufctl.c include/uapi/ringbuf_ioctl.h
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

check:
	perl $(CHECKPATCH) --no-tree --strict --terse --ignore MACRO_ARG_REUSE -f driver/ringbuf.c include/uapi/ringbuf_ioctl.h
	$(MAKE) -C $(KDIR) M=$(CURDIR)/driver C=2 W=1 modules

test: $(TESTS)
	./$(TESTS)

qemu-test: module userspace
	scripts/qemu-test.sh $(KERNEL_IMAGE) $(DRIVER) $(TESTS) $(TOOL)

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR)/driver clean
	rm -f $(TESTS) $(TOOL)
