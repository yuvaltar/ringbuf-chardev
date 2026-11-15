#!/usr/bin/env bash
# Boot a real kernel in QEMU with a busybox initramfs, load the module,
# exercise load/unload paths, run the test suite and check the kernel log.
#
# usage: qemu-test.sh KERNEL_IMAGE ringbuf.ko test_ringbuf ringbufctl
# env:   TEST_FILTER runs only the tests whose name contains it
set -euo pipefail

if [[ $# -ne 4 ]]; then
	echo "usage: $0 KERNEL_IMAGE MODULE TEST_BINARY CTL_BINARY" >&2
	exit 2
fi
KERNEL=$1 MODULE=$2 TESTS=$3 CTL=$4
BUSYBOX=${BUSYBOX:-$(command -v busybox || echo /bin/busybox)}

for f in "$KERNEL" "$MODULE" "$TESTS" "$CTL" "$BUSYBOX"; do
	[[ -r $f ]] || { echo "missing: $f" >&2; exit 2; }
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
root=$work/root
mkdir -p "$root"/{bin,dev,proc,sys}
cp "$BUSYBOX" "$root/bin/busybox"
cp "$MODULE" "$root/ringbuf.ko"
cp "$TESTS" "$root/test_ringbuf"
cp "$CTL" "$root/ringbufctl"

cat > "$root/init" <<EOF
#!/bin/busybox sh
TEST_FILTER='${TEST_FILTER:-}'
EOF
cat >> "$root/init" <<'EOF'
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
dmesg -n 1
# Drop boot messages so the final check sees only what the module produced.
# Under KVM with -cpu host the kernel can warn about the host CPU at boot
# (e.g. "RETBleed: WARNING ..."), which has nothing to do with the driver.
dmesg -c > /dev/null

status=0
fail() { echo "FAIL: $*"; status=1; }

echo "=== kernel $(uname -r), $(nproc) CPUs"

echo "=== invalid module parameters are rejected"
for args in "bufsize=8" "bufsize=2097152" "ndevices=0" "ndevices=17"; do
	if insmod /ringbuf.ko $args 2>/dev/null; then
		fail "insmod accepted $args"
		rmmod ringbuf
	else
		echo "rejected $args"
	fi
done

echo "=== largest configuration loads and unloads"
insmod /ringbuf.ko ndevices=16 bufsize=1048576 || fail "insmod ndevices=16"
[ -c /dev/ringbuf15 ] || fail "/dev/ringbuf15 missing"
rmmod ringbuf || fail "rmmod after ndevices=16"

echo "=== default load"
insmod /ringbuf.ko || fail "insmod"
cat /sys/module/ringbuf/parameters/ndevices /sys/module/ringbuf/parameters/bufsize
[ -c /dev/ringbuf0 ] && [ -c /dev/ringbuf1 ] || fail "device nodes missing"

echo "=== shell round trip"
echo "hello from user space" > /dev/ringbuf0
got=$(dd if=/dev/ringbuf0 bs=64 count=1 2>/dev/null)
[ "$got" = "hello from user space" ] || fail "round trip returned '$got'"
/ringbufctl /dev/ringbuf0 stats

echo "=== test suite"
/test_ringbuf $TEST_FILTER || fail "test suite"

echo "=== unload is refused while a descriptor is open"
exec 3</dev/ringbuf0
rmmod ringbuf 2>/dev/null && fail "rmmod succeeded with an open fd"
exec 3<&-
rmmod ringbuf || fail "rmmod"
[ ! -e /dev/ringbuf0 ] || fail "device node left after rmmod"
[ ! -e /sys/class/ringbuf ] || fail "sysfs class left after rmmod"

echo "=== kernel log"
if dmesg | grep -E "BUG|WARNING|Oops|Call Trace|general protection|refcount"; then
	fail "kernel reported problems"
else
	echo "clean"
fi

[ $status -eq 0 ] && echo "RESULT: PASS" || echo "RESULT: FAIL"
# -no-reboot makes QEMU exit on reboot; poweroff needs ACPI, which
# the minimal debug kernel lacks.
reboot -f
EOF
chmod +x "$root/init"

(cd "$root" && find . | cpio -o -H newc --quiet | gzip -1) > "$work/initramfs.gz"

accel=(-accel tcg)
if [[ -w /dev/kvm ]]; then
	accel=(-accel kvm -cpu host)
fi

log=$work/console.log
timeout "${QEMU_TIMEOUT:-1200}" qemu-system-x86_64 "${accel[@]}" \
	-m 1024 -smp 2 -nographic -no-reboot \
	-kernel "$KERNEL" -initrd "$work/initramfs.gz" \
	-append "console=ttyS0 panic=-1 quiet loglevel=3" | tee "$log"

grep -q "^RESULT: PASS" "$log"
