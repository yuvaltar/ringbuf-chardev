#!/usr/bin/env bash
# Boot a (sanitizer) kernel in QEMU and fuzz the driver:
#   1. model-based fuzzing of /dev/ringbuf0 against a reference model;
#   2. multi-threaded stress of four devices with signals;
#   3. stress with descriptors churning while a loop unloads and reloads
#      the module with random parameters;
#   4. kmemleak scan, then the kernel log must not contain any report
#      (KASAN, UBSAN, lockdep, hung task, WARN, BUG, Oops, kmemleak).
# With GCOV_OUT set, the driver's gcov counters are copied out of the guest.
#
# usage: qemu-fuzz.sh KERNEL_IMAGE ringbuf.ko ringbuf_fuzz
# env:   FUZZ_SEED, FUZZ_OPS (model ops), FUZZ_SECONDS (per stress phase),
#        GCOV_OUT (directory for ringbuf.gcda), QEMU_TIMEOUT
set -euo pipefail

if [[ $# -ne 3 ]]; then
	echo "usage: $0 KERNEL_IMAGE MODULE FUZZER" >&2
	exit 2
fi
KERNEL=$1 MODULE=$2 FUZZER=$3
BUSYBOX=${BUSYBOX:-$(command -v busybox || echo /bin/busybox)}
SEED=${FUZZ_SEED:-$(date +%s)}
OPS=${FUZZ_OPS:-200000}
SECS=${FUZZ_SECONDS:-60}

for f in "$KERNEL" "$MODULE" "$FUZZER" "$BUSYBOX"; do
	[[ -r $f ]] || { echo "missing: $f" >&2; exit 2; }
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
root=$work/root
mkdir -p "$root"/{bin,dev,proc,sys,tmp}
cp "$BUSYBOX" "$root/bin/busybox"
cp "$MODULE" "$root/ringbuf.ko"
cp "$FUZZER" "$root/ringbuf_fuzz"

cat > "$root/init" <<EOF
#!/bin/busybox sh
SEED=$SEED OPS=$OPS SECS=$SECS
EOF
cat >> "$root/init" <<'EOF'
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t debugfs debugfs /sys/kernel/debug
dmesg -n 1
dmesg -c > /dev/null
# Report boot-time kmemleak suspects now and forget them, so only objects
# allocated during the run can be reported at the end.
if [ -e /sys/kernel/debug/kmemleak ]; then
	echo scan > /sys/kernel/debug/kmemleak
	echo clear > /sys/kernel/debug/kmemleak
fi
dmesg -c > /dev/null

status=0
fail() { echo "FAIL: $*"; status=1; }

echo "=== kernel $(uname -r), $(nproc) CPUs, seed $SEED"
echo -n "instrumentation:"
for s in kasan_report __ubsan_handle_out_of_bounds lockdep_init kmemleak_scan gcov_info_link; do
	grep -q " $s\$" /proc/kallsyms && echo -n " $s"
done
echo

insmod /ringbuf.ko ndevices=4 || fail "insmod"

echo "=== 1. model fuzzing ($OPS operations)"
/ringbuf_fuzz model -s "$SEED" -n "$OPS" || fail "model fuzzing"

echo "=== 2. stress, 8 threads on 4 devices ($SECS s)"
/ringbuf_fuzz stress -s "$SEED" -t "$SECS" -j 8 -d 4 || fail "stress"

# Coverage counters persist after rmmod, but copy them while loaded anyway.
gcda=$(find /sys/kernel/debug/gcov -name ringbuf.gcda 2>/dev/null | head -1)

echo "=== 3. stress with module unload/reload ($SECS s)"
/ringbuf_fuzz stress -s "$((SEED + 1))" -t "$SECS" -j 4 -d 4 -c &
pid=$!
reloads=0
while kill -0 $pid 2>/dev/null; do
	if rmmod ringbuf 2>/dev/null; then
		insmod /ringbuf.ko ndevices=$((RANDOM % 4 + 1)) \
			bufsize=$((16 << (RANDOM % 17))) || fail "reinsmod"
		reloads=$((reloads + 1))
	fi
done
wait $pid || fail "stress with reloads"
echo "module reloaded $reloads times under load"
lsmod | grep -q '^ringbuf' || insmod /ringbuf.ko ndevices=4

if [ -n "$gcda" ]; then
	gcda=$(find /sys/kernel/debug/gcov -name ringbuf.gcda | head -1)
	echo "=== gcov"
	echo "GCDA-BEGIN"
	base64 "$gcda"
	echo "GCDA-END"
fi
rmmod ringbuf || fail "final rmmod"

if [ -e /sys/kernel/debug/kmemleak ]; then
	echo "=== kmemleak"
	echo scan > /sys/kernel/debug/kmemleak
	sleep 6
	echo scan > /sys/kernel/debug/kmemleak
	cat /sys/kernel/debug/kmemleak > /tmp/leaks
	if grep -q ringbuf /tmp/leaks; then
		cat /tmp/leaks
		fail "kmemleak found leaks in the driver"
	else
		echo "no leaks ($(grep -c unreferenced /tmp/leaks) unrelated suspects)"
	fi
	dmesg -c > /dev/null	# drop the generic "suspected memory leaks" line
fi

echo "=== kernel log"
if dmesg | grep -E -A40 "BUG|WARNING|Oops|KASAN|UBSAN|kmemleak:.*new suspected|possible (circular|recursive)|lockdep|INFO: task|hung_task|Call Trace|general protection"; then
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
timeout "${QEMU_TIMEOUT:-3600}" qemu-system-x86_64 "${accel[@]}" \
	-m 2048 -smp "${QEMU_SMP:-4}" -nographic -no-reboot \
	-kernel "$KERNEL" -initrd "$work/initramfs.gz" \
	-append "console=ttyS0 panic=-1 panic_on_warn=1 quiet loglevel=3 kmemleak=on" \
	| tee "$log"

if [[ -n ${GCOV_OUT:-} ]] && grep -q '^GCDA-BEGIN' "$log"; then
	mkdir -p "$GCOV_OUT"
	sed -n '/^GCDA-BEGIN/,/^GCDA-END/p' "$log" | sed '1d;$d' | tr -d '\r' |
		base64 -d > "$GCOV_OUT/ringbuf.gcda"
	echo "coverage data: $GCOV_OUT/ringbuf.gcda"
fi

grep -q "^RESULT: PASS" "$log"
