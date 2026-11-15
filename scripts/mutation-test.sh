#!/usr/bin/env bash
# Check that the tests catch real bugs: inject each mutation into a copy of
# the driver, run the QEMU tests, and require them to fail.
#
# usage: scripts/mutation-test.sh [KVER]
# env:   MODE=tests (default) runs the test suite (make qemu-test);
#        MODE=fuzz runs the fuzzer instead (make qemu-fuzz), to show what
#        the fuzzer catches on its own.
set -uo pipefail

KVER=${1:-$(uname -r)}
MODE=${MODE:-tests}
src=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# name | exact text in driver/ringbuf.c | replacement
mutants=(
	# Functional bugs
	"writes are not atomic|return len <= size ? space >= len : space > 0;|return space > 0;"
	"resize forgets to wake writers|	kvfree_sensitive(old, oldsize);\n	/* More room|	kvfree_sensitive(old, oldsize);\n	return 0;\n	/* More room"
	"wait condition uses the load-time size|	size_t size = READ_ONCE(rb->size);|	size_t size = bufsize;"
	"read drops data on -EFAULT|		return -EFAULT;\n\n	rb->tail|		return rb->count = 0, -EFAULT;\n\n	rb->tail"
	"resize refuses a size that exactly fits|	if (rb->count > newsize) {|	if (rb->count >= newsize) {"
	"exact-fit write is refused|return len <= size ? space >= len : space > 0;|return len <= size ? space > len : space > 0;"
	"poll reports a full buffer as writable|	if (count < size)|	if (count <= size)"
	# Security requirements (SECURITY.md)
	"SR-1 sysfs counters world-readable|static DEVICE_ATTR_ADMIN_RO(field)|static DEVICE_ATTR_RO(field)"
	"SR-1 device node world-accessible|		*mode = 0600;|		*mode = 0666;"
	"SR-2 CLEAR without write access|		if (!(filp->f_mode & FMODE_WRITE))\n			return -EBADF;\n		return rb_clear(rb);|		return rb_clear(rb);"
	"SR-2 RESIZE without write access|		if (!(filp->f_mode & FMODE_WRITE))\n			return -EBADF;\n		if (get_user|		if (get_user"
	# Distro kernels zero the stack (INIT_STACK_ALL_ZERO), which would hide
	# a missing memset; filling with 0xaa stands in for stale stack bytes.
	"SR-4 GET_STATS leaks stack bytes|	memset(st, 0, sizeof(*st));|	memset(st, 0xaa, sizeof(*st));"
	"SR-5 open sleeps on the device lock|	atomic_inc(&rb->open_count);|	mutex_lock(&rb->lock);\n	atomic_inc(&rb->open_count);\n	mutex_unlock(&rb->lock);"
	"SR-5 stats wait is unkillable|	if (mutex_lock_interruptible(&rb->lock))\n		return -ERESTARTSYS;\n	st->capacity|	mutex_lock(&rb->lock);\n	st->capacity"
)

target=qemu-test
[[ $MODE == fuzz ]] && target=qemu-fuzz

caught=0
for m in "${mutants[@]}"; do
	IFS='|' read -r name from to <<<"$m"
	rm -rf "$work/tree" && cp -r "$src" "$work/tree"
	python3 - "$work/tree/driver/ringbuf.c" "$from" "$to" <<'EOF' || exit 2
import sys
path, old, new = sys.argv[1], sys.argv[2].replace('\\n', '\n'), sys.argv[3].replace('\\n', '\n')
s = open(path).read()
assert old in s, f"pattern not found: {old!r}"
open(path, 'w').write(s.replace(old, new, 1))
EOF
	if ! make -s -C "$work/tree" module userspace fuzzer KVER="$KVER" >/dev/null 2>&1; then
		echo "BUILD FAILED  $name"
		exit 2
	fi
	if QEMU_TIMEOUT=${QEMU_TIMEOUT:-300} FUZZ_SECONDS=${FUZZ_SECONDS:-5} \
	   make -s -C "$work/tree" $target KVER="$KVER" >"$work/log" 2>&1; then
		echo "SURVIVED      $name"
	else
		echo "caught        $name"
		caught=$((caught + 1))
	fi
done

echo "$caught/${#mutants[@]} mutants caught ($MODE)"
[[ $caught -eq ${#mutants[@]} ]]
