#!/usr/bin/env bash
# Check that the test suite catches real bugs: inject each mutation into a
# copy of the driver, run the QEMU tests, and require them to fail.
#
# usage: scripts/mutation-test.sh [KVER]
set -uo pipefail

KVER=${1:-$(uname -r)}
src=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

# name | exact text in driver/ringbuf.c | replacement
mutants=(
	"writes are not atomic|return len <= size ? space >= len : space > 0;|return space > 0;"
	"resize forgets to wake writers|	kvfree(old);\n	/* More room|	kvfree(old);\n	return 0;\n	/* More room"
	"wait condition uses the load-time size|	size_t size = READ_ONCE(rb->size);|	size_t size = bufsize;"
	"read drops data on -EFAULT|		return -EFAULT;\n\n	rb->tail|		return rb->count = 0, -EFAULT;\n\n	rb->tail"
)

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
	if ! make -s -C "$work/tree" module userspace KVER="$KVER" >/dev/null 2>&1; then
		echo "BUILD FAILED  $name"
		exit 2
	fi
	if QEMU_TIMEOUT=${QEMU_TIMEOUT:-300} make -s -C "$work/tree" qemu-test KVER="$KVER" >"$work/log" 2>&1; then
		echo "SURVIVED      $name"
	else
		echo "caught        $name"
		caught=$((caught + 1))
	fi
done

echo "$caught/${#mutants[@]} mutants caught"
[[ $caught -eq ${#mutants[@]} ]]
