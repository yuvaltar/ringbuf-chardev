#!/usr/bin/env bash
# Build a small sanitizer kernel (KASAN, UBSAN, lockdep, kmemleak, gcov) for
# fuzzing the driver. The tree is left configured so the module can be built
# against it with `make module KDIR=<outdir>`.
#
# usage: build-debug-kernel.sh SOURCE_TARBALL_OR_DIR OUTDIR
set -euo pipefail

if [[ $# -ne 2 ]]; then
	echo "usage: $0 SOURCE_TARBALL_OR_DIR OUTDIR" >&2
	exit 2
fi
SRC=$1 OUT=$2
FRAGMENT=$(realpath "$(dirname "$0")/../fuzz/kernel/debug.config")

if [[ -f $OUT/arch/x86/boot/bzImage && $OUT/.fragment.sha == \
      $(sha256sum "$FRAGMENT" | cut -d' ' -f1) ]] 2>/dev/null; then
	echo "debug kernel already built in $OUT"
	exit 0
fi

mkdir -p "$OUT"
if [[ -f $SRC ]]; then
	tar -xf "$SRC" -C "$OUT" --strip-components=1
else
	cp -a "$SRC"/. "$OUT"/
fi

cd "$OUT"
make -s tinyconfig
scripts/kconfig/merge_config.sh -m .config "$FRAGMENT" >/dev/null
make -s olddefconfig

# merge_config silently drops options whose dependencies are missing;
# fail loudly instead of fuzzing without a sanitizer.
for opt in KASAN UBSAN PROVE_LOCKING DEBUG_ATOMIC_SLEEP DEBUG_KMEMLEAK \
	   GCOV_KERNEL MODULES DEVTMPFS SERIAL_8250_CONSOLE; do
	grep -q "^CONFIG_$opt=y" .config || { echo "CONFIG_$opt not set" >&2; exit 1; }
done

make -s -j"$(nproc)" bzImage modules
sha256sum "$FRAGMENT" | cut -d' ' -f1 > .fragment.sha
echo "built $OUT/arch/x86/boot/bzImage"
