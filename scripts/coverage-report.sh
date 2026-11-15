#!/usr/bin/env bash
# Turn the ringbuf.gcda copied out of the guest into a coverage report.
#
# usage: coverage-report.sh COVERAGE_DIR DRIVER_DIR
# Writes COVERAGE_DIR/ringbuf.c.gcov (annotated source) and summary.txt.
set -euo pipefail

out=$(realpath "$1") drv=$(realpath "$2")
[[ -s $out/ringbuf.gcda ]] || { echo "no coverage data in $out" >&2; exit 1; }
[[ -s $drv/ringbuf.gcno ]] || { echo "no ringbuf.gcno: build with GCOV_PROFILE=y" >&2; exit 1; }

cp "$out/ringbuf.gcda" "$drv/ringbuf.gcda"
cd "$out"
gcov -b -c -o "$drv" "$drv/ringbuf.c" > gcov.log
# gcov reports every file it touched; keep the driver's section only.
awk '/^File .*ringbuf\.c.$/ {p=1} p && /^$/ {exit} p' gcov.log | tee summary.txt
rm -f "$drv/ringbuf.gcda"
ls "$out"/*.gcov | grep -v '/ringbuf\.c\.gcov$' | xargs -r rm -f
