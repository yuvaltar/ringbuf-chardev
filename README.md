# ringbuf-chardev

[![CI](https://github.com/yuvaltar/ringbuf-chardev/actions/workflows/ci.yml/badge.svg)](https://github.com/yuvaltar/ringbuf-chardev/actions/workflows/ci.yml)

A Linux kernel module that exposes in-kernel ring buffers as character
devices. Each `/dev/ringbufN` is a byte FIFO with pipe-like semantics:
blocking and non-blocking I/O, `poll`/`select`/`epoll`, signal handling,
`ioctl` control and sysfs statistics.

Every push boots two real kernels (Ubuntu's 6.8 and 7.0) in QEMU, loads the
module and runs a 32-test suite against it, then fuzzes it on a kernel
built with KASAN, UBSAN, lockdep and kmemleak. The security design, threat
model and review findings are in [SECURITY.md](SECURITY.md).

## Features

- **Pipe-like I/O.** `read()` returns what is available and blocks only while
  the buffer is empty. `write()` blocks until all data is written.
- **Atomic writes.** A write no larger than the capacity goes in whole, so
  concurrent writers never interleave (the guarantee `pipe(7)` gives for
  `PIPE_BUF`). Larger writes stream through the buffer.
- **Non-blocking mode.** `O_NONBLOCK` returns `EAGAIN` instead of sleeping.
  Readiness is reported through `poll`, `select` and `epoll`.
- **Signals.** A blocked call is interrupted (`EINTR`). A write that already
  made progress returns the byte count instead.
- **ioctl.** `RINGBUF_IOC_GET_STATS`, `RINGBUF_IOC_CLEAR`, and
  `RINGBUF_IOC_RESIZE`, which keeps buffered data even when it wraps around.
- **sysfs.** `/sys/class/ringbuf/ringbufN/` exports `capacity`, `used`,
  `bytes_written`, `bytes_read` and `open_count`.
- **Module parameters.** `ndevices` (1–16) and `bufsize` (16 B – 1 MiB) are
  validated at load.
- **Hardened.** Root-only device and counters, destructive ioctls need write
  access, memcg-accounted allocations, wiped buffers, and no unkillable
  sleeps even when a writer stalls inside a user copy. See
  [SECURITY.md](SECURITY.md).

## Quick start

Requires Linux 6.4 or newer and the headers for the running kernel
(`linux-headers-$(uname -r)`).

```sh
make                                   # module, tests and ringbufctl
sudo insmod driver/ringbuf.ko ndevices=2 bufsize=4096

echo "hello" | sudo tee /dev/ringbuf0
sudo dd if=/dev/ringbuf0 bs=64 count=1  # -> hello
sudo tools/ringbufctl /dev/ringbuf0 stats
sudo tools/ringbufctl /dev/ringbuf0 resize 65536

sudo tests/test_ringbuf                 # run the suite on this machine
sudo rmmod ringbuf
```

## Testing

`make qemu-test` packs the module and test binaries into a busybox
initramfs, boots the kernel in QEMU (KVM when available) and:

1. checks that invalid module parameters are rejected, and that the largest
   configuration (16 devices × 1 MiB) loads and unloads;
2. runs the user-space suite in `tests/test_ringbuf.c`, covering:
   - FIFO order across 1 MiB of wraparound;
   - blocking and non-blocking reads and writes;
   - poll readiness and wakeups;
   - every ioctl, including resize with wrapped data;
   - `EFAULT` on bad user pointers, without losing data;
   - `ESPIPE` on seek;
   - signals during blocking calls;
   - resize while a writer is blocked;
   - record atomicity under four concurrent writers;
   - an eight-thread producer/consumer stress test;
   - the security requirements: unprivileged access is denied, `CLEAR` and
     `RESIZE` need write access, and a writer stalled on a userfaultfd page
     cannot block `open`/`poll` or make a stats request unkillable;
3. checks that `rmmod` is refused while a descriptor is open, and that device
   nodes and sysfs entries are removed afterwards;
4. fails if the kernel log contains `BUG`, `WARNING` or `Oops`.

CI runs this on both kernels, builds with `-Werror`, and runs
`checkpatch --strict`, `sparse`, `cppcheck`, `gcc -fanalyzer` and CodeQL.

### Fuzzing

`fuzz/ringbuf_fuzz.c` has two modes. **model** drives random
open/dup/close/read/write/ioctl/poll/lseek/mmap/fcntl/sysfs operations and
checks every result against a reference model of the specification, using
user buffers that are invalid or fault half-way through a copy. **stress**
runs eight threads on four devices with signals interrupting blocking calls,
and in a second pass while the module is unloaded and reloaded underneath.

```sh
make qemu-fuzz                 # on the stock kernel
make debug-kernel              # KASAN/UBSAN/lockdep/kmemleak/gcov kernel
make fuzz-debug                # fuzz on it and print driver coverage
FUZZ_SEED=1234 make qemu-fuzz  # replay a run
```

CI fuzzes every push, and runs ten times longer every night. When a run
fails, `scripts/triage.py` extracts and deduplicates the sanitizer reports,
prints a reproducer command and, if an `ANTHROPIC_API_KEY` secret is set,
adds an LLM root-cause analysis mapped to the security requirements.

### Mutation testing

`scripts/mutation-test.sh` injects 14 bugs into a copy of the driver
(non-atomic writes, a missing wakeup, a stale wait condition, data loss on
`EFAULT`, off-by-one capacity checks, and one violation of each security
requirement) and checks that the tests catch each one. `MODE=fuzz` runs
the fuzzer instead of the suite.

## Design notes

- **Locking.** One mutex per device guards the buffer and counters. User
  copies happen under it. They can fault and sleep, which rules out a
  spinlock.
- **Sleeping.** Waiters use `wait_event_interruptible()` on lock-free
  `READ_ONCE()` snapshots and re-check under the lock after waking. The lock
  is never held while sleeping, and no wakeup is lost.
- **Atomic writes and resize.** The wait condition reads the *current*
  capacity. If the buffer shrinks below a blocked write's size, the writer
  switches to streaming instead of waiting forever for space that can never
  exist. A test covers this case.
- **Fault safety.** Indexes are updated only after a user copy succeeds, so
  `-EFAULT` leaves the buffer untouched.
- **ABI.** The ioctl struct uses fixed-width fields with explicit padding,
  giving the same layout for 32- and 64-bit user space (`compat_ptr_ioctl`).
  It is zeroed before `copy_to_user()` so no kernel stack bytes leak.
- **Lifetime.** `fops.owner` pins the module while a descriptor is open.
  Load-time errors unwind in reverse order.

## Layout

```
driver/ringbuf.c             kernel module
include/uapi/ringbuf_ioctl.h ioctl ABI shared with user space
tests/test_ringbuf.c         user-space test suite (32 tests)
tools/ringbufctl.c           CLI for stats, clear and resize
fuzz/ringbuf_fuzz.c          model-based and concurrent fuzzer
fuzz/kernel/debug.config     sanitizer kernel config fragment
scripts/qemu-test.sh         boots a kernel in QEMU and runs the tests
scripts/qemu-fuzz.sh         boots a kernel in QEMU and fuzzes the driver
scripts/build-debug-kernel.sh builds the sanitizer kernel
scripts/coverage-report.sh   gcov report from a fuzzing run
scripts/mutation-test.sh     checks the tests catch injected bugs
scripts/triage.py            failure triage, optional LLM analysis
SECURITY.md                  threat model, requirements, findings
```

## License

GPL-2.0
