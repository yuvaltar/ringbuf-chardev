# Security

This document is the security case for the `ringbuf` driver: what it
protects, from whom, the requirements that follow, how each requirement is
verified, and the findings of the security review with their fixes. It
follows the phases of a secure development lifecycle (SDL): threat model →
requirements → secure implementation → verification → release gates →
response.

## 1. Scope and assets

The driver is a loadable kernel module. Every `/dev/ringbufN` is a byte
FIFO in kernel memory, controlled by `read`, `write`, `poll`, `ioctl` and
read-only sysfs counters.

| Asset | Property |
|---|---|
| A1. Kernel memory and control flow | Integrity: a driver bug is a kernel bug |
| A2. Data in the FIFOs | Confidentiality, integrity |
| A3. Usage metadata (byte counters, open count) | Confidentiality |
| A4. System availability (memory, tasks, CPU) | Availability |

## 2. Threat model

### Trust boundaries and entry points

```
            unprivileged user ──X── (0600 / 0400: no access)
                                │
 process with an fd ──► TB1: syscalls ──► open/release, read, write, poll,
 (any access mode)              │            ioctl(GET_STATS|CLEAR|RESIZE),
                                │            lseek, mmap (rejected)
 root ────────────────► TB2: sysfs (/sys/class/ringbuf/ringbufN/*)
 root ────────────────► TB3: module load/unload and parameters
```

### Adversaries and assumptions

- **ADV-1 Unprivileged local user** without access to the device node.
- **ADV-2 A process holding a descriptor**, possibly with fewer rights than
  the device owner: a read-only descriptor passed over a Unix socket, or a
  group granted access by a udev rule. It is malicious within those rights:
  arbitrary arguments, bad pointers, races between threads, signals, and
  user memory that faults slowly (userfaultfd, FUSE).
- **Assumption:** root is trusted. Module parameters and load/unload are
  root-only.

### STRIDE analysis

| # | Threat | Entry point | Adversary | Mitigation | Req. |
|---|---|---|---|---|---|
| T1 | **Spoofing/Elevation**: unprivileged user opens the device | open | ADV-1 | Node is 0600 root, set explicitly by the driver | SR-1 |
| T2 | **Information disclosure**: counters of another user's FIFO | sysfs | ADV-1 | Attributes are 0400 | SR-1 |
| T3 | **Tampering**: a reader destroys or reshapes data it may only read | ioctl CLEAR/RESIZE | ADV-2 | Need `FMODE_WRITE`, like `write()` | SR-2 |
| T4 | **Elevation**: crafted pointers/lengths make the kernel read or write out of bounds | read, write, ioctl | ADV-2 | All user memory via `copy_{to,from}_user`/`get_user`; sizes range-checked; indexes bounded by capacity | SR-3, SR-8 |
| T5 | **Tampering**: a faulting copy leaves the FIFO half-updated | read, write | ADV-2 | Indexes move only after the whole copy succeeds | SR-3 |
| T6 | **Information disclosure**: kernel stack bytes through struct padding | ioctl GET_STATS | ADV-2 | Struct zeroed before filling; explicit `reserved` field | SR-4 |
| T7 | **Denial of service**: a writer stalled in a user copy holds the lock; other tasks sleep unkillably behind it | open, release, poll, ioctl, sysfs | ADV-2 | open/release/poll are lock-free; every lock wait is interruptible | SR-5 |
| T8 | **Denial of service**: a writer blocks forever after the buffer shrinks below its atomic write | write + RESIZE | ADV-2 | Wait condition reads the current capacity; oversized writes stream | SR-5 |
| T9 | **Denial of service**: memory exhaustion through RESIZE outside cgroup limits | ioctl RESIZE | ADV-2 | Size bounded to 1 MiB; allocation charged to the caller's memcg | SR-6 |
| T10 | **Information disclosure**: cleared or freed data stays in kernel memory and resurfaces through a later bug | CLEAR, RESIZE, unload | ADV-2 | Buffer zeroed on CLEAR; old buffers freed with `kvfree_sensitive()` | SR-7 |
| T11 | **Elevation/DoS**: data races, use-after-free, lock misuse, leaks | all | ADV-2 | One mutex per device, documented lock-free reads, sanitizer fuzzing | SR-8 |
| T12 | **Elevation**: use-after-free when `open` races with `rmmod` | open + unload | root + ADV-2 | `fops.owner` pins the module; teardown order mirrors setup | SR-9 |

## 3. Security requirements and verification

Each requirement is traced to the checks that enforce it. All automated
checks run in CI on every push. `scripts/mutation-test.sh` additionally
re-breaks each requirement in a copy of the driver and confirms the checks
fail.

| Req. | Requirement | Verified by |
|---|---|---|
| SR-1 | Only root can open the device (0600) or read its counters (0400). | Test `unprivileged_access_is_denied` (drops to `nobody`, expects `EACCES`); mutants "SR-1" |
| SR-2 | Operations that modify the device (`write`, `CLEAR`, `RESIZE`) need a descriptor opened for writing. | Test `clear_and_resize_need_write_access`; fuzzer model checks `EBADF` on every access mode; mutants "SR-2" |
| SR-3 | All user input is validated: pointers through the uaccess API, sizes range-checked, unknown ioctls return `ENOTTY`, and a fault leaves the FIFO unchanged. | Tests `bad_user_pointers_return_efault`, `resize_rejects_invalid_sizes`, `unknown_ioctl_returns_enotty`; fuzzer: NULL, kernel and non-canonical pointers, buffers that fault half-way, near-miss ioctl numbers, boundary sizes |
| SR-4 | No kernel memory reaches user space except the FIFO data and the counters. | Fuzzer checks `reserved == 0` on every `GET_STATS`; CodeQL; mutant "SR-4" |
| SR-5 | No task can be made to sleep unkillably or forever by another user of the device. | Test `stalled_writer_does_not_block_others` (userfaultfd); tests for signals and `shrinking_does_not_strand_writer`; hung-task detector during fuzzing; mutants "SR-5" |
| SR-6 | Resource use is bounded: 1–16 devices, 16 B – 1 MiB each; user-triggered allocations are memcg-accounted. | Tests for invalid sizes and module parameters; code review (`GFP_KERNEL_ACCOUNT`) |
| SR-7 | Cleared or freed buffer contents are wiped. | Code review (`memset` in `rb_clear`, `kvfree_sensitive`) — not observable from user space by design |
| SR-8 | Memory safety and concurrency: no out-of-bounds access, use-after-free, data race, lock misuse, sleeping in atomic context or leak. | Fuzzing under KASAN, UBSAN, lockdep, `DEBUG_ATOMIC_SLEEP`, kmemleak; sparse, cppcheck, CodeQL `security-extended` |
| SR-9 | The module cannot be unloaded while in use; opens racing with unload are safe. | `qemu-test.sh` (rmmod refused with an open fd); fuzz phase 3 (unload/reload loop under load) |

### Fuzzing

`fuzz/ringbuf_fuzz.c` runs inside QEMU on a kernel built from
`fuzz/kernel/debug.config` (KASAN, UBSAN, lockdep, `DEBUG_ATOMIC_SLEEP`,
`DEBUG_PAGEALLOC`, kmemleak, hung-task detector, gcov; any warning panics):

1. **Model-based fuzzing.** Random open/dup/close/read/write/ioctl/poll/
   lseek/mmap/fcntl/sysfs operations on one device. Every return value,
   errno, byte read and counter is compared with a reference model of the
   specification. User buffers are valid, NULL, kernel or non-canonical
   addresses, or end in an unmapped guard page so a copy faults half-way.
2. **Concurrent stress.** 8 threads on 4 devices, blocking calls included,
   with a thread sending signals to interrupt them.
3. **Unload under load.** Threads churn descriptors while a loop unloads and
   reloads the module with random parameters.
4. **Leak check.** kmemleak scan after unloading.

Runs are reproducible from the printed seed (`FUZZ_SEED=<seed> make
qemu-fuzz`). The driver's gcov line and branch coverage is reported for
every run.

**Results on the fixed driver:** no divergence from the model, no
sanitizer report and no leak in any run so far, including a run under
all sanitizers of 100,000 model operations, 306,000 concurrent operations
(5,559 of them interrupted by signals) and 87,000 more while the module
was being unloaded and reloaded (seed 20261115).
CI is configured to run 500,000 model operations and 2 × 120 s of stress
on every push, and ten times that nightly. Fuzzing reaches 90% of the
driver's lines and 94% of its branches. The lines it does not reach are all
load-time error paths (allocation and registration failures, invalid module
parameters); `qemu-test.sh` covers the parameter checks.

**The fuzzer is checked too.** Injecting an off-by-one into `rb_copy_out()`
is caught within seconds: hardened usercopy stops a copy that reads past the
end of a 16-byte buffer, and `scripts/triage.py` turns the panic into a
deduplicated report with a reproducer command. `MODE=fuzz
scripts/mutation-test.sh` runs the fuzzer against all 14 mutants.

### Static analysis

| Tool | Scope | Gate |
|---|---|---|
| `checkpatch --strict` | driver, UAPI header | CI fails on any warning |
| sparse (`C=2`) | driver: address spaces (`__user`), locking context | CI fails on any warning |
| gcc `W=1 -Werror` | driver | CI fails on any warning |
| cppcheck | driver, tests, tools, fuzzer | CI fails on any warning |
| gcc `-fanalyzer` | tests, tools, fuzzer | CI fails on any warning |
| CodeQL `security-extended` | everything | results in GitHub code scanning |

## 4. Findings

The review against the threat model found six issues in the original
driver. All are fixed, and every fix has a check that fails on the original
code (the new tests fail on it; the fuzzer reports F1 as a model divergence
within the first hundred operations).

| ID | Severity | Finding | Threat | Fix |
|---|---|---|---|---|
| F1 | Medium | `CLEAR` and `RESIZE` worked on read-only descriptors, so a process allowed only to read could destroy buffered data or change the capacity. | T3 | Require `FMODE_WRITE` (`EBADF` otherwise). |
| F2 | Medium | `open`, `release`, `poll`, `GET_STATS` and sysfs reads took the device mutex uninterruptibly. A writer stalled in `copy_from_user()` (userfaultfd or FUSE page) could leave every other task touching the device in unkillable D state. | T7 | Atomic open count; lock-free `poll` snapshot; interruptible lock in stats and sysfs. |
| F3 | Low | `RESIZE` allocations were not charged to the caller's memory cgroup, so a container could pin up to 16 MiB outside its limit. | T9 | `GFP_KERNEL_ACCOUNT`. |
| F4 | Low | Sysfs counters were world-readable (0444) although the device is root-only, leaking traffic metadata. | T2 | 0400 (`DEVICE_ATTR_ADMIN_RO`). |
| F5 | Low | `CLEAR` reset only the indexes and freed buffers were not wiped, so old data stayed in kernel memory. | T10 | Zero on `CLEAR`; `kvfree_sensitive()` on resize and unload. |
| F6 | Info | The node's 0600 mode came from the devtmpfs default, not from the driver. | T1 | Explicit `devnode` callback, tested. |

## 5. Accepted risks

- `read` and `write` hold the device lock while copying user memory, so a
  stalled writer also delays other readers and writers of **the same
  device**. They wait interruptibly and can be killed. Pipes make the same
  trade-off; copying through a bounce buffer would cost a second copy of
  up to 1 MiB.
- Data read from the FIFO stays in the buffer until overwritten. Any
  process that can read the device can read whatever is buffered, by
  design: the device node's permissions are the access control.
- Module parameters are trusted (root only) but still range-checked.

## 6. Reporting a vulnerability

Please report security issues privately through
[GitHub security advisories](https://github.com/yuvaltar/ringbuf-chardev/security/advisories/new)
rather than public issues. Include the kernel version, the fuzzer seed or a
reproducer if you have one, and the kernel log.
