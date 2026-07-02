# Proposal: an io_uring + C++20 coroutine network path (behind a build flag)

## TL;DR

I'd like to propose upstreaming a Linux io_uring network path for the plain-HTTP
(non-TLS) transport, built on C++20 coroutines running on the existing per-thread
`IOUringContext`. It is fully behind a build flag and a runtime record
(`proxy.config.net.io_uring.enabled`, default `0`), so it is a no-op for anyone
who doesn't opt in. The whole socket lifecycle (accept / connect / read / write /
close / timeout-teardown) runs on io_uring with no epoll on the data path.

The performance picture, validated on a real 1 GbE NIC to a separate host:

- **Parity-to-small-win on the dominant traffic** (small-object keep-alive):
  about **-6% CPU/1k** and a **2-3x p99 tail improvement** at 4 KB cache hits.
- **A bounded loss on large un-accelerated streaming bodies**: **+5-8%** on the
  NIC, from io_uring's un-coalesced one-send-per-recv.
- **A large win on disk-served large objects** with the opt-in registered-buffer
  zero-copy send path: **up to -44% to -61% CPU/1k vs the epoll + thread-AIO
  master**, with true zero-copy on the wire, gated at a 256 KB send threshold.

I'm looking for early feedback on the approach and on a staged PR sequence before
opening any PRs.

---

## Motivation

The current io_uring usage in ATS is disk AIO. The network path is epoll +
one recvmsg/sendmsg syscall per operation, with hand-written readiness and
completion handling. An io_uring net path lets a single `io_uring_enter`
(`submit_and_wait`) per event-loop iteration drain all ready completions and
submit all queued operations, which is where the syscall-batching win comes from.

The design question was how to structure the completion handling. Hand-written
io_uring completion state machines are notoriously error-prone: each in-flight
operation needs its state carried across the submit/complete boundary by hand.
Instead this path uses **C++20 coroutines on the existing per-thread
`IOUringContext`**: each socket operation is an `co_await` that suspends until its
CQE arrives and then resumes, so the per-operation state lives in the coroutine
frame and the control flow reads as straight-line code. The frames are pooled in
a thread-local LIFO pool; the inline iovec is sized at 16 (~528 B/frame), which
measurement showed is the flat optimum (see the perf study). This keeps the
frame-locality cost to a ~2% loopback residual that the NIC's syscall-batching
win more than covers.

---

## What is implemented

Behind `proxy.config.net.io_uring.enabled` (restart-scoped, default off):

- **Whole socket lifecycle, epoll-free**: accept, connect (with timeout /
  refused handling), read, write (async batched send), do_io_close, and
  timeout-driven teardown with an operation in flight — all on io_uring.
- **An epoll <-> io_uring poll bridge** so a net thread blocked in the ring still
  services epoll-registered fds (async DNS UDP sockets) and cross-thread wakeups
  (`thread->evfd`) via a multishot poll armed on the ring. This restores the
  epoll->io_uring wakeup direction that a pure ring loop would otherwise lose.
- **Provided-buffer read as the default read path**
  (`read_provided_buffers`, default `1`): the recv lands in a kernel-late-bound
  ring buffer and is zero-copy-attached to the consumer's current buffer at
  completion, which decouples the recv destination from the consumer buffer and
  removes a whole class of buffer-churn races by construction. Single-shot `recv`
  is the fallback, and `-ENOBUFS` (ring exhaustion) falls back to single-shot to
  avoid a deadlock when one connection must buffer more than the whole ring.
- **Opt-in registered-arena zero-copy send** (`write_zerocopy`, default `0`;
  threshold `write_zerocopy_threshold`, default 262144 = 256 KB). Cache disk
  reads draw the `Doc` buffer from a registered, size-classed arena
  (`fixed_arena_size`, default 0 = off), so the send is `send_zc_fixed` straight
  out of registered memory — no copy and no per-send page pin. The arena is a
  single registered region partitioned into power-of-two size classes with a
  lock-free (`InkAtomicList`) free pool and per-class metrics. Anon `send_zc`
  (no arena) and plain copy (below threshold) are the other two send tiers.
- **A config guard**: io_uring + a non-`thread` origin session pool
  (`global`/`hybrid`) is rejected at startup, because a cross-thread session
  migration would move an fd out from under an in-flight ring operation.

Code map for reviewers:

- Coroutine runtime: `include/iocore/io_uring/Coroutine.h`
- Net path: `src/iocore/net/IOUringNetVConnection.cc`
- Arena: `include/iocore/io_uring/UringFixedBufArena.h` (+ `.cc`), registration in
  `src/iocore/io_uring/io_uring.cc`, cache hook in `src/iocore/cache/CacheVC.cc`
- Config: `src/records/RecordsConfig.cc` (search `net.io_uring`)
- Tests: `tests/gold_tests/io_uring/` (see below)

Correctness validation to date: an io_uring net-path gold-test suite in
`tests/gold_tests/io_uring/` covering both read paths (single-shot and the
default provided-buffer path), write / zero-copy, connect timeout / refused,
close-with-op-in-flight and deferred free, EOS/RST, backpressure, keep-alive
re-arm, pipelining, `-ENOBUFS` ring-exhaustion fallback, drip origin, chunked
req+resp with 100-continue, empty body, and async DNS. The suite runs green under
ASan, including a `-F` (freelist-off) load + churn run of ~1.2M requests with no
UAF / overflow / double-free. A force-on differential (flip the default to 1, run
plain-HTTP gold tests, diff vs off) found and fixed several real bugs along the
way (a recv-destination UAF, a mid-send source-buffer free, a keep-alive re-arm
race) — those fixes are in the branch.

---

## Performance case (validated, with its conditions)

Full data and method are in `experiments/coro-net-prototype/PERF-CORO-IOURING.md`
(the study) and `experiments/coro-net-prototype/PERF-RESULTS-2026-06-28.md` (the
canonical A/B numbers). Rig: i9-12900K, cgroup-pinned P-cores, governor
`performance`, turbo off; the same frame-pointer binary toggled `enabled=0/1` so
the net path is the only variable. NIC-sensitive claims were re-run on a real
1 GbE link to a second host — localhost is loopback and short-circuits before the
driver, so a second host is required. Metric is `cpu/1k` = CPU-seconds per 1000
requests; medians over 3 interleaved reps.

**Small-object keep-alive (the dominant traffic).** 4 KB cache hits on the NIC:
io_uring 0.0281 vs epoll 0.0299 cpu/1k = **-6%**, with a **2-3x better p99 tail**.
The win is syscall batching (~1.35 `io_uring_enter`/req vs ~3 syscalls) where a
syscall has real cost. On loopback this same workload is parity — loopback
charges ~0 for syscall entry, so it undersells the NIC win.

**Large un-accelerated streaming bodies (the honest liability).** 1 MB
origin-passthrough on the NIC: io_uring 1.98 vs epoll 1.85 cpu/1k = **+5-8%**.
io_uring signals `READ_READY` after every recv and does one send per recv
completion (~2x epoll's coalesced transmits), which costs real driver `xmit` +
TX-softirq. This is the one place the plain net path is behind on real hardware.

**Disk-served large objects with the opt-in zero-copy send.** This is the arena's
best case: the whole on-disk `Doc` is one contiguous registered block, read once
and DMA'd to the NIC with zero copies and zero per-send setup. Disk-served 1 MiB
cache hits (verified 100% disk reads), under `iommu=pt`:

| step                               | cpu/1k | vs master |
| ---------------------------------- | ------ | --------- |
| epoll + thread-AIO (master)        | 0.341  | --        |
| + io_uring (net + AIO), copy send  | 0.315  | -7.7%     |
| + zero-copy send (anon `send_zc`)  | 0.211  | -38%      |
| + registered arena (`send_zc_fixed`) | 0.132 | **-61%**  |

The registered-arena step is **-61% cpu/1k** vs the epoll + thread-AIO master
(~2.6x requests per CPU-second), `zc_copied=0` (true zero-copy on the wire). An
earlier measurement of the same step read **-44%**; that used auto-AIO (not a true
thread-AIO master) and a smaller arena whose top size-class exhausted under load,
diluting the fixed step — so I quote the range **-44% to -61%** and treat -61% as
the properly-measured figure. The -44% also appears as the instruction-count drop
of the fixed step vs the copy baseline (361K vs ~680K instr/req).

**Conditions on the large-object win (do not read it as universal):**

- It requires the opt-in flags (`write_zerocopy=1` + a sized `fixed_arena_size`)
  and a send `>= 256 KB` (the `send_zc` per-send notification only amortizes over
  large sends; below ~128 KB it loses).
- It was measured on bare metal with the NIC in an IOMMU identity domain
  (`iommu=pt`). Behind a translating IOMMU the per-send pin cost rises.
- A recv-coalescing variant to extend this to cache-miss passthrough was built
  and measured at -28%, but is **NO-GO for general production** (it needs a high
  `SO_RCVLOWAT` that is unsafe for TLS/H2, and is moot under H2's framing copy).
  It stays off by default; I would not propose shipping it on.

---

## Scope and constraints

- **Behind a build flag** (Linux + liburing; the send_zc/registered-buffer paths
  need a recent kernel — measured on 6.17) and a **runtime record, default off**.
  Non-Linux and non-opted-in builds are unaffected.
- **TLS-independent.** This path only selects the plain VC in
  `UnixNetProcessor` when `net.io_uring.enabled` is set. TLS today does not route
  through io_uring — it stays on `SSLNetVConnection` + epoll — and
  **TLS-over-io_uring is blocked on the SSLNetVConnection layering refactor**
  landing. Once that lands, io_uring becomes orthogonal (transport under TLS), so
  the net path can upstream independently of TLS. All the differentials above
  therefore skip TLS/H2-over-TLS.

---

## Proposed PR sequence

Staged so each PR is independently reviewable and (except the last)
behavior-neutral for existing users:

1. **Coroutine runtime primitive.** `include/iocore/io_uring/Coroutine.h` +
   frame pool, with the Catch2 unit test. Pure library, no data-path change;
   already ASan-clean.
2. **epoll <-> io_uring poll bridge.** Multishot-poll the thread's epoll fd and
   `thread->evfd` into the ring + non-blocking harvest, so a ring-blocked net
   thread still services DNS and cross-thread wakeups. Restores the
   epoll->io_uring wakeup direction the net path depends on.
3. **The io_uring coroutine net path**, behind `net.io_uring.enabled` (default
   off): accept / connect / read / write (async batched send) / close / timeout
   teardown, provided-buffer read as the default with single-shot + `-ENOBUFS`
   fallback, the non-`thread` session-pool startup guard, and the
   `tests/gold_tests/io_uring/` suite. This is the reviewable core.
4. **Opt-in registered-arena zero-copy send** (default off): the size-classed
   lock-free arena, the `CacheVC` disk-read hook, the `send_zc_fixed` /
   `send_zc` / copy send tiers, per-class metrics, and the zero-copy autest.

A later, optional step is `IORING_REGISTER_CLONE_BUFFERS` to register the arena
once and clone into every net ring (1x memlock accounting instead of N x). The
recv-coalescing experiment is explicitly **not** in this sequence.

---

## What is not yet validated (out of scope for the first PRs)

Being upfront about the gaps so the default stays off until they're closed:

- **TLS** — blocked on the SSLNetVConnection refactor (above); untested here.
- **Scale: 10k+ connections** — per-VC + ring + pooled-frame memory, and the
  frame-locality residual, are a scaling risk; the prototype pool doesn't free.
- **CPU-saturated operating point** — the 1 GbE link caps load below CPU
  saturation, so the syscall-batching win's magnitude when CPU-bound is
  unmeasured.
- **HTTP/2, NUMA / multi-socket, 10G+ NICs, high-churn teardown CPU** — not
  measured (happy-path CPU only; correctness of RST/timeout/half-close is tested).

Given these, the proposal is explicitly to land the path **default-off, opt-in**,
and revisit the default once TLS and the scale/saturation numbers exist.

I'd welcome feedback on the coroutine-on-`IOUringContext` approach, the staging,
and whether the arena/zero-copy piece should ride with the net path or land
separately once the plain path is in.
