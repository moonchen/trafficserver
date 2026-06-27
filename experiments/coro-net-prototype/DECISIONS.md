# io_uring networking port — decisions log

An append-only record of the non-obvious decisions made while porting ATS
networking onto io_uring + C++20 coroutines. Newest decisions at the bottom of
each section. Status lives in `PROGRESS.md`; the behavioural contract lives in
`doc/developer-guide/netvconnection-invariants.en.rst`.

## Runtime (Phase 1)

- **D1. Reuse the per-thread `IOUringContext`; add no new thread or event loop.**
  Every `ET_NET` thread already owns a `thread_local` ring pumped by
  `NetHandler::waitForActivity` (submit before `epoll_wait`, `service()` drains
  CQEs at the tail). The coroutine runtime rides that. Rationale: thread-confined
  completions for free (a CQE drains on the submitting thread), no second reactor.

- **D2. `UringOp` is non-movable and lives in the coroutine frame.** `this` is the
  SQE `user_data`; relocation after submission would corrupt the kernel's pointer.
  Frame residency (a `co_await` temporary or a named local) pins it and any buffer
  it references for exactly the op's lifetime — no class-scope `msghdr`, no per-op
  heap. The prep callable is held by value (templated, not `std::function`).

- **D3. `UringCancel` is a real `IOUringCompletionHandler`, not a sentinel.** ATS's
  `IOUringContext::service()` calls `handle_complete()` on *every* CQE's
  `user_data`; the standalone prototype's `(void*)1` sentinel would be
  dereferenced here. The cancel SQE carries a real (no-op) handler.

- **D4. `_res` → `_result`.** glibc `<resolv.h>` `#define`s `_res`; it is pulled in
  transitively once the runtime header is used from the net layer (`ink_sock.h`).
  Avoid member names that collide with common libc/POSIX macros.

## Net VConnection integration (Phase 2, maintainer-directed)

- **D5. Do NOT port the old `net-iouring` branch stack.** It predates the
  `include/iocore` reorg and is written against removed APIs (`Debug`/`Dbg`,
  `NET_*_DYN_STAT`/Metrics, `I_*.h`), so a faithful port is a full rewrite plus an
  invasive shared-infra refactor. Instead add a new VC the way
  `SSLNetVConnection` relates to `UnixNetVConnection`, and swap I/O seams to
  io_uring one at a time. Plain HTTP only for now (TLS waits on the layered-SSL
  refactor).

- **D6. `IOUringNetVConnection : public UnixNetVConnection`.** A subclass (not a
  source copy): inherits the entire do_io_*/VIO/NetHandler integration, so an
  override-nothing version is behaviourally identical (green baseline), and each
  io_uring seam is "override one method." Selected at accept time by
  `proxy.config.net.io_uring.enabled` (restart-required record, default 0) gating
  `UnixNetProcessor::allocate_vc`.

- **D7. Use the global `ClassAllocator` directly, not `THREAD_ALLOC`/`THREAD_FREE`.**
  The per-thread `ProxyAllocator` fast-path requires a member on the eventsystem
  `Thread` class (only `netVCAllocator`/`sslNetVCAllocator`/`quicNetVCAllocator`
  exist). Rather than modify `Thread` for an experimental gated VC, allocate/free
  from the global `ioUringNetVCAllocator` (itself thread-safe). `free_thread` is
  overridden to return there. Revisit if this VC becomes the default (add a
  Thread proxy member then).

- **D8. Announce engagement with a one-time `Note`.** `allocate_vc` reads the flag
  once (function-local static) and logs `io_uring NetVConnection enabled`; the
  autests assert on it so a config that silently fell back to `UnixNetVConnection`
  fails the test rather than passing for the wrong reason.

## Read path (Phase 2B)

- **D9. Bounded first cut: keep the epoll-readiness trigger; async-ify only the
  recvmsg.** `net_read_io` (still driven by `EPOLLIN`) launches a coroutine that
  does the recvmsg via `UringOp`; the completion fills + signals. Reuses the
  inherited enable/backpressure/reenable machinery and leaves the write path
  alone. Chosen over a fully completion-driven path (suppress epoll read interest)
  because it is the smallest correct increment.

- **D10. The read coroutine drains the socket per epoll edge.** The net poll set is
  edge-triggered (`EPOLLIN | EPOLLET`); a single recvmsg per trigger strands
  readable bytes (proven: a large body hung). The coroutine loops recvmsg until a
  short read / full buffer / VIO satisfied (mirrors the base's synchronous drain
  loop). See INV-R3.

- **D11. Take the VIO mutex only after the completion resumes.** The recvmsg is
  async, so the mutex cannot be held across the await; thread-confinement (D1)
  keeps it uncontended at resume. Known limit: no fallback yet if the post-await
  `MUTEX_TRY_LOCK` ever fails under contention (it reschedules and bails).

- **D12. `do_io_close` = cancel-then-unwind.** With a recvmsg in flight, close
  cancels the op and defers the free to the resuming coroutine (frees once no op
  is in flight). Freeing inline would resume the coroutine into a freed `this` —
  the net-iouring branch's `delete this`-with-an-op UAF. See INV-L2.

- **D13. Reimplement `read_signal_and_update`/`read_signal_done` in the subclass.**
  The base helpers are file-static in `UnixNetVConnection.cc`. The reimplementations
  preserve the `recursion`/`closed`/`free_netevent` contract verbatim so a
  do_io_close fired from inside a read signal defers correctly (INV-L1).

## Write path (Phase 2C)

- **D16. Symmetric to the read path: async sendmsg + per-edge drain loop.**
  `net_write_io` launches a `_write` coroutine doing `io_uring_prep_sendmsg`; the
  completion consumes the reader and signals. EPOLLOUT is also edge-triggered, so
  it drains per writable edge (loop until short send / empty buffer / VIO done).

- **D17. Demand-driven, not buffer-ahead (INV-W1).** Before sending, if the
  buffer does not hold all requested bytes and is not at high water, signal
  `WRITE_READY` so the user produces more. We do not stage ciphertext ahead (that
  matters for the layered TLS VC; for a plain VC there is no staging buffer, so
  `WRITE_COMPLETE` inline after the sendmsg completion is safe — same as base).

- **D18. Build the send iovec from a *clone* of the reader.** The real reader is
  consumed only after the sendmsg completes (`consume(wr)`), so a cancelled or
  short send never loses bytes. iovec + msghdr live in the coroutine frame.

- **D19. Unified two-op teardown.** `do_io_close` cancels whichever of recvmsg /
  sendmsg is in flight and defers the free until *neither* remains
  (`_complete_deferred_close`). The signal-unwind free (`_*_signal_and_update`) is
  likewise gated on `_read_op == nullptr && _write_op == nullptr`, so a close
  fired from inside a read signal cannot free the VC while a sendmsg is still in
  the kernel (INV-L2).

- **D20. `net_*_io` must NOT clear `triggered` (INV-R3) — bug found + fixed.** The
  edge-trigger latch `read.triggered`/`write.triggered` is the buffer-full →
  reenable re-drive mechanism (`ep.modify` is a no-op under EPOLLET). Clearing it
  in `net_read_io`/`net_write_io` strands a backpressured flow. Clear it ONLY on
  the genuinely-drained paths inside the coroutine (EAGAIN / short read / short
  send). The write conversion surfaced this (a body never re-armed after the
  consumer drained); the read path had the same latent bug, now fixed too.

## Testing / sanitizers

- **D14. Verify every phase under ASan and TSan, plus a real load test.** Unit test
  (Catch2) + autests (`io_uring_netvc`, `io_uring_read`). The load test
  (`wrk -t4 -c64 -d15s`, 256 KB cached body) doubles as the close-path stress (high
  connection churn) and caught the D10 drain-loop bug.

- **D15. TSan on this box needs `vm.mmap_rnd_bits=28`** (kernel default 32 makes
  TSan abort with "unexpected memory mapping"), set via `sudo sysctl` — this fixes
  both the TSan-instrumented build tools and the runtime. Without sudo,
  `setarch -R <cmd>` (disable ASLR) works for a standalone binary but not for
  build-time codegen. jemalloc is already OFF in the `dev` preset (required for
  TSan). Suppressions live in `.tsan_suppressions` at the repo root.

## Teardown coverage (finding, 2026-06-21)

- **D21. The deferred (cancel-then-unwind) close branch is a safety net, not a hot
  path — and is not yet hit by a test.** Added `proxy.process.net.io_uring.
  vc_deferred_close` + a gated debug line on the branch. Observation: it fires
  **zero** times across all current autests, including the wrk load test. Reason:
  ATS quiesces the read/write VIOs (disable → the coroutine exits and clears
  `_read_op`/`_write_op`) *before* `do_io_close` runs, so at close time there is
  normally no op in flight; the normal close takes `super::do_io_close` inline.
  The deferred branch is still reachable and correct for closes driven from
  *outside* the coroutine's own completion (e.g. a WRITE_COMPLETE-driven close
  while a read is armed on the same VC), but a simple HTTP test does not force it.
  A deterministic trigger (active-timeout mid-stream, or a cross-stream close) is
  future work. The counter makes the gap visible rather than hiding it. (Earlier
  notes that "the load test exercises the close path" refer to close in general;
  the op-in-flight sub-path specifically is uncovered.)

## No epoll — fully completion-driven (Phase 2D)

- **D22. Drop epoll for the io_uring VC; drive purely from completions.** Set
  `ep.syscall = false` in the constructor → `startIO`'s `ep.start` is a no-op, so
  the fd is never registered with epoll (the documented EventIO opt-out QUIC
  uses; verified at runtime `ep.syscall == 0`). io_uring needs no readiness
  signal. Consequence: nothing sets `read/write.triggered` (that was the epoll
  edge), so override `reenable`/`reenable_re` to set `triggered = 1` ("io_uring is
  always armable") before delegating — the existing ready/enable-list machinery
  then drives `net_read_io`/`net_write_io` with no epoll edge, on both the
  same-thread and cross-thread (enable_list) paths. The coroutines keep
  `triggered` set and re-arm via `read/writeReschedule`; a short read/send
  re-submits an op that waits in the kernel rather than waiting for an epoll edge.
  This deletes the hybrid model and the entire edge-trigger-latch bug class
  (INV-R3 no longer applies). Timeouts are unaffected (the InactivityCop uses its
  own `open_list`/queues + `netActivity()` timestamps, not epoll). Verified
  Debug/ASan/TSan on both autests; the load test (64 keep-alive conns) passes
  with the fd entirely out of epoll.
  - Note: continuous re-arming does *not* by itself make the deferred-close path
    fire (the common close still rides the read completion: FIN → EOS → close, op
    already drained). That path still needs an external close (Phase 2E).

## Connect (Phase 2F) + a reverted teardown refactor (2026-06-22)

- **D23. Connect needs no conversion; the inherited optimistic connect is correct
  under io_uring.** Proven (standalone probe): an io_uring `sendmsg`/`recvmsg` on a
  still-connecting socket **waits via internal poll** (no -EAGAIN returned) until
  the handshake completes. So the inherited `connectUp` (non-blocking connect →
  EINPROGRESS → immediate `NET_EVENT_OPEN`) + the io_uring first read/write
  transparently handles connect-in-progress, even with epoll off. Crucially this
  also *matches master's semantics*: a refused connect surfaces as an async
  `VC_EVENT_ERROR` (not `NET_EVENT_OPEN_FAILED`), which HttpSM's retry/error path
  depends on. An explicit `io_uring_prep_connect` would diverge (refused →
  `NET_EVENT_OPEN_FAILED`), so we deliberately do NOT convert connect. Verified by
  `io_uring_connect.test.py` (success + refused, both green, ASan/TSan clean).

- **D24. FIXED (2026-06-22) via io_uring-native connect (Design B).** Symptom: a
  black-holed origin connect (SYN dropped) returned 000 / hung ~30 s under io_uring
  vs 502 on epoll. Root cause: the inherited `connectUp` does an *optimistic*
  non-blocking `connect(2)` and the `ConnectingEntry` probe (`do_io_write(1, empty
  reader)`) treats the resulting `WRITE_READY` as "socket writable = connected."
  On epoll, `net_write_io` runs only on `EPOLLOUT`, so that `WRITE_READY` means
  *actually writable*; the io_uring VC runs `net_write_io` immediately on
  `reenable` (no writability gate), so it signalled `WRITE_READY` before the
  handshake → ATS reported the connect complete (`CONNECT_EVENT_TXN`), applied the
  30 s post-connect timeout, and never honored the connect timeout → 000.
  **Fix (D26):** override `connectUp` to use `io_uring_prep_connect` + an
  `IORING_OP_LINK_TIMEOUT` (`proxy.config.http.connect_attempts_timeout`).
  `NET_EVENT_OPEN` is delivered on the connect *success* CQE (so it means the
  handshake is truly done → the probe's `WRITE_READY` is accurate), and
  `NET_EVENT_OPEN_FAILED` on failure/timeout. Empirically confirmed `prep_connect`
  semantics (standalone probe): blackhole → no CQE until done; refused →
  `-ECONNREFUSED` immediately; blackhole + linked timeout → `-ETIME` + `-ECANCELED`.
  Now: black-holed connect → 502 in ~2 s (matching epoll, ASan/TSan-clean). The
  connect op is already resolved when `_connect` handles it, so there is no
  in-flight op at the resulting free (sidesteps the D25 teardown coupling for the
  connect case). Repro for the timeout path (manual, needs root):
  `iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport <p> -j DROP`. The committed
  `io_uring_connect` autest covers success + refused (portable); the timeout path
  is verified manually (Debug/ASan/TSan).

- **D26. io_uring-native connect = the preferred design (maintainer: "I will
  generally prefer an io_uring-native design").** `io_uring_prep_connect` is the
  idiomatic primitive — its CQE is posted exactly on handshake completion/failure
  (it *is* "don't notify me until connect is done"); `POLLOUT` is the lower-level
  alternative (writable ⇒ resolved, then check `SO_ERROR`). An io_uring socket VC
  always overrides `connectUp` (the only reason connect "worked" without it was
  the io_uring read/write internally waiting on a *syscall*-initiated connect —
  not native). Known limitation: the linked timeout reads the *global*
  `connect_attempts_timeout`, not the per-transaction `txn_conf` value (connectUp
  has no SM handle); acceptable for now (the user OK'd not touching the cops).

- **D25. REVERTED a `free_thread`-as-choke-point teardown refactor — it introduced
  a UAF under load.** While chasing D24 I hypothesized the timeout path freed the
  VC via `mainEvent` → base signal → `free_netevent` → `free_thread` with an op in
  flight (bypassing do_io_close's deferral), and refactored `free_thread` to be the
  single deferral choke. That hypothesis was wrong for the 000 (it didn't change
  it), and the refactor introduced a heap-use-after-free in `io_uring_read` (the
  wrk-load test, ASan) — so it was reverted (commit "Revert net: make free_thread
  ...the teardown choke point"). The underlying concern is real but unverified: the
  *current* (Phase-2D) teardown defers only in `do_io_close`, so a timeout/base-
  signal-driven close could in principle free with an op in flight. It is not
  observed in any test (the deferred path doesn't fire — D21). **Future work: do
  the free_thread-choke properly, but only with a deterministic deferred-path test
  first (TDD)** — the blind refactor was the mistake.

- **D28. FIXED D25 (2026-06-22), TDD this time.** The concern in D25 is real and
  now reproduced deterministically: an origin that accepts but never responds keeps
  an io_uring recvmsg in flight; the server inactivity timeout then closes the VC
  via `mainEvent` → base `read/write_signal` → `free_netevent` → `free_thread`,
  freeing it with the recv in flight → the cancelled recv resumes into a freed VC.
  **Detector:** this UAF is invisible to ASan by default (VCs go to a ClassAllocator
  freelist, not malloc/free). Two ways surfaced it — (a) a temporary
  `ink_release_assert(no op in flight)` at the top of `free_thread` *fired*; (b)
  running with **`-F`** (disable the ProxyAllocator freelist → real malloc/free)
  made ASan report `heap-use-after-free`. **Fix:** make `free_thread` itself defer —
  if an op is in flight, cancel it and return, letting the resuming coroutine free
  via `_complete_deferred_close` (reusing the do_io_close path; the no-op path is
  byte-identical to before, so the load-test close path is untouched — that's what
  the prior blind refactor got wrong). **Verified:** new `io_uring_origin_timeout`
  autest runs with `-F`; without the fix → `-F`+ASan UAF, with it → 504 + clean;
  no regression on the wrk load test under `-F`+ASan. The deciding lesson vs the
  D25 revert: a deterministic failing test under a *real* detector (`-F`+ASan) first,
  then the minimal fix, verified on both the new test and the prior regression point.

## Accept (Phase 2G, 2026-06-22)

- **D27. io_uring accept = per-thread, single-shot, throttle-gated re-arm.** New
  `IOUringNetAccept : NetAccept, IOUringCompletionHandler` (in `UnixNetAccept.cc`
  so it can use the file-static `handle_max_client_connections`), selected by
  `UnixNetProcessor::createNetAccept` when `io_uring.enabled`. It forces the
  **per-thread** accept path (not the default dedicated-accept-thread loop): each
  ET_NET thread keeps one `io_uring_prep_accept` in flight on its own ring and
  re-arms in `handle_complete` after delivering the VC. The accepted VC stays on
  the accepting thread — **no cross-thread hand-off** (INV-L3 holds; the listen fd
  is shared and each thread's ring competes for connections, like EPOLLEXCLUSIVE).
  **Single-shot, not multishot:** the accept throttle (`check_net_throttle(ACCEPT)`,
  per-client max) is checked on every accept; multishot would bypass it. Under
  throttle we accept-then-close + re-arm (matches `acceptFastEvent`); true
  "stop-accepting-under-throttle" backpressure is a later refinement. The
  VC-creation mirrors `acceptFastEvent` and is kept separate (the syscall accept
  path is untouched — zero regression risk; TODO: dedup once settled). One-time
  NOTE "io_uring accept enabled"; the `io_uring_netvc` autest asserts it. Verified
  Debug + ASan(0) + TSan(0 races in io_uring code) incl. the wrk load (64 conns).
  Known gaps: no batching (one accept in flight per thread; could submit several);
  shutdown cancels the pending accept via listen-socket close (-ECANCELED →
  handle_complete returns, no re-arm) — best-effort, not a targeted test.

## Frame allocator (leaf #3, 2026-06-22)

- **D29. Per-thread coroutine-frame pool = the path to epoll parity.** First perf
  baseline (cache-hit plain HTTP/1.1, ATS pinned to 4 saturated cores): the io_uring
  net path ran **15-27% below epoll**. Root cause: each `_read`/`_write`/`_connect`
  drive heap-allocates a ~1KB `DetachedTask` frame (an iovec array + msghdr +
  locals) and frees it at completion — one malloc/free per op, the dominant cost at
  saturation. A self-time profile **mis-ranks** it (malloc looks ~3%); the cost is
  the per-op allocation *instruction stream* (verified: a frame pool cuts
  instructions/req ~16% at near-flat IPC; an env-gated prototype, then a production
  allocator, both recover it).
- **Design: a bespoke thread-local bounded intrusive pool, NOT `ink_freelist`.**
  `detail::FramePool` in `Coroutine.h`, on `DetachedTask::promise_type`
  new/delete. Rationale for each choice: *thread_local* (no atomics) because VCs are
  thread-confined so a frame is allocated and freed on the same EThread — a global
  `ink_freelist` (versioned-CAS) would add needless atomics; *intrusive* free list
  (next-ptr in the freed frame) so the pool needs no allocation of its own;
  *bounded* (CAP=1024/size/thread, ≤8 size classes, else fall back to
  `::operator new`) so it can't grow with peak connection count (the prototype's
  never-free was the panel's main risk). *Honors `-f`/`-F`* via the new
  `ink_freelist_global_disabled()` accessor: when freelists are globally disabled
  every frame routes through malloc/free, so ASan still sees frame allocations —
  which the D25/D28 teardown test depends on.
- **Result:** within-campaign head-to-head, io_uring is now **−1.5% large / −2.4%
  small req/s vs epoll (was −27%/−15%), p99 BETTER on both** — residual ≤ IQR noise
  = effectively parity. Verified Debug + ASan (0 UAF, load + `-F` teardown) +
  non-io_uring build + format. **Not yet done (perf scope, deferred):** ≥10k-conn
  memory behavior, cache-MISS/origin-facing + H2/TLS scenarios, perf-stat
  replication — see [[io-uring-perf-baseline]].

## Deep-dive round (2026-06-23)

Full hypothesis→experiment→result→conclusion log: `PERF-CORO-IOURING.md`.

- **D30. Cross-thread wakeup doorbell — a regression the io_uring branch introduced,
  now fixed.** `initialize_thread_for_net` (`UnixNet.cc`) chose `IOUringEventIO` vs
  `AsyncSignalEventIO` at **compile time** (`#if TS_USE_LINUX_IO_URING`), so the
  io_uring build never registered `thread->evfd` — the fd `NetHandler::signalActivity`
  writes for cross-thread wakeups. A net thread blocked in `submit_and_wait` (or, on
  the epoll fallback, in `epoll_wait`) therefore could not be woken by another thread
  scheduling work onto it; such work stalled to the 60 ms heartbeat. Plain HTTP is
  unaffected (default `aio.mode=auto` completes disk reads on the net thread's own
  ring; connection work is thread-local), which is why it went unnoticed. **Repro:**
  force `aio.mode=thread` + low-concurrency disk cache → p99 62 ms on both the io_uring
  path and its epoll fallback (true master, USE_IOURING=0, is fine). **Fix, two parts:**
  (1) on the io_uring path, arm an `io_uring_prep_poll_multishot` on `thread->evfd` in
  the ring (`NetHandler::IOUringWakeup`), re-armed on `!IORING_CQE_F_MORE`, draining the
  counter each CQE — the io_uring-native equivalent of `AsyncSignalEventIO`; (2) on the
  epoll fallback, also register `thread->evfd` via `AsyncSignalEventIO` (inert on the
  io_uring path, which never waits on epoll). **Result:** p99 62 ms → ~2.1 ms on both
  paths, perf-neutral on the hot path (the poll only completes when rung). This is the
  correct way to be "fully io_uring without the eventfd": drop the *completion* eventfd
  (the io_uring→epoll bridge), keep a doorbell on the *wakeup* eventfd — in the ring.

- **D31. Write is now pure async (batched), reversing EXP-1b.** EXP-1b had kept an
  opportunistic synchronous `sendmsg` (fall back to io_uring on EAGAIN) because the
  async round-trip cost ~1.2%. That held only *before* the frame shrink (16 KB → 16
  iovec) + direct blocking made the CQE/resume nearly free. Re-measured: a pure async
  `io_uring_prep_send`/`sendmsg` rides the single `submit_and_wait` per loop, so at load
  many sends batch into one `io_uring_enter` and the per-request `sendmsg` syscall
  disappears — `sendmsg` 0.98→0/req, net syscalls ~halve, **cycles/req −1.8%** (IPC
  1.368→1.400), and the 64 KB write tail collapses (p99 ~550 ms → ~16 ms). The read
  stays async (EXP-1's finding stands: a keep-alive read is a genuine wait). Combined
  with D30, vs epoll: 4 KB +0.7% (noise), **64 KB −4.3%** (io_uring wins), cache-MISS
  1 MB +0.1%. Validated: 4 io_uring autests + ASan `-F` load/churn/timeout clean.

- **D32. Findings that did *not* produce a change (recorded so they are not re-litigated).**
  (a) `IOU_FRAME_IOV=16` is optimal: a sweep {1,4,16,64,256,1024} × {64 KB,1 MB,8 MB}
  shows iovec sensitivity *peaks at medium sizes* (64 KB U-curve, ±10%) and *vanishes*
  for large transfers (copy-bound) — both too-few (extra ops) and too-large (frame
  bloat) lose; 16 sits in the flat optimum. The "larger reads need a larger iovec"
  intuition is wrong. (b) A contiguous-slab frame arena measured ≈ the scattered LIFO
  freelist (±1%, noise): the frame is already ~300 B and the working set stays resident,
  so contiguity buys nothing at this scale. (c) Real-TCP (veth, MTU 1500, offloads off)
  holds parity (+1.9%/+0.0%), as does origin-facing cache-MISS (+0.1%) — the loopback
  result was not an artifact. (d) The clean n=3 mechanism **corrects** an earlier
  cross-session claim: io_uring is +1% instructions / +2% cycles vs master (not fewer),
  and the residual is *locality* (cache/dTLB/branch) in the `_read`/`_write` `.actor`
  bodies + `submit_and_wait`, not instruction count.

## Deep-dive round 2 (2026-06-23, follow-up questions)

Full H/E/R/C log: `PERF-CORO-IOURING.md` H7–H10. Harness now out-of-tree at
`~/work/io-uring-coro-bench` (the narrative stays here; the runnable rig does not).

- **D33. The residual is a memory *footprint* cost, not control-flow — and it is not
  reachable by huge pages or block sizing.** Precise/leaf profiling (H7): io_uring's
  excess is LLC misses (+79%) and dTLB page-walks (+59%) at `_read.actor` (the frame) +
  `submit_and_wait` (the rings), with **L1 unchanged** — cold-line/capacity, not L1
  thrash. The coroutine resume indirect-jump is **BTB-predicted** (not a branch-miss
  source, refuting the theory); the small branch excess is kernel SQE-issue. Huge pages
  (H8) can't reach ATS's `ink_freelist`/brk allocations (`AnonHugePages=0` across THP +
  glibc-`malloc.hugetlb`), and the working ATS hugetlb knob backs only the shared
  iobuffer arena (lowers both arms, no cpu/1k change). Bigger MIOBuffer blocks (H9) leave
  CQE/req immovable (67.6→67.0 across 8 KB→256 KB→+2 MB SO_RCVBUF) — backpressure, not
  block size, sets the recv count. **No production change from any of these.**
- **D34. Frame-cost mitigations evaluated and rejected — keep the FramePool.** Two
  attempts to make io_uring's efficiency show by removing the frame cost (H10): shrinking
  `IOU_FRAME_IOV` 16→8 (dead end — the cost is the allocation, not the byte count) and
  embedding the frame in the VC (`_read_frame`/`_write_frame` members, custom `operator
  new`, no-op delete; patch in `io-uring-coro-bench/prototypes/`). Frame-in-VC is correct
  and clean, but an interleaved fixed-rate A/B (the saturated large-object cpu/1k has a
  ±5% floor) shows **−0.5%, within noise** — the pool already keeps the frame hot — and
  it would add **1.28 KB to every VC** (worse memory scaling than the pool for idle
  keep-alives). Decision: **keep the pool; do not adopt either.** The frame is not the
  lever; reducing ops/req (the deferred multishot/provided-buffer features) is.
- **D35. Op-count audit + write-coalescing rejected (H11/H12).** Counting SQEs-by-opcode vs
  epoll syscalls per transaction: io_uring wins decisively on *syscalls* (1 MB passthrough
  18.2 `io_uring_enter` vs 52.6; 4 KB hot path 1.71 ops vs 2.93 — epoll wastes an EAGAIN
  drain-probe recvmsg), but does ~10% more *ops*, all **sends** — it emits one send per recv
  completion (`READ_READY` signalled after every recv at `IOUringNetVConnection.cc:377`)
  where epoll coalesces ~2 reads per send. Tried coalescing (accumulate reads before
  signalling, epoll-style): it cut sends 28.8→16.1/req (below epoll) and total ops below
  epoll, **but raised cpu/1k ~2% and instr/req a clean +6%** (revert restores it — not
  drift). Rejected: because the async batched write (H6) already amortized the send
  syscalls, coalescing strips near-free syscalls while adding multi-block `sendmsg` iovec
  build + read-accumulation cost. **Keep the simple per-block `prep_send`.** Instructive: it
  re-confirms H6 captured the real write win and H7's "per-op cost is small" framing.
- **D36. Real-NIC validation (hawaii, 1 GbE) — the loopback verdict is corrected in both
  directions (PERF-CORO-IOURING.md NV1–NV4).** All prior findings were loopback-only, where
  a syscall is cheap and a transmit is free. Re-ran the NIC-sensitive ones with ATS on
  `enp6s0` (atlantic) to a separate client host (M1 Mac Mini, `wrk`). **(a) Small object
  (4 KB): io_uring now WINS −6%** (was loopback parity) — its op batching (1.35
  `io_uring_enter`/req) beats epoll's ~3 syscalls/req where a syscall has real cost.
  **(b) Large object (1 MB): io_uring loses +5–8% on proc/instr** (loopback was +17% proc
  with no transmit cost) — its un-coalesced "1 send per recv" (H11) does ~2× epoll's driver
  `xmit` + TX-completion softirq. **(c)** An epoll-only send-strategy A/B isolated the two
  costs: `send()` < `sendmsg()` by ~480 instr/send on both media (NIC-independent
  `import_iovec`); and the **coalescing verdict flips sign** — no-coalesce+`send` was
  cheapest on loopback, **coalesce is cheapest on the NIC** (per-transmit cost is real).
  **(d)** The io_uring read-side coalescing (H12) is still rejected on the NIC, now for a
  *measured* reason: it halves in-flight op concurrency (read-only during accumulation vs
  per-block's read+write interleave), so completions batch less per `io_uring_enter`
  (loopback SQE-per-enter 97→53) — more event-loop iterations than the saved sends are
  worth. **No code change shipped** (all investigation); the recommendation is now: io_uring
  is a net win on small-object/keep-alive traffic and a bounded loss on large streaming
  bodies, the latter fixable by a write-side batch (preserving the read↔write interleave) or
  multishot recv. NIC-INDEPENDENT findings (H1/H2/H4/H8/H10) stand unchanged — pure
  CPU/cache/frame effects. Harness: `~/work/io-uring-coro-bench/scripts/measure-nic2.sh`,
  results in `findings/NIC-*.txt`.

## Multishot recv read path (2026-06-25)

Built `UringMultishotOp` (one SQE → stream of CQEs, `more()`/`flags()`, re-arm on
re-await) + `IOUringContext::setup_buf_ring`/`free_buf_ring` (committed `3d8900f737`,
socketpair-tested: poll/recv/recycle/-ENOBUFS-recovery, ASan-clean). Then an
EXPERIMENTAL flag-gated read path (`proxy.config.net.io_uring.read_multishot`, default
off): one armed multishot recv per VC against a shared per-thread provided-buffer ring,
each filled buffer attached to the read MIOBuffer **zero-copy** via a `RingBufferData :
IOBufferData` whose virtual `free()` recycles the buffer (works because
`RefCountObj::free()` is virtual and `IOBufferBlock::clone()` shares the
`Ptr<IOBufferData>`). `-ENOBUFS` parks the VC on a per-ring wait list; a recycle wakes it.

Findings (controlled experiments, `tests/gold_tests/io_uring/io_uring_read_multishot.test.py`):

- **The current single-shot recvmsg read path is already zero-copy** (recvmsg straight
  into the dest MIOBuffer blocks, per-VC growable buffer). So multishot's only solid win
  is fewer SQE submits + no per-op iovec (master hands up to `UIO_MAXIOV`=1024 segments;
  multishot hands 0) — small, and the read residual is footprint, not op-count.
- **Zero-copy + a fixed shared ring couples buffer lifetime to the SLOWEST consumer.**
  On a cache miss the cache-write consumer accumulates up to
  `proxy.config.cache.target_fragment_size` (default 1 MB) before flushing a fragment and
  releasing. Proven by single-variable flips: ring=32×8K(=object)+1 MB frag → **deadlock**
  (0 recycles); ring=4096×8K+1 MB frag → **pass**; ring=32×8K+**64 KB** frag → **pass**.
  So the liveness invariant is: **provided-buffer ring ≥ target_fragment_size ×
  concurrent cache-misses**, or the read deadlocks (needs a buffer to reach EOS; cache
  won't free one until EOS). Single-shot has no such floor (per-VC growable buffer).
- **The cache cannot be threaded zero-copy to disk today.** Cache-write `memcpy`s into a
  4 MB page-aligned aggregation buffer (`AGG_SIZE`) and io_uring-writes it (same per-thread
  ring; `aio.mode=auto`). The fd is **O_DIRECT** (`CacheProcessor.cc:231`), which requires
  every iovec segment block-aligned in base AND length — arbitrary recv buffers + the
  interleaved Doc header don't qualify, so a `writev` of raw buffers can't replace the agg
  assembly. The agg `memcpy` is the O_DIRECT alignment shim. ATS registers no io_uring
  buffers, so the O_DIRECT write re-`get_user_pages` every time.
- **Readiness is vestigial for io_uring reads.** `read_ready_list`/`write_ready_list` are
  touched only by `ReadWriteEventIO` (epoll edge — off for the io_uring VC) and
  `NetHandler`'s dequeue→`net_read_io`/`net_write_io`; nothing outside net reads them, and
  timeouts run off `netActivity` timestamps. A persistently-armed multishot recv would make
  the read-readiness path dead code for io_uring.

Direction (not yet built): the compelling framing is not "save SQE submits" but a
**registered (fixed) provided-buffer pool as a zero-copy substrate** — persistent-armed
recv into it, drop read-readiness, and a cheap self-contained first win:
`io_uring_register_buffers` on the existing agg buffers so O_DIRECT cache writes stop
re-pinning (no format/lifetime change). Full NIC→disk zero-copy is blocked by O_DIRECT
alignment, not by io_uring. Code committed as WIP, flag off by default.

### Verdict (2026-06-26): abandon multishot read; use single-shot + provided buffers

A keep-alive POST workload crashed multishot read at `ink_assert(0)` (Http1ClientSession
`state_keep_alive` got a bogus `VC_EVENT_READ_COMPLETE`). Root cause: multishot must
cancel + drain to stop the armed stream, which inserts a `co_await` suspension between
*deciding* the read is complete (`ntodo<=0`) and *signaling* `READ_COMPLETE`. During that
suspension the connection's response WRITE completes, the tunnel injects its own
`READ_COMPLETE` (`HttpTunnel.cc:1539`) and `Http1ClientSession::release` issues
`do_io_read(INT64_MAX)` for keep-alive — reassigning `read.vio` — so the deferred
`READ_COMPLETE` lands on the keep-alive VIO. Epoll/single-shot never hit this: they
compute-and-signal in one non-suspending pass, re-checking `ntodo()/enabled` after each
callback (`UnixNetVConnection.cc:591/601/608`).

The violated contract is real, not incidental: "no read events after the read is
stopped/disabled/completed" is documented (`do_io_shutdown`/`do_io_close` "MUST NOT send
any further events"; `reenable`; INV-R5), assumed by consumers (survey: 17 fatal
`ink_assert(0)`/`ink_release_assert(0)` handlers on an unexpected read event vs 3
defensive), and structurally provided by the epoll path.

The stale signal is suppressible (signal before the drain; re-validate the VIO), but the
deeper problem is structural and unavoidable: with a SHARED provided-buffer ring (`bgid`
is 16-bit; prod has >>64k conns, so per-connection rings are impossible) the only way to
apply *per-connection* backpressure to a multishot — stop one slow connection without
`-ENOBUFS`-starving the shared pool for the others — is to CANCEL its op. Verified against
kernel 6.17: no throttle/pause/partial-consumption feature does it (`IOU_PBUF_RING_INC`
6.12, `REGISTER_PBUF_STATUS` 6.8, `RECVSEND_BUNDLE` 6.10 all checked and rejected), and no
prior-art server does no-cancel per-connection backpressure on a shared multishot ring
(the runtimes that get free backpressure use owned-buffer single-shot). And
cancel-for-backpressure must STAGE the in-flight bytes the drain would otherwise drop —
the current drain `recycle()`s them (`IOUringNetVConnection.cc:719`), a latent data-loss
bug masked today only because cancel fires solely at end-of-read, where the recv is armed
waiting and nothing is in flight.

So multishot read needs the full apparatus — proactive cancel per throttle, a bounded
staging buffer, deferred re-arm, the in-flight-after-cancel race — to buy one thing: SQE
collapse on large streaming reads (~1 arm vs ~750 single-shot recvs/MiB). That win
concentrates entirely in large reads, while proxy traffic is dominated by small keep-alive
reads where the economics invert (arm + throttle-cancel = 2-3 ops vs single-shot's 1).

**DECISION:** drive reads with SINGLE-SHOT recv + provided buffers (the existing
`ReadBufRing` infra, demand-driven). Per-connection backpressure is free — don't submit the
next recv; nothing is armed, so nothing to cancel, no window, no stale-VIO crash, no
interleave, no stage. It keeps the provided-buffer late binding (the kernel picks a ring
buffer only when data is ready, so idle keep-alive connections hold no read buffer), caps
each connection to ~1 in-flight buffer (fair shared-pool use vs multishot's `F_MORE`
bursts), and caps each recv to `min(ntodo, bufsize)`. Cost: +1 SQE per read vs multishot,
but an SQE build is not a syscall (batched submit amortizes it). Multishot stays only as
recorded above — a dead end for the shared-ring read path.

## Open / pending decisions

- Whether/when to go fully completion-driven for reads/writes (drop epoll
  interest entirely and rely only on io_uring completions).
- accept/connect via io_uring (`io_uring_prep_accept` / `_connect`).
- Cross-thread migration (`migrateToCurrentThread`) for the global session pool.
- A pooled coroutine-frame allocator (currently one heap alloc per read episode).
- Targeted close-with-recv-in-flight test (e.g. inactivity timeout while a
  keep-alive read is armed) — the deferred path is currently exercised only
  incidentally by load churn.

### Real-NIC perf: single-shot provided-buffer read path (2026-06-26)

A/B/C on the real NIC (enp6s0/atlantic 1GbE, ATS pinned to P-cores 0,2,4,6 via cgroup;
wrk on hawaii), POST 1 MiB -> generator so the client-facing read path is the dominant
work. Three read drives as runtime flags on one fp Release binary, 5 reps, medians:

| read drive            | cpu/1k | vs epoll | instr/req | cyc/req | read syscalls/req |
|-----------------------|--------|----------|-----------|---------|-------------------|
| epoll (recvmsg)       | 4.610  | --       | 13.89M    | 11.20M  | 1456 recvmsg      |
| io_uring recvmsg      | 4.131  | -10.4%   | 13.01M    | 9.67M   | 0 (744 enter)     |
| io_uring provided-buf | 4.188  | -9.2%    | 13.16M    | 9.82M   | 0 (713 enter)     |

All NIC-bound at 114 req/s (~93% of line rate); throughput and p99 (~536 ms, pure NIC
queueing at c64x1MB) identical across modes, so CPU/req is the differentiator. Both
io_uring drives beat epoll ~9-10% cpu/req (-13% cyc/req) by turning ~1456 recvmsg
syscalls/req into SQEs. The provided-buffer drive is at parity with the recvmsg drive
(+1.4% cpu/1k, consistent across all 5 reps) --- the cost is userspace bookkeeping
(RingBufferData alloc/recycle + buf_ring add/advance), NOT syscalls (provided issues
slightly fewer io_uring_enter, 713 vs 744). The +1.4% buys idle-connection late binding
(no read buffer held while idle), fair shared-pool use, per-connection backpressure, and
removal of the stale-VIO crash class. Caveat: at 1500 MTU reads are MTU-paced (~1.45 KB),
so 8 KB provided buffers run ~18% full --- the late-binding memory win is for idle
connections (not measured here, saturated-CPU test). Harness: io-uring-coro-bench/scripts/
measure-read-ab.sh + setup-box.sh.

### Idle-connection memory: provided vs recvmsg vs epoll (2026-06-26)

The provided-buffer memory question (CPU is parity, the value is memory): with many IDLE
keep-alive connections, io_uring keeps a recv armed per connection. Does the provided
shared ring avoid the per-connection read buffer that the recvmsg drive pins? Measured by
holding N idle keep-alive conns (loopback holder) and reading ATS per-allocator in-use
(ink_freelists_dump) + RSS, for all three read drives on one fp binary. N=10000:

| per-conn allocator           | epoll      | io_uring recvmsg | io_uring provided |
|------------------------------|------------|------------------|-------------------|
| read buffer ioBufAllocator[5]| 4.0 KB     | 4.0 KB           | 0                 |
| VC (netVC / ioUringNetVC)    | 1.51 KB    | 1.56 KB          | 1.56 KB           |
| session (http1ClientSession) | 1.02 KB    | 1.02 KB          | 1.02 KB           |
| fixed per-thread ring        | --         | --               | ~33 MB (4096x8K)  |

Finding: epoll AND recvmsg each pin one 4 KB session read buffer per idle connection
(10000 in-use 4 KB blocks for 10000 conns); the recvmsg armed recv REUSES the session
block (no second buffer). provided holds ZERO --- its data lands in the shared ring,
released after each request, so an idle connection's read buffer is empty. So provided
saves ~4 KB/idle-conn vs BOTH (not io_uring-specific: epoll holds it too; provided's shared
ring is what removes it). VC + session memory identical across modes. The 4 KB is traded
for a FIXED ~33 MB/thread ring (faults into RSS during the test, which is why raw dRSS/conn
looked flat ~10 KB at 10k): it amortizes --- ~3.3 KB/conn at 10k (~cancels the 4 KB saved),
~0.3 KB/conn at 100k (4 KB/conn saving dominates, ~370 MB saved); below ~4k conns the ring
costs more than it saves. Net: provided wins memory in the many-idle-connections regime
(conns >> ring buffers), wash/loss at low counts. Bounded here by the small 4 KB header
buffer; larger held read buffers would widen the saving. Caveat: both io_uring modes carry
a per-conn suspended coroutine frame epoll lacks (does not amortize). Harness:
io-uring-coro-bench/scripts/measure-idle-mem.sh + idle_holder.py.

### Zero-copy receive exploration (2026-06-26): pinned pending HDS hardware

Explored eliminating the skb->userspace copy (`_copy_to_iter`, the dominant per-byte read
cost --- ~25% of CPU on the loopback profile). Two mechanisms, both gated on hardware
header/data split (HDS) for a server taking arbitrary inbound traffic:

- **TCP_ZEROCOPY_RECEIVE** (getsockopt, ~4.18): remaps received skb pages into userspace via
  vm_insert_page instead of copying. API is NIC-independent, but only zero-copies the
  page-aligned portion and pays a per-call vm_insert + madvise(DONTNEED) TLB cost. Verified
  with a socketpair test (/tmp/tcpzc_test.c): **0% mapped on a default loopback send**
  (page_frag packing leaves payload unaligned), **87.7% only after forcing the SENDER to hand
  page-aligned pages via MSG_ZEROCOPY** --- a loopback artifact (controlled sender + loopback
  forwarding frags intact). On a real NIC the wire erases alignment (MSS segmentation +
  receiver re-DMA -> payload at offset ~54), so inbound-from-arbitrary-clients maps ~0%
  without HDS. NOT a generic server win.
- **zcrx** (io_uring zero-copy rx, kernel 6.15): NIC DMAs payload directly into a registered
  "area" via HDS; IORING_OP_RECV_ZC reaps {area-offset,len} aux CQEs; app returns buffers via
  a refill ring. True from-the-wire zero-copy, HDS-gated.

Verdict: zero-copy RECEIVE for arbitrary inbound REQUIRES HDS at the receiving NIC (the wire
carries no page boundaries). The atlantic/aqc107 1GbE here lacks HDS -> neither exercisable.
Pinned pending an mlx5/bnxt-class card. Also wants a cleartext/bulk path (TLS delivers
ciphertext; decrypt re-copies --- but the IO/crypto-decoupling TLS refactor makes ciphertext
consumable, so it's one-fewer-copy not zero-benefit; pays off only above ~4KB).

**zcrx adoption sketch** (if HDS arrives): data-path seam is clean --- `RingBufferData` (wrap
area+offset, `free()` posts to the refill ring) + the kept `UringMultishotOp` port ~80%.
zcrx is **multishot-ONLY** (`io_recvzc_prep` rejects non-multishot), so it resurrects a
persistent multishot recv --- BUT buffer-SAFE: the recv owns no buffer (NIC fills the area
independently via the refill ring), so cancel drops no data (reaped data pinned by user_refs;
unreaped stays in the socket queue). Only the control-flow stale-VIO hazard remains (guard aux
CQEs vs a torn-down VIO; F_MORE-clear = only terminator). Real work = the SETUP layer:
ifq/area/refill registration + ET_NET-thread<->NIC-rx-queue affinity (one ifq/queue, RSS
steering) + queue-global backpressure (a slow consumer pinning area blocks stalls the whole rx
queue -> per-consumer pin budget). A parallel HDS-gated fast path, not a rewrite of _read_provided.

**Read-drive standing** (no zero-copy, real NIC, cpu/1k medians): recv->MIOBuffer (`_read`,
provided off) = 4.131, cheapest + the default; provided buffers (`_read_provided`) = 4.188
(+1.4%) for the 4KB/idle-conn memory saving (opt-in, off); zcrx pinned. NEXT: zero-copy +
multishot for the WRITE path (SEND_ZC needs no HDS -> testable on this box).

### Write-path zero-copy send (SEND_ZC): implemented, gated off, a CPU LOSS on 1GbE (2026-06-26)

Unlike zero-copy RECEIVE (HDS-gated, untestable here), zero-copy SEND needs no special NIC
(only NETIF_F_SG; the kernel silently copy-falls-back otherwise) and is TLS-compatible in
principle (the ciphertext is the wire data), so it was buildable + measurable on the atlantic
1GbE here.

Implemented `proxy.config.net.io_uring.write_zerocopy` (+ `write_zerocopy_threshold`, default
4096; both restart, off by default). In `_write`, when the coalesced send is >= the threshold:
submit io_uring_prep_send_zc / sendmsg_zc (with IORING_SEND_ZC_REPORT_USAGE) via the multishot
awaitable, hold a Ptr<IOBufferBlock> anchor per source block, await the send-result CQE then
DRAIN the IORING_CQE_F_NOTIF CQE (the send CQE's F_MORE flags that a notification follows; the
source pages are NOT free until it lands --- typically after the peer ACK), then drop the
anchors + consume. The existing clone-for-iovec discipline ports directly. Teardown holds
_write_op set across both CQEs so the deferred free waits until the notification drains.

VALIDATION: functional (20/20 1MiB cache hits returned intact, no crash); ASan-clean under
teardown churn + mid-write client aborts (the pinned-pages-vs-free hazard); and zc_copied=0 on
the real NIC --- the fast path is genuinely live (loopback ALWAYS copy-falls-back for
MSG_ZEROCOPY, so it must be NIC-tested, not loopback).

REAL-NIC A/B (atlantic 1GbE -> hawaii, 1 MiB cache-hit GET, 3 reps, medians):
| mode          | cpu/1k | instr/req | io_uring_enter/req | zc_copied |
|---------------|--------|-----------|--------------------|-----------|
| sendmsg (off) | 0.432  | 654 K     | 31.2               | --        |
| send_zc (on)  | 1.171  | 1787 K    | 62.2               | 0         |

=> send_zc is **+171% cpu/1k on 1GbE --- a clear LOSS.** Mechanism: the per-send F_NOTIF
doubles the CQEs / io_uring_enter and adds page-pinning, while at 1GbE the LINK (not memory
bandwidth) is the bottleneck, so the copy it eliminates is trivially cheap (~1 MiB x 113/s =
~113 MB/s of memcpy). The published send_zc wins (+22% @ 4 KB etc.) are on FAST NICs where the
copy bandwidth dominates; on a slow link the fixed notification overhead exceeds the cheap
copy. So SEND_ZC needs a 10/25/100 GbE NIC to pay off --- pinned on hardware like the read side,
but for a different reason (read: HDS; write: a memory-bandwidth-bound link). Bundle/multishot-
send rejected (no multishot send exists; BUNDLE == the coalesced sendmsg we already do).

Kept flag-gated + OFF by default: correct, validated, and a ready fast-NIC lever. Harness:
io-uring-coro-bench/scripts/measure-write-zc-ab.sh.

#### Correction (2026-06-26): the SEND_ZC loss is the IOMMU, not memory bandwidth / NIC speed

The "1GbE is not memory-bandwidth-bound" reasoning above is WRONG. System-wide perf profiling
(measure-write-zc-ab + profile-write-zc-sys, atlantic NIC -> hawaii) traced the +171% to the
IOMMU. Cost by mechanism (system-wide self%, summed across cores):

| mechanism                         | noz (copy) | zc (send_zc) |
|-----------------------------------|-----------:|-------------:|
| IOMMU / DMA-map (__domain_mapping,clflush) | 4.37 | **8.80** |
| payload copy (_copy_from_iter)    | 1.57       | 0.04         |
| skb page alloc/zero (clear_page)  | 2.80       | 0.03         |
| io_uring enter/CQE                | 0.43       | 0.71         |
| pin/unpin pages                   | 0.00       | 0.30         |
| ZC notification                   | 0.01       | 0.12         |

Root cause: this box runs Intel VT-d in TRANSLATE mode (default domain type DMA-FQ on all 19
groups incl. the NIC). So the NIC cannot DMA from the app's cache pages without a per-send
IOMMU mapping (__domain_mapping + clflush of the PTEs) on submit + an unmap on ACK. The copy
path avoids this because its skb pages come from a RECYCLED kernel pool whose IOMMU mappings
are reused; send_zc's source is the per-request cache blocks --- different physical pages each
send --> a FRESH mapping every time, uncacheable. The IOMMU-map share DOUBLED (4.4 -> 8.8%) and
exceeded the copy+page-zero it removed (~4.3%). NIC speed is NOT the driver (the per-send cost
is fixed); the IOMMU per-send translation is.

Prod relevance: DMA-FQ is the distro DEFAULT (device isolation), NOT what a throughput-tuned
prod host runs. CDN/NFV/hyperscaler hosts boot iommu=pt (passthrough) or IOMMU off precisely
to avoid per-DMA translation. So this result is PESSIMISTIC vs prod. Untested hypothesis: under
iommu=pt (or send_zc_fixed with the cache region registered = mapped once), the __domain_mapping
cost vanishes and send_zc should flip to a win (removes the copy for ~free). This box's NIC is
alone in IOMMU group 18, so a runtime switch to an identity domain (no reboot) is feasible to
test. Field survey prompt: research/zerocopy-write-landscape-prompt.md.

#### iommu=pt empirical test (2026-06-26): IOMMU is ~half the loss; a notification-roundtrip residual remains

Switched the atlantic NIC's IOMMU group to an identity (passthrough) domain at runtime (no
reboot: unbind atlantic -> echo identity > /sys/kernel/iommu_groups/18/type -> rebind -> DHCP),
i.e. the prod-typical iommu=pt config for that device, and re-ran the A/B (1 MiB cache-hit GET,
atlantic 1GbE -> hawaii, 3 reps, cpu/1k medians):

| mode | DMA-FQ (translate) | identity (passthrough) |
|------|-------------------:|-----------------------:|
| noz (sendmsg) | 0.432 | 0.339 |
| zc (send_zc)  | 1.171 | **0.589** |
| zc vs noz     | +171% | **+74%** |

Passthrough HALVED zc's cpu/1k (1.171 -> 0.589) and the confirming profile shows IOMMU/DMA-map
8.80% -> 0.09% --- the per-send __domain_mapping is gone, proving it was real. But zc is STILL
+74% vs noz under passthrough. The residual is the NOTIFICATION ROUNDTRIP: every send_zc posts a
second F_NOTIF CQE that lands ~an RTT later in its own event-loop iteration, so enter/req stays
2x (62 vs 31) --- an extra io_uring_enter + coroutine resume per send. That is intrinsic to
send_zc (you must reap the NOTIF to free the pages) and to the demand-driven write (each block's
completion gates the next). At 1GbE the copy it buys back is tiny (_copy_from_iter ~1.6% +
page-zero ~2.8%), so there is almost nothing to offset the notification cost.

Decomposition of the original +171%: ~+97pts IOMMU translate-mode per-send mapping (config-
dependent; prod likely runs iommu=pt) + ~+74pts notification roundtrip (intrinsic) against a
near-zero copy saving (1GbE). So send_zc needs BOTH (a) passthrough / registered buffers (to
kill the IOMMU mapping) AND (b) a NIC fast enough that the eliminated copy is actually expensive
(bandwidth-bound), to win. Registered buffers (send_zc_fixed) would remove the pinning but NOT
the notification roundtrip, so they alone won't close the +74% on a slow NIC. This box (1GbE)
cannot exhibit a win; a 10/25/100 GbE host with iommu=pt is the regime to test next. Box restored
to DMA-FQ after the test.

#### Microbench decomposition (2026-06-27): corrects "pinning is 65% of the residual" -> it is the NOTIFICATION

An isolated io_uring send_zc microbench (scripts/sender_zc.c, atlantic -> hawaii sink, copied=0
true ZC at window=2) decomposes the residual by comparing three modes at the SAME send size:
send (plain copy, 1 CQE), zc (send_zc, per-send pin + 2 CQEs), fixed (send_zc_fixed, registered
buffer = pinned once, 2 CQEs). At passthrough (no IOMMU), instr/MB:

| send size | copy | zc  | fixed | residual(zc-copy) | pinning(zc-fixed) | pin % of residual |
|-----------|-----:|----:|------:|------------------:|------------------:|------------------:|
| 32 KB     | 204K | 813K| 738K  | 609K              | 75K               | **12%**           |
| 64 KB     | 156K | 413K| 325K  | 257K              | 88K               | 34%               |
| 256 KB    | 124K | 209K| 128K  | 85K               | 81K               | 95%               |
| 512 KB    | 118K | 159K| 79K   | 41K               | 80K               | 195%              |

The earlier "pinning ~65% of the residual" (from a noisy ATS perf-diff bucketing) was WRONG. At
our 32 KB send size the residual is 88% the NOTIFICATION ROUNDTRIP (the 2nd F_NOTIF CQE: extra
io_uring submit/reap + ZC skb build) and only 12% pinning. Two facts make this precise:
 - Pinning is ~CONSTANT 80K instr/MB across all send sizes (256 page-pins/MB regardless of
   coalescing) -- it is a per-BYTE cost. Registered buffers remove it.
 - The notification roundtrip is per-SEND, so it shrinks as sends coalesce: 530K/MB at 32 KB
   (32 sends) -> ~0 at 512 KB (2 sends). Only coalescing removes it.

So the two levers are COMPLEMENTARY and size-dependent: coalescing kills the (dominant-at-small-
sends) notification; registered buffers kill the (dominant-at-large-sends) pinning. TOGETHER they
flip the verdict: at 512 KB sends with registered buffers, fixed = 79K instr/MB BEATS the copy
path's 118K by 33% -- send_zc wins on this 1GbE box once both levers are applied. Plain send_zc
(anonymous, 159K) still loses to copy at 512 KB because the 80K/MB pinning keeps it above.

Size lever, standalone (zc, instr/MB vs send size): 32K=1060K, 128K=490K, 512K=205K -- 5.2x from
coalescing alone, since ~85% of the 32 KB send-path instructions are per-operation, not per-byte.

Implication for the ATS path: its writes are buffer-capped at 32 KB (4x 8K blocks; IOU_FRAME_IOV
allows 16 but the response buffer water-mark gates occupancy), i.e. the worst case -- max
notifications, ZC a clear loss. Making ATS send_zc win needs BOTH (a) large coalesced sends
(raise the write water-mark / coalesce target) AND (b) registered cache buffers. Neither alone
suffices. Harness: scripts/sender_zc.c + the persistent hawaii python sink.
