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

## Open / pending decisions

- Whether/when to go fully completion-driven for reads/writes (drop epoll
  interest entirely and rely only on io_uring completions).
- accept/connect via io_uring (`io_uring_prep_accept` / `_connect`).
- Cross-thread migration (`migrateToCurrentThread`) for the global session pool.
- A pooled coroutine-frame allocator (currently one heap alloc per read episode).
- Targeted close-with-recv-in-flight test (e.g. inactivity timeout while a
  keep-alive read is armed) — the deferred path is currently exercised only
  incidentally by load churn.
