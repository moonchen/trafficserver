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

- **D24. KNOWN DIVERGENCE: a black-holed origin connect (SYN dropped) returns 000
  to the client under io_uring vs 502 on master/epoll.** Root cause is NOT the
  io_uring teardown: `Connection::connect` returns 0 on EINPROGRESS (optimistic),
  so ATS reports the handshake complete (`CONNECT_EVENT_TXN`) and applies the 30 s
  post-connect timeout instead of the 2 s connect timeout; with epoll the failure
  is surfaced differently than with io_uring's internal-poll wait. Deep
  HttpSM/ConnectingEntry/connect-failure-detection territory; an edge case (origin
  silently dropping SYNs). Repro: `iptables -A OUTPUT -p tcp -d 127.0.0.1 --dport
  <p> -j DROP`, remap to that port, short `connect_attempts_timeout`. NOT yet
  fixed — needs its own investigation (likely explicit connect-failure detection).

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

## Open / pending decisions

- Whether/when to go fully completion-driven for reads/writes (drop epoll
  interest entirely and rely only on io_uring completions).
- accept/connect via io_uring (`io_uring_prep_accept` / `_connect`).
- Cross-thread migration (`migrateToCurrentThread`) for the global session pool.
- A pooled coroutine-frame allocator (currently one heap alloc per read episode).
- Targeted close-with-recv-in-flight test (e.g. inactivity timeout while a
  keep-alive read is armed) — the deferred path is currently exercised only
  incidentally by load churn.
