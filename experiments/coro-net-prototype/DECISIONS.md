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

## Open / pending decisions

- Whether/when to go fully completion-driven for reads/writes (drop epoll
  interest entirely and rely only on io_uring completions).
- accept/connect via io_uring (`io_uring_prep_accept` / `_connect`).
- Cross-thread migration (`migrateToCurrentThread`) for the global session pool.
- A pooled coroutine-frame allocator (currently one heap alloc per read episode).
- Targeted close-with-recv-in-flight test (e.g. inactivity timeout while a
  keep-alive read is armed) — the deferred path is currently exercised only
  incidentally by load churn.
