# Porting the coroutine io_uring model into ATS — progress

This tracks the in-tree port described in [NEXT-STEPS.md](NEXT-STEPS.md). The
standalone prototype in this directory stays as the reference; the work below is
on the real ATS tree.

## Phase 1 — coroutine io_uring runtime + unit test — DONE

A minimal, header-only coroutine runtime now rides the existing per-thread
`IOUringContext` (the disk-AIO ring pumped by `NetHandler::waitForActivity`) —
no new thread, no new event loop.

**Landed (3 commits):**
- `include/iocore/io_uring/Coroutine.h` — the runtime, gated `#if TS_USE_LINUX_IO_URING`:
  - `Task<T>` (owned, RAII handle, eager start, `done()`/`result()`) and
    `DetachedTask` (fire-and-forget, self-cleaning frame), ported from the
    prototype's `reactor.h`.
  - `UringOp<Prep>` — an awaitable that *is* an `IOUringCompletionHandler`. It
    arms a caller-prepared SQE on `local_context()` (`this` == SQE `user_data`)
    and resumes the awaiter from `handle_complete()` with `cqe->res`. The prep
    callable is held by value (templated, not `std::function`) so the buffer
    lifetime is structural and allocation-free.
  - `UringCancel` — `io_uring_prep_cancel` for cancel-then-unwind. Unlike the
    prototype's sentinel `user_data`, it is a *real* handler, because ATS's
    `IOUringContext::service()` dispatches `handle_complete()` on **every** CQE's
    `user_data` (a sentinel pointer would be dereferenced).
- `src/iocore/io_uring/unit_tests/test_coroutine.cc` — Catch2 tests driving the
  runtime over an `AF_UNIX` socketpair, pumped by hand exactly like
  `waitForActivity`. Covers: recv/send echo, `DetachedTask` to completion,
  `Task<int>` value return, and **cancel-then-unwind** (an in-flight recv
  cancelled via `UringCancel` resumes with `-ECANCELED` and the frame is
  reclaimed — the fix for net-iouring's `delete this`-with-an-op-in-flight UAF).
- `src/iocore/io_uring/CMakeLists.txt` — registers `test_iouring_coro`; also
  fixes the pre-existing `test_iouring` link (it lacked a Catch2 `main`).

**Verified:**
- Debug `-DUSE_IOURING=1`: 4 cases / 22 assertions; 20× repeat + 10× random-order
  all clean; `ctest -R iouring` green (both io_uring tests).
- ASan: 5/5 clean — no leaks, no UAF (proves frame reclamation + safe teardown).
- clang-format clean (pinned 18.1.2); the header is a verified no-op when
  io_uring is disabled, so the default build is untouched.
- Adversarial multi-lens review (lifetime/UAF, teardown/re-entrancy,
  API/portability): 0 real correctness bugs; only doc clarifications applied.

**Invariant to carry into Phase 2:** never destroy a `Task` whose coroutine is
still suspended on an in-flight op — that frees the awaitable that is the
kernel's `user_data`. Cancel-then-unwind (drive to `done()`) first. This is the
contract `do_io_close` must honor (documented on `Task` in `Coroutine.h`).

## Build & test recipe (corrections to NEXT-STEPS.md)

- The `dev` preset's binary dir is **`build-dev`** (not `build/dev`).
- The ctest filter is **`-R iouring`** (the targets are `test_iouring*`, no
  underscore — `-R io_uring` matches nothing).

```sh
cmake --preset dev -DUSE_IOURING=1
cmake --build build-dev --target test_iouring_coro
ctest --test-dir build-dev -R iouring --output-on-failure
# ASan: cmake --preset dev-asan -DUSE_IOURING=1 && cmake --build build-dev-asan --target test_iouring_coro
```

## Phase 2A — clone UnixNetVConnection, hook plain HTTP, identical baseline — DONE

Per maintainer guidance (don't port the old `net-iouring` stack — it predates the
`include/iocore` reorg and uses removed APIs throughout; instead add a new VC the
way `SSLNetVConnection` subclasses `UnixNetVConnection`, then swap pieces to
io_uring one at a time):

**Landed (3 commits):**
- `src/iocore/net/{P_IOUringNetVConnection.h,IOUringNetVConnection.cc}` —
  `IOUringNetVConnection : public UnixNetVConnection`. For now a behavioral clone
  (all I/O inherited); own `ClassAllocator` + `free_thread` override returning to
  it (uses the global allocator directly — no per-thread `ProxyAllocator` member
  on `Thread`). Gated `#if TS_USE_LINUX_IO_URING`.
- `proxy.config.net.io_uring.enabled` (record, default 0) gates
  `UnixNetProcessor::allocate_vc`: when set, plain (non-TLS) connections are
  minted as `IOUringNetVConnection`. Read once, announced with a NOTE.
- `tests/gold_tests/io_uring/io_uring_netvc.test.py` — plain-HTTP transaction with
  the flag on; checks the origin body is proxied intact **and** that the io_uring
  VC path actually engaged (the NOTE in diags.log), not a silent fallback.

**Verified:** autest passes (Debug, `-DUSE_IOURING=1`, install to /tmp/ats-dev),
engagement proven. Default (flag off) path is the stock `allocate_vc`, unchanged.

Autest harness gotchas (this box): `pipenv` is broken — build a uv venv
(`uv venv /tmp/ats-autest-venv --python 3.10` + `uv pip install autest==1.10.4
traffic-replay microserver ... `), put its bin on PATH (so the spawned
`microserver` is found), and run `autest run -D gold_tests --ats-bin
/tmp/ats-dev/bin --build-root build-dev --sandbox <dir> -f io_uring_netvc`.

## Phase 2B — swap the read path to io_uring recvmsg — NEXT (the deep step)

The seam is `net_read_io` (UnixNetVConnection.cc): it builds an iovec from the
read MIOBuffer's write blocks and does a synchronous `con.sock.recvmsg`, then
fills + signals the read VIO. Reads are *triggered* by epoll readiness
(`reenable` → `ep.modify(EVENTIO_READ)` → `read_ready_list` → `net_read_io`).

Converting to io_uring is not a one-liner because it changes the control model
(completion- vs readiness-driven). The hard problems to design for:
1. **Trigger.** Either keep the epoll-readiness trigger and only async-ify the
   recvmsg (submit on EPOLLIN, signal from the completion) — simplest first cut,
   reuses the enable/backpressure machinery — or go fully completion-driven and
   suppress epoll read interest (`ep.modify(EVENTIO_READ)`) entirely.
2. **VIO mutex under async completion.** `net_read_io` holds `read.vio.mutex`
   across the (synchronous) read+signal. With an async recv the mutex can only be
   taken *after* the completion resumes; rely on thread-confinement so it is
   uncontended (the coroutine resumes on the owning EThread under the NetHandler
   mutex, via `IOUringContext::service()` in `waitForActivity`).
3. **Backpressure / re-arm.** Stop reading when the buffer is full; re-arm on
   reenable. A restart-per-episode coroutine (start on reenable, exit when it
   can't progress) avoids a persistent parked coroutine.
4. **Teardown re-entrancy.** A read signal can close (free) the VC; and
   `do_io_close` may fire with a recv in flight. Use cancel-then-unwind
   (`UringCancel` the in-flight recv, let the read coroutine unwind, free after) —
   exactly what the Phase-1 runtime + the prototype were built for.

The Phase-2A autest is the regression guard across this swap.

## Later leaves (after 2B), in order

Write path (`load_buffer_and_write` → io_uring `sendmsg`) → `do_io_close` fully
on cancel-then-unwind → accept/connect → then the bigger items the spike left
out: TLS (via the layered SSLNetVConnection once that refactor lands), timeouts
via `IORING_OP_TIMEOUT`, SQ-full backpressure as a suspending await, migration.

Each leaf keeps the `do_io_*` + `Continuation`/VIO facade identical to callers
and is guarded by the Phase-2A autest plus any leaf-specific test.
