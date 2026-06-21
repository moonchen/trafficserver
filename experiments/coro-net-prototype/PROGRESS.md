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

## Phase 2 — convert one leaf of the net path (the read path) — NEXT

Bring the `net-iouring` branch's `IOUringNetVConnection` onto the current tree
(it predates the `include/iocore` reorg — expect to relocate files and fix
includes), then convert **reads only**:

1. Replace `IOUringReader` + `prep_read` + the `ops_in_flight` read bookkeeping
   with a coroutine read loop driven by `UringOp` (`io_uring_prep_recv`/`recvmsg`).
   Keep `do_io_read` + the VIO/`Continuation` signalling identical to callers.
2. Buffer/iovec lives in the coroutine frame across the await (deletes the
   class-scope `msghdr` hack).
3. `do_io_close` = `UringCancel` + `co_await` the `-ECANCELED`, then unwind —
   not the branch's `delete this` (the known UAF).
4. Leave the **write** path on the old mechanism (mixed is fine; keeps the diff
   reviewable).

Acceptance: ATS builds `-DUSE_IOURING=1`; a focused autest/unit test drives an
inbound connection whose reads go through the coroutine path, verifying correct
data and clean close (no UAF under ASan).

Later leaves, in order: write path → accept/connect → full close → then the
bigger items the spike left out (TLS, timeouts via `IORING_OP_TIMEOUT`,
MIOBuffer, SQ-full backpressure as a suspending await, migration).
