# Prompt: port the coroutine io_uring net model onto real ATS

You are picking up a research effort in the Apache Traffic Server tree. A working,
standalone C++20 coroutine networking prototype already exists under
`experiments/coro-net-prototype/`, along with two design notes. Your job is to
take the **next concrete step**: prove the coroutine model on real ATS plumbing by
landing a minimal coroutine io_uring runtime in-tree and converting **one leaf** of
the existing io_uring net path to use it.

Read these first (they are the spec):
- `experiments/coro-net-prototype/README.md` — the design, the three "seams", and
  the thread-confinement / no-per-VC-mutex / sync-destination-pulled-migration
  decisions. Honor these decisions; don't relitigate them.
- `experiments/coro-net-prototype/ATS-INTEGRATION.md` — the precise mapping from
  the prototype onto ATS's existing `IOUringContext`, and a concrete `UringOp`
  awaitable sketch. **This is the blueprint for Phase 1.**
- The prototype sources themselves (`io_backend.h`, `reactor.h`, `async_socket.h`,
  `coro_netvc.{h,cc}`) — the reference implementation of the awaitable + VC facade.

Background you must internalize:
- The disk-AIO io_uring work is already on `master`: every `ET_NET` thread has a
  `thread_local IOUringContext` (`include/iocore/io_uring/IO_URING.h`,
  `src/iocore/io_uring/io_uring.cc`) that is `submit()`/`service()`-pumped inside
  `NetHandler::waitForActivity` (`src/iocore/net/NetHandler.cc`) via an eventfd
  bridge (`IOUringEventIO`). Completions dispatch through
  `IOUringCompletionHandler::handle_complete(io_uring_cqe*)` keyed on SQE
  `user_data`. **You reuse this; you do not build a new reactor or thread.**
- The fork's `net-iouring` branch already added socket io_uring to ATS by hand:
  `IOUringNetVConnection` with `IOUringReader`/`IOUringWriter` (both
  `IOUringCompletionHandler`s) and a manual `ops_in_flight` counter and
  class-scope `msghdr`/`iovec`. See `git show net-iouring:iocore/net/IOUringNetVConnection.cc`
  (functions `prep_read`, `prep_write`, `load_buffer_and_write`). **This is the
  code your coroutine version replaces, one leaf at a time.**

## Goal

Replace hand-written completion-handler objects + explicit state with C++20
coroutines, driven by the EThread's existing `IOUringContext`, with **no new
thread and no new event loop**. Keep the `NetVConnection` `do_io_*` + `Continuation`
facade so callers are unaffected.

## Phase 1 — minimal coroutine io_uring runtime in-tree (do this first)

1. Add a small coroutine runtime under `include/iocore/io_uring/` (header-only is
   fine), gated by `#if TS_USE_LINUX_IO_URING`:
   - A `Task<T>` / `DetachedTask` coroutine type (port from `reactor.h`, adapting
     ownership; eager-start fire-and-forget plus an owned variant).
   - A `UringOp` awaitable that **is** an `IOUringCompletionHandler`, submits via
     `IOUringContext::local_context()->next_sqe(this)` + a caller-supplied
     `io_uring_prep_*`, and resumes the awaiting coroutine in `handle_complete`
     with `cqe->res`. Start from the sketch in `ATS-INTEGRATION.md`.
   - A `UringCancel` helper that submits `io_uring_prep_cancel` so a connection can
     drain an in-flight op before teardown (cancel-then-unwind, as the prototype
     does).
2. Add a unit test under `src/iocore/io_uring/unit_tests/` modeled on the existing
   `test_diskIO.cc` (same Catch2 harness + `IOUringContext` driving). Exercise a
   coroutine that does `recv`/`send` over an `AF_UNIX` socketpair (or a file
   read/write), pumped by a hand-rolled loop calling `local_context()->submit()` /
   `service()` exactly like `waitForActivity`. Assert correctness and that the
   coroutine frame is reclaimed (no leak).
3. Wire the test into the io_uring CMake (`src/iocore/io_uring/CMakeLists.txt`),
   matching how `test_diskIO` is registered.

**Acceptance for Phase 1:** with `-DUSE_IOURING=1`, the new unit test builds and
passes; it demonstrates a coroutine suspended on a real `IOUringContext` op and
resumed from `service()`. No changes to the net path yet.

## Phase 2 — convert ONE leaf of the net io_uring path

Bring the `net-iouring` branch's `IOUringNetVConnection` onto the current tree
(it predates the `include/iocore` reorg, so expect to relocate files and fix
includes), then convert a single direction — start with the **read** path:

1. Replace `IOUringReader` + `prep_read` + the `ops_in_flight` bookkeeping for
   reads with a coroutine `read loop` driven by `UringOp` (using
   `io_uring_prep_recvmsg`/`recv`). Keep `do_io_read` + the VIO/`Continuation`
   signalling identical from the caller's perspective.
2. Apply the prototype's lifetime rule: the read buffer/iovec lives in the
   coroutine frame across the await (deletes the class-scope `msghdr` hack).
3. Implement `do_io_close` as cancel-then-await (`UringCancel` + co_await the
   `-ECANCELED`) instead of the branch's `delete this` (which is a known UAF —
   see the review in this repo's history / README).
4. Leave the **write** path on the old mechanism for now (mixed is fine); this
   keeps the diff reviewable and isolates the read conversion.

**Acceptance for Phase 2:** ATS builds with `-DUSE_IOURING=1`; a focused autest or
unit test drives an inbound connection whose reads go through the coroutine path
and verifies correct data + clean close (no UAF under ASan). Document what you ran.

## Build & test (real ATS — you have the full toolchain)

```sh
# configure with io_uring on; the 'dev' preset is a good base
cmake --preset dev -DUSE_IOURING=1
cmake --build build/dev -j

# io_uring unit tests
ctest --test-dir build/dev -R io_uring --output-on-failure

# ASan variant for the close/UAF check
cmake --preset dev-asan -DUSE_IOURING=1 && cmake --build build/dev-asan -j
```

Useful presets: `dev`, `dev-asan`, `asan`, `autest`. io_uring requires
`liburing-dev` and a recent kernel (5.19+ for `io_uring_prep_cancel`/async-cancel).

## Constraints & conventions

- **C++20** (the tree already sets `CMAKE_CXX_STANDARD 20`). Coroutines are in.
- Everything new is gated by `#if TS_USE_LINUX_IO_URING`; the default (non-io_uring)
  build must be untouched and must still compile.
- Run `clang-format` (repo `.clang-format`) on everything you touch; CI lints it.
- Reuse the existing `IOUringContext` — do not add a second ring, thread, or loop.
- Preserve thread confinement: a VC's coroutine is only ever resumed on its owning
  EThread (this is automatic — the ring is `thread_local`, so its CQEs drain on the
  submitting thread inside that thread's `waitForActivity`). Do **not** add a
  per-VC mutex.
- Keep diffs small and reviewable: Phase 1 is self-contained; Phase 2 converts one
  direction only. Don't boil the ocean (no TLS, UDP, timeouts, migration in this
  pass — those are later).
- Commit in logical steps with clear messages; keep the standalone prototype under
  `experiments/coro-net-prototype/` as the reference (don't delete it).

## Definition of done for this task

1. Phase 1 runtime + unit test merged and green under `-DUSE_IOURING=1`.
2. Phase 2 read-path conversion building and verified (data correctness + clean
   close under ASan), with a short note in `experiments/coro-net-prototype/` (or a
   new `doc/`) recording what changed, what was tested, and the next leaf to
   convert (the write path, then accept/connect, then close fully).

Work incrementally, verify at each step, and prefer a small proven slice over a
large unproven one.
