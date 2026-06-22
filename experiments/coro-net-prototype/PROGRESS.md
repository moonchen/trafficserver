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

## Phase 2B — swap the read path to io_uring recvmsg — DONE (bounded first cut)

The seam was `net_read_io` (a synchronous `con.sock.recvmsg`, triggered by epoll
readiness). `IOUringNetVConnection` now overrides it to submit an asynchronous
recvmsg via the coroutine runtime; the completion (drained by
`IOUringContext::service()` on the owning EThread) fills the buffer and signals
the read VIO. What landed (`src/iocore/net/IOUringNetVConnection.{cc,h}`, 3
commits):

- **Bounded first cut: keep the epoll-readiness trigger**, only async-ify the
  recvmsg. Reuses the inherited enable/backpressure/reenable machinery and the
  write path unchanged.
- **Edge-triggered drain loop.** The net poll set is `EPOLLIN | EPOLLET`, so the
  read coroutine drains the socket per trigger (loops recvmsg until a short read,
  a full buffer, or the VIO is satisfied). A single read per trigger stalls — the
  load test caught exactly this (curl error 18 + 30 s hang) before the fix.
- **VIO mutex post-completion.** The mutex is taken only after the recv resumes;
  thread-confinement keeps it uncontended. The buffer/msghdr/iovec live in the
  coroutine frame, pinned across the await.
- **Teardown = cancel-then-unwind.** `do_io_close` with a recv in flight cancels
  the op and defers the free to the resuming coroutine (which frees once no op is
  in flight); the `read_signal_*`/recursion contract (reimplemented, since the
  base helpers are file-static) handles a close fired from inside a read signal.
- **Resolver-macro fix.** `UringOp::_res` → `_result` (glibc `<resolv.h>` defines
  `_res`, pulled in via the net layer's `ink_sock.h`).

**Verified:** `io_uring_netvc` (basic) and `io_uring_read` (256 KB drain loop +
`wrk -t4 -c64 -d15s` load) both pass on Debug **and ASan** with zero ASan errors.
Load: ~1.75 M requests / 418 GB in 15 s, 0 socket errors, 0 non-2xx — the read
and close paths are clean under heavy connection churn.

**TSan:** the Phase-1 unit test is clean; under the load test TSan reports only
pre-existing shared-infra races (lock-free freelist accounting, `ProxyMutex`
trylock accounting, `CacheVC`, hdrs print, logging) — the exact classes the TLS
campaign established as benign on master. Triaged by the racing access (frame
#0/#1): **none are in io_uring code**; `IOUringNetVConnection`/`_read`/
`handle_complete` appear only as call-stack *context* driving those infra races.
The thread-confined model (one ring per EThread, completion resumes on the
submitting thread, no per-VC mutex) holds. Added `race:ink_freelist_free` to
`.tsan_suppressions` (free-side counterpart of the existing `freelist_new`;
surfaced more because the io_uring VC frees to a global allocator — see D7).
Recipe: `sudo sysctl vm.mmap_rnd_bits=28`, build with `-fsanitize=thread`
(WARNING_AS_ERROR=OFF — a plugin uses `atomic_thread_fence`, unsupported under
GCC TSan), run autests against the TSan install with
`TSAN_OPTIONS=suppressions=.tsan_suppressions`.

**Known limits of the first cut (later work):** relies on thread-confinement for
the post-await mutex (no fallback if contended); SQ-full on the cancel SQE is not
retried; per-read coroutine-frame heap alloc (no pool); the deferred-close path
is exercised incidentally by churn, not yet by a targeted close-with-recv-in-
flight test (e.g. an inactivity timeout while a keep-alive read is armed).

## Later leaves (after 2B), in order

Write path (`load_buffer_and_write` → io_uring `sendmsg`) → `do_io_close` fully
on cancel-then-unwind → accept/connect → then the bigger items the spike left
out: TLS (via the layered SSLNetVConnection once that refactor lands), timeouts
via `IORING_OP_TIMEOUT`, SQ-full backpressure as a suspending await, migration.

Each leaf keeps the `do_io_*` + `Continuation`/VIO facade identical to callers
and is guarded by the Phase-2A autest plus any leaf-specific test.
