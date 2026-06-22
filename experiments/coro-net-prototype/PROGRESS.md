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
retried; per-episode coroutine-frame heap alloc (no pool); the deferred-close
path is exercised incidentally by churn, not yet by a targeted
close-with-op-in-flight test (e.g. an inactivity timeout while a keep-alive read
is armed).

## Phase 2C — swap the write path to io_uring sendmsg — DONE

`net_write_io` now launches a `_write` coroutine (symmetric to `_read`):
`io_uring_prep_sendmsg`, per-writable-edge drain loop, demand-driven
`WRITE_READY` before sending (INV-W1), iovec built from a *clone* of the reader
so bytes are consumed only after the send completes. Teardown generalized to
both directions: `do_io_close` cancels whichever of recvmsg/sendmsg is in flight
and defers the free until neither remains (`_complete_deferred_close`); the
signal-unwind free is gated the same way (INV-L2). Write still selected by the
same `proxy.config.net.io_uring.enabled`.

While converting writes, found + fixed a latent **edge-trigger latch** bug
(INV-R3 / decision D20): `net_*_io` must not clear `triggered` (it is the
reenable re-drive mechanism under EPOLLET); clear it only on the drained paths
(EAGAIN / short read / short send) inside the coroutine. The write path exposed
it (a body never re-armed after the consumer drained); the read path had the
same latent bug, fixed too.

**Verified (read + write):** `io_uring_netvc` + `io_uring_read` (256 KB drain +
`wrk` load) pass on Debug, ASan (0 errors), and TSan (no race with its racing
access in io_uring code; bodies delivered intact under all three). The response
body now flows through io_uring sendmsg.

## Phase 2D — drop epoll, fully completion-driven — DONE

`ep.syscall = false` so the fd is never registered with epoll (verified at
runtime `ep.syscall == 0`); io_uring completions need no readiness signal.
`reenable`/`reenable_re` mark `triggered = 1` (always armable) and delegate, so
the existing ready/enable-list machinery drives the coroutines with no epoll
edge. This deletes the hybrid epoll-trigger model and the edge-trigger-latch bug
class (INV-R3 no longer applies; see D22). Timeouts unaffected (cop uses its own
queues). Verified Debug + ASan (0 errors) + TSan (0 races in io_uring code) on
both autests incl. the wrk load.

## Phase 2F — io_uring-native connect — DONE (fixes D24)

`connectUp` overridden to connect with `io_uring_prep_connect` + an
`IORING_OP_LINK_TIMEOUT` instead of a `connect(2)` syscall; `NET_EVENT_OPEN` on
the success CQE (so it means the handshake is *actually* done), `NET_EVENT_OPEN_FAILED`
on failure/timeout. This fixed D24 (a black-holed origin connect returned 000 /
hung 30s under io_uring because the optimistic syscall-connect made the
`ConnectingEntry` write-ready probe fire before the handshake; see D24/D26). Now
502 in ~2s, matching epoll. Verified Debug + ASan + TSan (success / refused /
timeout). The connect op resolves before `_connect` handles it, so no in-flight
op at the resulting free.

## Phase 2G — io_uring accept — DONE

`IOUringNetAccept` (NetAccept subclass + IOUringCompletionHandler) accepts with
`io_uring_prep_accept` per ET_NET thread (single-shot + throttle-gated re-arm),
so the accepted VC stays thread-local — no cross-thread hand-off. Selected by
`createNetAccept` when `io_uring.enabled`, forcing the per-thread accept path.
Single-shot (not multishot) so `check_net_throttle(ACCEPT)` is honored each
accept. Verified Debug + ASan + TSan incl. the wrk load (64 conns). See D27.

With this, the whole inbound+outbound socket lifecycle — accept, connect, read,
write, close — runs on io_uring with no epoll for the io_uring VC.

## D25 — defer the free when an op is in flight — FIXED (TDD)

`free_thread` (reached by the inactivity/active-timeout close via the inherited
`mainEvent` → base signal → `free_netevent`, bypassing `do_io_close`) freed the VC
with a recvmsg in flight → the cancelled recv resumed into a freed VC. Reproduced
deterministically (`io_uring_origin_timeout`: origin accepts + hangs → recv in
flight at the inactivity timeout), surfaced via `-F` + ASan (freelist off, so ASan
sees the VC free) plus a transient free-time assert. Fix: `free_thread` defers like
`do_io_close` (cancel + return; the resuming coroutine frees). No-op path
unchanged. Verified: `-F`+ASan UAF without the fix, clean with it, no load-test
regression. See D28.

## Later leaves, in order

(1) **Multishot read** on a provided/ring buffer (deferred — hard to reconcile
provided-buffer lifetime with MIOBuffer; single-shot stays for now). Then the
bigger items: TLS (layered SSLNetVConnection),
timeouts via `IORING_OP_TIMEOUT`, a pooled coroutine-frame allocator, migration.

Each leaf keeps the `do_io_*` + `Continuation`/VIO facade identical to callers
and is guarded by the Phase-2A autest plus any leaf-specific test, and is
verified under ASan + TSan.
