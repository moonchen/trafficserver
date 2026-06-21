# coro-net: a coroutine networking spike

A small, self-contained, **runnable** prototype that explores what a C++20
coroutine-based networking layer for Traffic Server could look like — and, more
importantly, where the **boundaries** between the pieces fall. It is deliberately
*not* wired into the ATS build; it is an architecture spike you can read in one
sitting and run in two seconds.

It grew out of a comparison of two earlier WIP branches:

| branch | idea | engine | how completions surface |
|---|---|---|---|
| `async-net` / `tcp-net-processor` | abstract the socket into an async-socket layer (`NetAIO`) | **epoll only** | `TCPConnectionObserver` callbacks |
| `net-iouring` | port the existing VConnection onto io_uring | **io_uring only** | `IOUringCompletionHandler::handle_complete(cqe)` |

Both hand-rolled a suspendable state machine over completions, and both botched
object teardown in opposite ways (async-net leaked VCs; net-iouring `delete this`'d
with ops still in the kernel — a use-after-free). This spike asks: if you let the
*language* provide the state machine (coroutines) and pick the engine behind a
single interface, what do the seams look like?

## The three seams

```
        ┌─────────────────────────────────────────────────────────────┐
        │  application: HttpSM-style code                              │
        │     vc->do_io_read(...) / do_io_write(...) / do_io_close()   │
        └─────────────────────────────────────────────────────────────┘
                                   │   SEAM 3  (coro_netvc.h)
                                   │   classic NetVConnection + Continuation
                                   │   facade, driven by ONE coroutine
        ┌─────────────────────────────────────────────────────────────┐
        │  CoroNetVConnection::drive()  — a single linear coroutine    │
        │     n = co_await sock.recv(buf); ... co_await sock.send(...) │
        └─────────────────────────────────────────────────────────────┘
                                   │   SEAM 2  (reactor.h)
                                   │   Reactor::resume() — the ONE place
                                   │   EThread-affinity + VC mutex would live
        ┌─────────────────────────────────────────────────────────────┐
        │  AsyncSocket awaitables  (async_socket.h)                    │
        │     submit IoOp on suspend, return result on resume          │
        └─────────────────────────────────────────────────────────────┘
                                   │   SEAM 1  (io_backend.h)
                                   │   IBackend: submit / cancel / poll(IoOp*)
                                   │   knows NOTHING about coroutines or VCs
        ┌──────────────────────────────┬──────────────────────────────┐
        │  EpollBackend                │  UringBackend                 │
        │  (readiness → do syscall)    │  (SQE → kernel → CQE)         │
        └──────────────────────────────┴──────────────────────────────┘
```

### Seam 1 — backend boundary (`io_backend.h`, `epoll_backend.*`, `uring_backend.*`)
The engine understands exactly one type, `IoOp`, and exposes three calls:
`submit`, `cancel`, `poll`. It never calls up into the net layer (contrast the
WIP branches, where the backend dispatched directly into VConnection code via a
virtual `handle_complete`/observer). Swapping epoll for io_uring changes nothing
above this line — the demo runs identical upper-layer code on both, selected by a
command-line argument.

### Seam 2 — coroutine / thread-affinity boundary (`reactor.h`)
The backend only *detects* completion; the reactor decides what resuming means.
`Reactor::resume()` is the single chokepoint where coroutine bodies are
re-entered. The multi-threaded model (see below) makes this a plain thread-local
call — **no per-VC mutex** — because each connection is confined to one thread.

### Seam 3 — NetVConnection boundary (`coro_netvc.*`)
`CoroNetVConnection` keeps the sacred `do_io_read` / `do_io_write` /
`do_io_close` + `Continuation` facade that the rest of ATS depends on — but
underneath, the entire read/write lifecycle is one coroutine, `drive()`, instead
of an `op_state`/`connect_state` machine (async-net) or `IOUringReader`/`Writer`
completion objects with a manual `ops_in_flight` counter (net-iouring).

## What the spike actually demonstrates

1. **One interface, two engines.** `./coro_net epoll` and `./coro_net uring`
   exercise byte-for-byte identical coroutine + VConnection code.
2. **Buffer lifetime is structural.** The `IoOp` and its buffer live in the
   awaiting coroutine frame, pinned across the suspension point. No class-scope
   hoisting (net-iouring's crash fix), no per-I/O `unique_ptr<msghdr>` heap churn
   (async-net).
3. **Safe teardown, no UAF.** `do_io_close()` is not `delete this`. It issues a
   real cancel (`IORING_OP_ASYNC_CANCEL` on the io_uring side); the in-flight op
   completes with `-ECANCELED`; the coroutine resumes, sees it's closing, and
   unwinds as ordinary straight-line code. The VC is freed only after the
   coroutine has fully unwound. Verified clean under ASan + UBSan on both engines.
4. **Two resume sources, one path.** I/O completions (backend) and API calls
   (`do_io_read` waking a parked driver) both funnel through `Reactor::resume*`.

## Build & run

```sh
cd experiments/coro-net-prototype
cmake -B build && cmake --build build
./build/coro_net epoll
./build/coro_net uring        # requires liburing + a recent kernel
./build/coro_net_mt uring     # the multi-threaded / migration demo (see below)
```

Or directly:

```sh
g++ -std=c++20 -DHAVE_LIBURING main.cc epoll_backend.cc uring_backend.cc coro_netvc.cc -luring -o coro_net
```

Expected (abridged): clientA's echo round-trips and verifies; the idle clientB's
server-side VC is closed while its `recv` is in flight, and you can watch the
cancel → unwind → free sequence in the log:

```
== coro-net prototype, backend = io_uring ==
    [VC 1] do_io_close(): cancelling any in-flight op, then unwinding
    [VC 1] drive() unwound; closing socket asynchronously
    [VC 1] finalize(): VC freed (no op was left dangling)
  ✓ cancelled-on-close VC freed (no UAF) (3/3)
== done (3/3 checks passed) ==
```

## Multi-threaded: the EThread-affinity model (`coro_net_mt`)

The second executable takes the ATS net-thread model seriously and answers the
obvious question: *with coroutines, where does the per-VConnection mutex go?*

**Short answer: it goes away.** ATS puts a `ProxyMutex` on every VConnection
because its event system is *general* — any `Continuation` can be scheduled onto
any thread, so `MUTEX_TRY_LOCK` is the universal serialization primitive. But net
VConnections are, in practice, **thread-confined**: a VC lives on one `ET_NET`
thread, and even the origin connection is *migrated* onto the client connection's
thread for the global session pool. If you make that confinement an explicit,
enforced invariant, the resume path needs no lock at all — it would only ever be
taken uncontended. The per-VC mutex's real job is instead handled by **explicit
synchronized hand-offs**: the few legitimate cross-thread events go through a
small number of synchronized channels — `Reactor::post_remote()` (accept
hand-off) and a session-pool mutex (migration) — never a lock on the VC itself.

So the multi-threaded design is:

- **N worker reactors, one per OS thread, each with its own backend** (its own
  io_uring ring / epoll set). A connection is confined to one worker for its
  lifetime. Because each thread submits to its own ring, completions are always
  drained on the owner thread: **I/O-completion affinity is free**, no cross-thread
  resume on the hot path.
- **Accept hand-off** (`acceptor → worker`) is a `post_remote` of the new fd —
  the one necessary cross-thread step to place a connection on a worker.
- **Migration** is **synchronous and destination-pulled**, mirroring ATS's
  `UnixNetVConnection::migrateToCurrentThread` (which is called by the thread that
  wants the session and returns the re-homed VC). A connection that finishes a
  transaction is `park_and_release`'d into a session pool — **bare, with no armed
  io_uring op**. A *different* worker later pulls it from the pool and calls
  `vc->migrate_here(*self)` on its own reactor: a synchronous adopt, **no callback,
  no cross-thread message**. The pool's mutex supplies the happens-before edge,
  exactly as ATS leans on the session-pool lock.

  Why pulled-and-bare rather than pushed? epoll's `migrateToCurrentThread` can
  yank the fd off the source thread's poll set from the destination (`ep.stop()`,
  an `epoll_ctl` that is thread-safe). io_uring has **no thread-movable
  registration** — an armed SQE lives on the source ring and can only be cancelled
  by the source thread — so we require quiescence (a pooled connection holds no
  op) and let the destination adopt the bare fd onto its own ring. Same
  synchronous API as ATS; the only new constraint is "don't keep an op armed on a
  pooled connection."

`coro_net_mt` runs 3 workers + an acceptor + a client driver, echoes over 4
connections (2 transactions each), and migrates one connection between workers
between its two transactions. The log shows the pull:

```
  acceptor(reactor 0): handed conn 0 to worker reactor 1 (will be pooled + migrated)
    [VC 0 @reactor 1] park_and_release(): parking bare (no armed op), awaiting a pull
    [VC 0 @reactor 2] migrate_here(): adopted synchronously (destination-pulled)
== done: clients 4/4, server VCs freed 4/4 ==
```

**Verified race-free under ThreadSanitizer** (both engines, 10× repeat) and clean
under ASan/UBSan — with zero per-VC locks. The two synchronized cross-thread
channels are the `post_remote` queue (accept hand-off) and the session-pool mutex
(migration). The park-then-publish ordering in `ParkAndRelease` is what keeps the
pool hand-off race-free: the coroutine's resume handle is stored *before* the VC
becomes visible in the pool, so the adopting thread's later `do_io_read` always
finds it.

## Test matrix

Correctness here depends on *which* engine and *which* sanitizer you run under,
so testing is a grid, not a single command. The machinery makes the grid
first-class.

- **Backends** are swept automatically. Each test executable takes the backend
  (`epoll` / `uring`) as `argv[1]`; CTest registers one test per available
  backend. io_uring tests appear wherever liburing is found and are simply absent
  where it is not — you never name backends by hand.
- **Sanitizers** are a build-level axis: `-DSANITIZER=none|asan|tsan`. Each variant
  knows how to fail a test (a regex over the output: `ThreadSanitizer`,
  `AddressSanitizer`, `runtime error`, …) and sets the env that makes the
  sanitizer abort on error.

Sweep everything in one shot:

```sh
./run-matrix.sh                 # {none,asan,tsan} x {epoll,uring}, prints a summary
./run-matrix.sh --repeat 20     # run each test up to 20x — race hunting under TSan
./run-matrix.sh --sanitizers none,tsan
./run-matrix.sh -L backend=uring        # pass-through ctest label filter
```

Or drive one configuration directly:

```sh
cmake -B build-tsan -DSANITIZER=tsan && cmake --build build-tsan
ctest --test-dir build-tsan --output-on-failure
```

Adding a future test is **one line** in `CMakeLists.txt` — it is then run across
the whole backend × sanitizer grid for free:

```cmake
coro_add_matrix_test(<target> "<success-marker-regex>")
```

The current grid is `{none, asan, tsan} × {coro_net, coro_net_mt} × {epoll, uring}`
= 12 invocations, all green. (The harness is self-checked: breaking a success
marker fails the run, and an injected cross-thread resume is caught under TSan.)

## Driving this inside ATS

The toy `Reactor` here stands in for an ATS `ET_NET` thread. ATS already runs the
exact machinery a coroutine pump needs — a `thread_local` io_uring ring per net
thread (`IOUringContext`, from the merged disk-AIO work), drained every loop
iteration by `NetHandler::waitForActivity`. See **[ATS-INTEGRATION.md](ATS-INTEGRATION.md)**
for the precise prototype→ATS mapping and a concrete `UringOp` awaitable that
plugs a coroutine into the existing `IOUringContext::service()` dispatch — no new
thread, no new loop.

## What this spike deliberately leaves out

It is an architecture probe, not a net stack. Out of scope (and exactly the work
a real effort would tackle next): TLS/`SSLNetVConnection`; timeouts (which map
cleanly to `IORING_OP_TIMEOUT` / linked timeouts); MIOBuffer instead of flat
buffers; SQ-full backpressure as a suspending await rather than `-EAGAIN`; a
pooled coroutine-frame allocator; UDP; connection tracking; and mid-stream (not
just between-transaction) migration. The point here is only to make the
**boundaries** concrete enough to argue about.
