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
`Reactor::resume()` is the single chokepoint where, in real ATS, you would
confirm you're on the owning `EThread` and take the VConnection's mutex before
re-entering its code. Today both branches duplicate that lock/affinity dance in
every completion handler; here it is written once.

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
./build/coro_net uring     # requires liburing + a recent kernel
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

## What this spike deliberately leaves out

It is an architecture probe, not a net stack. Out of scope (and exactly the work
a real effort would tackle next): the multi-threaded EThread-affine resume +
per-VC mutex behind Seam 2; TLS/`SSLNetVConnection`; timeouts (which map cleanly
to `IORING_OP_TIMEOUT` / linked timeouts); MIOBuffer instead of flat buffers;
SQ-full backpressure as a suspending await rather than `-EAGAIN`; a pooled
coroutine-frame allocator; UDP; connection tracking. The point here is only to
make the **boundaries** concrete enough to argue about.
