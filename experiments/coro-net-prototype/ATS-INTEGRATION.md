# Driving the coroutine reactor inside ATS

This note answers: *how would the prototype's coroutine layer actually run inside
Apache Traffic Server, rather than against the toy `Reactor` in this directory?*

The short answer: **you don't add a reactor — ATS already has one, and it already
pumps a per-thread io_uring ring.** The disk-AIO io_uring work merged on `master`
(originally #8992) gives you, on every `ET_NET` thread, exactly the three things
the prototype's `Reactor` + `IBackend` provide. Driving coroutines is a matter of
writing an awaitable that plugs into that existing machinery.

## What master already has

All references are `origin/master`.

### A per-thread io_uring context
`include/iocore/io_uring/IO_URING.h`:

```cpp
class IOUringCompletionHandler {
public:
  virtual void handle_complete(io_uring_cqe *) = 0;     // the completion contract
};

class IOUringContext {
  io_uring_sqe *next_sqe(IOUringCompletionHandler *handler) {  // get SQE, user_data=handler
    io_uring_sqe *sqe = io_uring_get_sqe(&ring);
    if (sqe == nullptr) { submit(); sqe = io_uring_get_sqe(&ring); }  // auto-flush a full ring
    if (sqe) io_uring_sqe_set_data(sqe, handler);
    return sqe;
  }
  void submit();
  void service();                 // drain all CQEs -> handler->handle_complete(cqe)
  void submit_and_wait(ink_hrtime ms);
  int  register_eventfd();
  static IOUringContext *local_context();   // thread_local: one ring per thread
};
```

`src/iocore/io_uring/io_uring.cc`:

```cpp
IOUringContext &IOUringContext::local_context() { thread_local IOUringContext c; return c; }

void IOUringContext::service() {                 // called every net-loop iteration
  io_uring_cqe *cqe = nullptr;
  io_uring_peek_cqe(&ring, &cqe);
  while (cqe) { handle_cqe(cqe); io_uring_cqe_seen(&ring, cqe); io_uring_peek_cqe(&ring, &cqe); }
}
void IOUringContext::handle_cqe(io_uring_cqe *cqe) {
  auto *op = reinterpret_cast<IOUringCompletionHandler *>(io_uring_cqe_get_data(cqe));
  op->handle_complete(cqe);                       // <-- dispatch on user_data
}
```

### An eventfd bridge so io_uring completions wake the epoll loop
`src/iocore/io_uring/IOUringEventIO.cc`:

```cpp
int  IOUringEventIO::start(EventLoop l, IOUringContext *h) {
  _h = h; return start_common(l, _h->register_eventfd(), EVENTIO_READ);
}
void IOUringEventIO::process_event(int) { _h->service(); }   // CQE-ready -> drain
```

Registered once per net thread in `src/iocore/net/UnixNet.cc` (`initialize_thread_for_net`):

```cpp
#if TS_USE_LINUX_IO_URING
  auto ep = new IOUringEventIO();
  ep->start(pd, IOUringContext::local_context());
#endif
```

### The pump: the net thread's tail handler
`src/iocore/net/NetHandler.cc`, `NetHandler::waitForActivity` (runs every EThread loop iteration):

```cpp
SCOPED_MUTEX_LOCK(lock, mutex, this->thread);     // (A) runs under the NetHandler mutex
process_enabled_list();
#if TS_USE_LINUX_IO_URING
  ur->submit();                                   // (B) flush queued SQEs once
#endif
p->do_poll(timeout);                              // (C) epoll_wait
for (each ready fd) epd->process_event(flags);    // (D) incl. IOUringEventIO -> service()
process_ready_list();
#if TS_USE_LINUX_IO_URING
  ur->service();                                  // (E) drain remaining CQEs at the tail
#endif
```

## The mapping: prototype -> ATS

| prototype (this dir)                | ATS construct (master)                                   |
|-------------------------------------|----------------------------------------------------------|
| `Reactor` (the loop)                | `EThread` + `NetHandler::waitForActivity` — **exists**   |
| `IBackend` (io_uring)               | `IOUringContext` (per-thread, `local_context()`) — exists|
| `IBackend::submit`                  | `IOUringContext::next_sqe(handler)` + `io_uring_prep_*`   |
| `IBackend::poll` -> completed ops   | `IOUringContext::service()` (already called in the loop)  |
| `IoOp.waiter` (coroutine handle)    | `IOUringCompletionHandler*` stored as SQE `user_data`     |
| `Reactor::resume(op->waiter)`       | `handle_complete(cqe)` -> `coroutine_handle.resume()`     |
| per-thread ring => free affinity    | `local_context()` is `thread_local` — same property       |
| `Reactor::resume_soon` (non-IO wake)| `EThread::schedule_imm_local` / the enabled list          |
| wakeup pipe (`post_remote`)         | `thread->evfd` + `signalActivity()` — exists              |

So the prototype's two seams collapse onto things ATS already runs: **Seam 1 is
`IOUringContext`; Seam 2 is `service()` calling `handle_complete` inside
`waitForActivity` on the owning EThread.**

## The adapter (illustrative — compiles against ATS, not this prototype)

A single awaitable is all that's needed. It *is* an `IOUringCompletionHandler`,
so the existing `service()` resumes it:

```cpp
#include "iocore/io_uring/IO_URING.h"
#include <coroutine>
#include <functional>

// One in-flight io_uring socket op, driven by THIS EThread's ring. No new thread,
// no new loop: the completion is delivered by the ur->service() call already in
// NetHandler::waitForActivity.
class UringOp : public IOUringCompletionHandler {
public:
  template <class Prep>                          // Prep fills the SQE
  explicit UringOp(Prep prep) : _prep(std::move(prep)) {}

  bool await_ready() const noexcept { return false; }

  void await_suspend(std::coroutine_handle<> h) {
    _waiter = h;
    io_uring_sqe *sqe = IOUringContext::local_context()->next_sqe(this); // user_data = this
    _prep(sqe);                                  // io_uring_prep_recv / _send / _accept ...
    // No submit() here: waitForActivity() flushes once per loop (step B).
  }

  int await_resume() const noexcept { return _res; }   // bytes, or -errno

  void handle_complete(io_uring_cqe *cqe) override {    // called by service(), on this EThread
    _res = cqe->res;
    _waiter.resume();                            // already on the owning thread, under the NH mutex
  }

private:
  std::function<void(io_uring_sqe *)> _prep;
  std::coroutine_handle<>             _waiter;
  int                                 _res = 0;
};
```

Usage reads like the prototype's `AsyncSocket`:

```cpp
ts::Task echo(int fd) {
  char buf[32 * 1024];
  for (;;) {
    int n = co_await UringOp([&](io_uring_sqe *s){ io_uring_prep_recv(s, fd, buf, sizeof buf, 0); });
    if (n <= 0) break;
    co_await UringOp([&](io_uring_sqe *s){ io_uring_prep_send(s, fd, buf, n, MSG_NOSIGNAL); });
  }
}
```

`UringOp` and `buf` live in the coroutine frame across the suspend, so they
outlive the in-flight SQE — the same structural lifetime guarantee the prototype
relies on, and the exact bug (`msghdr`/`iovec` hoisted to class scope) that the
`net-iouring` branch hit by hand.

## Consequences and caveats

1. **No separate reactor or thread.** The EThread loop is the reactor; you ride
   `waitForActivity`. The prototype's `Reactor` is a stand-in for it.

2. **Affinity is already correct.** `local_context()` is `thread_local`, so a CQE
   is drained on the same EThread that submitted it — resume lands on the owning
   thread for free. This is the prototype's "per-thread ring => free affinity",
   already true in ATS.

3. **Resumes run under the NetHandler mutex** (step A) on the EThread. That is the
   locking context a resumed coroutine body inherits. In a thread-confined
   coroutine design you can drop the per-`NetVConnection` mutex entirely (see the
   main README's Seam-2 discussion); the EThread confinement does the work.

4. **Submit is batched for you.** Awaitables just `next_sqe` + `prep`; the single
   `ur->submit()` per loop (step B) flushes them, and `next_sqe` auto-flushes a
   full ring. No per-op submit syscall.

5. **Close needs a cancel.** Safe teardown submits `io_uring_prep_cancel` via
   `next_sqe` (with a tiny handler) and `co_await`s the original op's `-ECANCELED`
   — exactly the prototype's cancel-then-unwind, using the same context.

6. **Sockets are still epoll on master.** Upstream io_uring is disk-AIO only; the
   net path uses epoll. To drive a coroutine *net* layer you add socket ops
   (recv/send/accept/connect/cancel) to the same per-thread context. That is
   precisely what the fork's `net-iouring` branch did — but with hand-written
   `IOUringReader` / `IOUringWriter` (`IOUringCompletionHandler`s carrying a manual
   `ops_in_flight` counter and class-scope `msghdr`). The coroutine approach
   **replaces those handler-objects-plus-state with one `UringOp` awaitable per
   suspend**, and the state machine becomes the coroutine body.

7. **Two drive modes already exist.** The net thread uses the *bridged* mode
   (epoll waits; the io_uring eventfd wakes it; `service()` drains). A dedicated
   io_uring thread could instead use the *pure* mode, `submit_and_wait(ms)`, which
   blocks directly on the ring. Both are in `IOUringContext`; coroutines work over
   either.

## Suggested next step

Port `UringOp` (above) plus a minimal `Task` into the ATS tree behind
`TS_USE_LINUX_IO_URING`, and rewrite one leaf of `IOUringNetVConnection`'s
read/write path (from the `net-iouring` branch) as a coroutine driven by the
existing `local_context()` — no new threads, reusing `waitForActivity`'s
`submit()`/`service()`. That is the smallest change that proves the coroutine
model on real ATS plumbing.
