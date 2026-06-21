/** @file
 *
 *  SEAM 3 — the NetVConnection boundary.
 *
 *  Everything above this line in real ATS (HttpSM, protocol state machines,
 *  session management) talks to a NetVConnection through do_io_read /
 *  do_io_write / do_io_close and gets called back via a Continuation with
 *  VC_EVENT_* events. That contract is sacred — thousands of lines depend on it.
 *
 *  This class keeps that exact facade, but instead of a hand-written op_state /
 *  connect_state machine (async-net) or IOUringReader/IOUringWriter completion
 *  objects with a manual ops_in_flight counter (net-iouring), the entire read/
 *  write lifecycle is a single linear coroutine, drive(). do_io_read/do_io_write
 *  just hand a VIO to that coroutine and wake it; do_io_close cancels whatever
 *  the coroutine is awaiting and lets it unwind.
 *
 *  The payoff is concentrated in two places:
 *    1. Buffers handed to the kernel live in the coroutine frame across the
 *       await, so the "buffer must outlive the in-flight op" rule that bit
 *       net-iouring is satisfied structurally.
 *    2. do_io_close() is *not* `delete this`. It requests cancellation; the
 *       in-flight op completes with -ECANCELED; the coroutine resumes, sees it
 *       is closing, and runs its cleanup as ordinary straight-line code. The VC
 *       is freed only after the coroutine has fully unwound — no use-after-free.
 */
#pragma once

#include "async_socket.h"
#include "reactor.h"

#include <coroutine>
#include <cstdint>
#include <functional>

namespace coronet
{

// A minimal stand-in for ATS VC_EVENT_*.
enum VcEvent {
  VC_READ_READY    = 1,
  VC_READ_COMPLETE = 2,
  VC_WRITE_COMPLETE = 3,
  VC_EOS           = 4,
  VC_ERROR         = 5,
};

using Continuation = std::function<void(int event)>;

// An internal one-shot awaitable used to park drive() when it has no VIO work,
// and to wake it when do_io_read/do_io_write/do_io_close arrive. This is the
// second resume source besides the backend: API calls, not I/O completions,
// both routed through Reactor::resume*.
class Event
{
public:
  explicit Event(Reactor &r) : _r(r) {}

  bool await_ready() const noexcept { return _signaled; }
  void await_suspend(std::coroutine_handle<> h) noexcept { _waiter = h; }
  void await_resume() noexcept { _signaled = false; }

  void
  notify()
  {
    if (_waiter) {
      auto h   = _waiter;
      _waiter  = {};
      _r.resume_soon(h);
    } else {
      _signaled = true;
    }
  }

private:
  Reactor                &_r;
  std::coroutine_handle<> _waiter{};
  bool                    _signaled{false};
};

class CoroNetVConnection
{
public:
  CoroNetVConnection(Reactor &r, int fd, int id, std::function<void()> on_freed = {});

  CoroNetVConnection(const CoroNetVConnection &)            = delete;
  CoroNetVConnection &operator=(const CoroNetVConnection &) = delete;

  // The NetVConnection facade.
  void do_io_read(void *buf, size_t len, Continuation cont);
  void do_io_write(const void *buf, size_t len, Continuation cont);
  void do_io_close();

  size_t read_done() const { return _read.done; }
  int    id() const { return _id; }

private:
  struct VIO {
    enum Kind { NONE, READ, WRITE } kind{NONE};
    uint8_t *base{nullptr};
    size_t   len{0};
    size_t   done{0};
    bool     active() const { return kind != NONE && done < len; }
  };

  DetachedTask drive();           // the single coroutine that owns all I/O
  void         finalize();        // last straight-line step: free fd + self

  Reactor     &_r;
  int          _fd;
  int          _id;
  AsyncSocket  _sock;
  Event        _work;             // wakes drive() on a new VIO / on close
  VIO          _read;
  VIO          _write;
  Continuation _read_cont;
  Continuation _write_cont;
  bool         _closing{false};
  std::function<void()> _on_freed;
};

} // namespace coronet
