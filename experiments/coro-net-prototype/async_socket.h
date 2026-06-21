/** @file
 *
 *  The awaitable layer: turns the backend's IoOp contract into things you can
 *  `co_await`. The join between Seam 1 (backend) and Seam 2 (reactor).
 *
 *      ssize_t n = co_await sock.recv(buf, len);   // n bytes, or -errno
 *
 *  The op lives in the awaitable, which is a temporary in the co_await
 *  expression; per [expr.await] its lifetime extends across the suspension
 *  point. So the IoOp and the buffer it references are automatically pinned for
 *  exactly the duration of the in-flight operation — no per-I/O heap allocation,
 *  no class-scope hoisting.
 *
 *  The socket holds its reactor by POINTER, not reference, so it can be rebound
 *  to a different reactor (thread) during connection migration. Rebinding is
 *  only legal while quiescent (no op in flight) — see rebind().
 */
#pragma once

#include "io_backend.h"
#include "reactor.h"

#include <cassert>
#include <cerrno>
#include <coroutine>
#include <unistd.h>

namespace coronet
{

class AsyncSocket
{
public:
  AsyncSocket(Reactor &r, int fd) : _r(&r), _fd(fd) {}

  AsyncSocket(const AsyncSocket &)            = delete;
  AsyncSocket &operator=(const AsyncSocket &) = delete;

  int
  fd() const
  {
    return _fd;
  }
  Reactor &
  reactor() const
  {
    return *_r;
  }

  // Move this socket to another reactor/thread. Only valid when nothing is in
  // flight (migration happens at a quiescent point — see CoroNetVConnection).
  void
  rebind(Reactor &r)
  {
    assert(_in_read == nullptr && _in_write == nullptr && "cannot migrate a socket with I/O in flight");
    _r = &r;
  }

  class Op
  {
  public:
    Op(AsyncSocket &s, IoOp op, IoOp **slot) : _s(s), _op(op), _slot(slot) {}

    bool
    await_ready() const noexcept
    {
      return false;
    }

    void
    await_suspend(std::coroutine_handle<> h) noexcept
    {
      _op.waiter = h;
      *_slot     = &_op;             // make this op reachable for cancellation
      _s._r->backend().submit(&_op); // Seam 1 hand-off, on the owner thread
    }

    int
    await_resume() noexcept
    {
      *_slot = nullptr;
      return _op.result;
    }

  private:
    AsyncSocket &_s;
    IoOp         _op;
    IoOp       **_slot;
  };

  Op
  recv(void *buf, size_t len)
  {
    return {
      *this, IoOp{.type = IoOp::Type::Recv, .fd = _fd, .buf = buf, .len = len},
       &_in_read
    };
  }

  Op
  send(const void *buf, size_t len)
  {
    return {
      *this, IoOp{.type = IoOp::Type::Send, .fd = _fd, .buf = const_cast<void *>(buf), .len = len},
       &_in_write
    };
  }

  Op
  connect(sockaddr *addr, socklen_t addrlen)
  {
    _connect_addrlen = addrlen;
    return {
      *this, IoOp{.type = IoOp::Type::Connect, .fd = _fd, .addr = addr, .addrlen = &_connect_addrlen},
       &_in_write
    };
  }

  Op
  accept(sockaddr *addr, socklen_t *addrlen)
  {
    return {
      *this, IoOp{.type = IoOp::Type::Accept, .fd = _fd, .addr = addr, .addrlen = addrlen},
       &_in_read
    };
  }

  Op
  close()
  {
    return {
      *this, IoOp{.type = IoOp::Type::Close, .fd = _fd},
       &_in_write
    };
  }

  void
  cancel_read()
  {
    if (_in_read) {
      _r->backend().cancel(_in_read);
    }
  }

  void
  cancel_write()
  {
    if (_in_write) {
      _r->backend().cancel(_in_write);
    }
  }

  bool
  idle() const
  {
    return _in_read == nullptr && _in_write == nullptr;
  }

private:
  Reactor  *_r;
  int       _fd;
  IoOp     *_in_read{nullptr};
  IoOp     *_in_write{nullptr};
  socklen_t _connect_addrlen{0};
};

} // namespace coronet
