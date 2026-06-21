/** @file
 *
 *  The awaitable layer: turns the backend's IoOp contract into things you can
 *  `co_await`. This is the join between Seam 1 (backend) and Seam 2 (reactor).
 *
 *  An AsyncSocket is the spiritual successor to NetAIO::TCPConnection, but where
 *  NetAIO exposed callbacks (onRecvmsg/onSendmsg/onConnect...), here every
 *  operation is an awaitable that yields its result inline:
 *
 *      ssize_t n = co_await sock.recv(buf, len);   // n bytes, or -errno
 *
 *  The op lives in the awaitable, which is a temporary in the co_await
 *  expression; per [expr.await] its lifetime is extended across the suspension
 *  point. So the IoOp and the buffer it references are automatically pinned for
 *  exactly the duration of the in-flight operation. No class-scope hoisting
 *  (net-iouring), no per-I/O heap allocation (async-net).
 */
#pragma once

#include "io_backend.h"
#include "reactor.h"

#include <cerrno>
#include <coroutine>
#include <unistd.h>

namespace coronet
{

class AsyncSocket
{
public:
  AsyncSocket(Reactor &r, int fd) : _r(r), _fd(fd) {}

  AsyncSocket(const AsyncSocket &)            = delete;
  AsyncSocket &operator=(const AsyncSocket &) = delete;

  int fd() const { return _fd; }

  // One awaitable type drives every op. It registers itself as the socket's
  // current in-flight op for its direction so that cancel_read()/cancel_write()
  // can reach it, submits to the backend on suspend, and returns the result on
  // resume.
  class Op
  {
  public:
    Op(AsyncSocket &s, IoOp op, IoOp **slot) : _s(s), _op(op), _slot(slot) {}

    bool await_ready() const noexcept { return false; }

    void
    await_suspend(std::coroutine_handle<> h) noexcept
    {
      _op.waiter = h;
      *_slot     = &_op;              // make this op reachable for cancellation
      _s._r.backend().submit(&_op);   // Seam 1 hand-off
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
    return {*this, IoOp{.type = IoOp::Type::Recv, .fd = _fd, .buf = buf, .len = len}, &_in_read};
  }

  Op
  send(const void *buf, size_t len)
  {
    return {*this, IoOp{.type = IoOp::Type::Send, .fd = _fd, .buf = const_cast<void *>(buf), .len = len}, &_in_write};
  }

  Op
  connect(sockaddr *addr, socklen_t addrlen)
  {
    return {*this, IoOp{.type = IoOp::Type::Connect, .fd = _fd, .addr = addr, .addrlen = &_connect_len(addrlen)}, &_in_write};
  }

  Op
  accept(sockaddr *addr, socklen_t *addrlen)
  {
    return {*this, IoOp{.type = IoOp::Type::Accept, .fd = _fd, .addr = addr, .addrlen = addrlen}, &_in_read};
  }

  Op
  close()
  {
    return {*this, IoOp{.type = IoOp::Type::Close, .fd = _fd}, &_in_write};
  }

  // Cancellation handles for whoever owns this socket (e.g. a NetVConnection's
  // do_io_close). The in-flight op still completes — with -ECANCELED — and the
  // awaiting coroutine resumes normally and unwinds. That is the safe-teardown
  // contract.
  void
  cancel_read()
  {
    if (_in_read) {
      _r.backend().cancel(_in_read);
    }
  }

  void
  cancel_write()
  {
    if (_in_write) {
      _r.backend().cancel(_in_write);
    }
  }

private:
  // connect() needs somewhere stable to keep the address length; stash it here.
  socklen_t &
  _connect_len(socklen_t v)
  {
    _connect_addrlen = v;
    return _connect_addrlen;
  }

  Reactor  &_r;
  int       _fd;
  IoOp     *_in_read{nullptr};   // current in-flight read-side op (recv/accept)
  IoOp     *_in_write{nullptr};  // current in-flight write-side op (send/connect/close)
  socklen_t _connect_addrlen{0};
};

} // namespace coronet
