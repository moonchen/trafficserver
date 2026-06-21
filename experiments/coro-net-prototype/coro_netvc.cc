#include "coro_netvc.h"

#include <cstdio>
#include <unistd.h>

namespace coronet
{

static void
vclog(int id, int reactor_id, const char *what)
{
  ::printf("    [VC %d @reactor %d] %s\n", id, reactor_id, what);
}

CoroNetVConnection::CoroNetVConnection(Reactor &owner, int fd, int id, std::function<void()> on_freed)
  : _owner(&owner), _fd(fd), _id(id), _sock(owner, fd), _on_freed(std::move(on_freed))
{
  drive(); // start the driver; it immediately parks on _work
}

void
CoroNetVConnection::do_io_read(void *buf, size_t len, Continuation cont)
{
  assert_owner();
  _read      = VIO{VIO::READ, static_cast<uint8_t *>(buf), len, 0};
  _read_cont = std::move(cont);
  _work.notify(*_owner);
}

void
CoroNetVConnection::do_io_write(const void *buf, size_t len, Continuation cont)
{
  assert_owner();
  _write      = VIO{VIO::WRITE, static_cast<uint8_t *>(const_cast<void *>(buf)), len, 0};
  _write_cont = std::move(cont);
  _work.notify(*_owner);
}

void
CoroNetVConnection::do_io_close()
{
  assert_owner();
  if (_closing) {
    return;
  }
  _closing = true;
  vclog(_id, _owner->id(), "do_io_close(): cancel any in-flight op, then unwind");
  _sock.cancel_read();
  _sock.cancel_write();
  _work.notify(*_owner);
}

// A suspend-and-rehome awaitable. await_suspend hands the SUSPENDED coroutine
// across to the destination thread; the source thread does nothing further with
// the VC. This is what makes migration race-free without a lock: the coroutine
// is genuinely parked between the two threads, and post_remote provides the
// happens-before edge.
namespace
{
  struct Handoff {
    CoroNetVConnection *vc;
    Reactor            *dest;
    bool
    await_ready() const noexcept
    {
      return false;
    }
    void
    await_suspend(std::coroutine_handle<> h) const
    {
      vc->migrate_handoff(h, *dest);
    }
    void
    await_resume() const noexcept
    {
    }
  };
} // namespace

void
CoroNetVConnection::request_migrate(Reactor &dest, std::function<void()> on_adopted)
{
  assert_owner();
  assert(_sock.idle() && "migrate only at a quiescent point (no I/O in flight)");
  _migrate_dest = &dest;
  _migrate_cb   = std::move(on_adopted);
  _work.notify(*_owner); // wake drive() so it reaches the migration point
}

void
CoroNetVConnection::migrate_handoff(std::coroutine_handle<> resume_me, Reactor &dest)
{
  // Called while drive() is suspended. The destination thread becomes the owner
  // and resumes the coroutine; the source thread is already done with us.
  dest.post_remote([this, &dest, resume_me] {
    _owner = &dest;
    _sock.rebind(dest);
    vclog(_id, _owner->id(), "adopted on new thread; resuming coroutine here");
    dest.resume_soon(resume_me);
  });
}

DetachedTask
CoroNetVConnection::drive()
{
  for (;;) {
    if (_closing) {
      break;
    }
    if (_migrate_dest) {
      Reactor *dest = _migrate_dest;
      _migrate_dest = nullptr;
      vclog(_id, _owner->id(), "request_migrate(): suspending to hand off");
      co_await Handoff{this, dest}; // resumes on dest's thread; _owner is now dest
      if (auto cb = std::move(_migrate_cb)) {
        cb(); // kick off the next transaction on the new thread
      }
      continue;
    }
    if (!_read.active() && !_write.active()) {
      co_await _work; // park until a do_io_* call (or close / adoption)
      continue;
    }

    if (_read.active()) {
      int n      = co_await _sock.recv(_read.base + _read.done, _read.len - _read.done);
      _read.kind = VIO::NONE; // one-shot
      if (_closing) {
        break;
      }
      if (n <= 0) {
        if (_read_cont) {
          _read_cont(n == 0 ? VC_EOS : VC_ERROR);
        }
      } else {
        _read.done += n;
        if (_read_cont) {
          _read_cont(_read.done >= _read.len ? VC_READ_COMPLETE : VC_READ_READY);
        }
      }
    }

    if (_write.active()) {
      int n = co_await _sock.send(_write.base + _write.done, _write.len - _write.done);
      if (_closing) {
        break;
      }
      if (n <= 0) {
        _write.kind = VIO::NONE;
        if (_write_cont) {
          _write_cont(VC_ERROR);
        }
      } else {
        _write.done += n;
        if (_write.done >= _write.len) {
          _write.kind = VIO::NONE;
          if (_write_cont) {
            _write_cont(VC_WRITE_COMPLETE);
          }
        }
      }
    }
  }

  vclog(_id, _owner->id(), "drive() unwound; closing socket asynchronously");
  co_await _sock.close();
  finalize();
}

void
CoroNetVConnection::finalize()
{
  auto cb = _on_freed;
  vclog(_id, _owner->id(), "finalize(): VC freed (no op left dangling)");
  if (cb) {
    cb();
  }
  delete this;
}

} // namespace coronet
