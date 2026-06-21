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

// Parks drive() on _work, THEN publishes the VC for adoption. The ordering
// matters: the park (writing _work's waiter handle) happens-before the publish,
// and the publish happens-before the adopter's pool-take (the pool lock), so the
// adopter's later do_io_read -> _work.notify sees the parked handle. No lock on
// the VC, no cross-thread message — the connection is bare (no armed op) while it
// sits parked, waiting to be pulled.
struct CoroNetVConnection::ParkAndRelease {
  CoroNetVConnection *vc;
  bool
  await_ready() const noexcept
  {
    return false;
  }
  void
  await_suspend(std::coroutine_handle<> h) const
  {
    vc->_work.park(h); // park first...
    auto publish   = std::move(vc->_on_parked);
    vc->_on_parked = nullptr;
    publish(vc); // ...then make the parked VC visible for a destination pull
  }
  void
  await_resume() const noexcept
  {
  }
};

void
CoroNetVConnection::park_and_release(std::function<void(CoroNetVConnection *)> on_parked)
{
  assert_owner();
  assert(_sock.idle() && "release only a quiescent connection (no in-flight op)");
  // Called from within a continuation (drive() is running), so no notify is
  // needed: drive() reaches the release point on its next loop turn.
  _on_parked = std::move(on_parked);
}

void
CoroNetVConnection::migrate_here(Reactor &dest)
{
  // Synchronous, destination-pulled (cf. ATS migrateToCurrentThread). The caller
  // is already on dest's thread and has pulled this VC out of a synchronized pool,
  // so the previous owner's writes are visible and nobody else touches the VC.
  assert(dest.on_owner_thread() && "migrate_here must run on the destination thread");
  assert(_sock.idle() && "migrate only a quiescent connection (no in-flight op)");
  _owner = &dest;
  _sock.rebind(dest); // adopt the bare fd onto dest's ring/poll set
  vclog(_id, dest.id(), "migrate_here(): adopted synchronously (destination-pulled)");
}

DetachedTask
CoroNetVConnection::drive()
{
  for (;;) {
    if (_closing) {
      break;
    }
    if (_on_parked) {
      // Quiesce into a pool and wait to be pulled. ParkAndRelease resumes us on
      // whichever thread later adopts us (migrate_here + do_io_read); _owner has
      // been re-homed by then.
      vclog(_id, _owner->id(), "park_and_release(): parking bare (no armed op), awaiting a pull");
      co_await ParkAndRelease{this};
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
