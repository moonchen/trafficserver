#include "coro_netvc.h"

#include <cstdio>
#include <unistd.h>

namespace coronet
{

static void
vclog(int id, const char *what)
{
  ::printf("    [VC %d] %s\n", id, what);
}

CoroNetVConnection::CoroNetVConnection(Reactor &r, int fd, int id, std::function<void()> on_freed)
  : _r(r), _fd(fd), _id(id), _sock(r, fd), _work(r), _on_freed(std::move(on_freed))
{
  drive(); // start the driver coroutine; it immediately parks on _work
}

void
CoroNetVConnection::do_io_read(void *buf, size_t len, Continuation cont)
{
  _read      = VIO{VIO::READ, static_cast<uint8_t *>(buf), len, 0};
  _read_cont = std::move(cont);
  _work.notify();
}

void
CoroNetVConnection::do_io_write(const void *buf, size_t len, Continuation cont)
{
  _write      = VIO{VIO::WRITE, static_cast<uint8_t *>(const_cast<void *>(buf)), len, 0};
  _write_cont = std::move(cont);
  _work.notify();
}

void
CoroNetVConnection::do_io_close()
{
  if (_closing) {
    return;
  }
  _closing = true;
  vclog(_id, "do_io_close(): cancelling any in-flight op, then unwinding");
  // Reach into whatever the coroutine is awaiting and cancel it. The op still
  // completes (with -ECANCELED); drive() resumes and unwinds cleanly.
  _sock.cancel_read();
  _sock.cancel_write();
  _work.notify(); // in case drive() is parked on _work rather than on I/O
}

// The whole VConnection read/write lifecycle as one straight-line coroutine.
DetachedTask
CoroNetVConnection::drive()
{
  for (;;) {
    if (_closing) {
      break;
    }
    if (!_read.active() && !_write.active()) {
      co_await _work; // nothing to do; park until a do_io_* call (or close)
      continue;
    }

    if (_read.active()) {
      // The recv buffer is _read.base, owned by the caller and pinned for the
      // duration of this await because we are suspended here.
      int n      = co_await _sock.recv(_read.base + _read.done, _read.len - _read.done);
      _read.kind = VIO::NONE; // one-shot: caller re-arms with another do_io_read
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
          _write.kind = VIO::NONE; // fully written
          if (_write_cont) {
            _write_cont(VC_WRITE_COMPLETE);
          }
        }
        // else: partial write, stay active and loop to send the remainder.
      }
    }
  }

  // Closing path. Any op we were awaiting has already completed (cancelled), so
  // there is nothing in flight referencing this object. Now we can safely close
  // the fd and destroy ourselves.
  vclog(_id, "drive() unwound; closing socket asynchronously");
  co_await _sock.close();
  finalize();
}

void
CoroNetVConnection::finalize()
{
  // Copy out anything we need before we delete ourselves.
  auto cb = _on_freed;
  vclog(_id, "finalize(): VC freed (no op was left dangling)");
  if (cb) {
    cb();
  }
  delete this; // safe: last statement reachable from this object; the drive()
               // coroutine frame is separate and self-destructs after we return.
}

} // namespace coronet
