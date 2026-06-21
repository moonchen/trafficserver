/** @file
 *
 *  SEAM 3 — the NetVConnection boundary (thread-confined + migratable).
 *
 *  Same sacred facade as before — do_io_read / do_io_write / do_io_close +
 *  Continuation — driven underneath by a single coroutine, drive(). What this
 *  version adds is an explicit ownership model that mirrors ATS net threads:
 *
 *    - A VC is OWNED by one reactor (_owner). Every do_io_* and every resume
 *      happens on that reactor's thread. do_io_* assert this in debug builds.
 *      There is no per-VC mutex: confinement IS the serialization.
 *
 *    - A VC may be MIGRATED to another reactor/thread, mirroring ATS's
 *      UnixNetVConnection::migrateToCurrentThread: SYNCHRONOUS and
 *      DESTINATION-PULLED. The thread that wants the connection calls
 *      migrate_here() on its own reactor and the call returns with the VC re-homed
 *      to it — no callback, no cross-thread message. This works because migration
 *      is only legal on a QUIESCENT connection (no in-flight op): an idle pooled
 *      connection holds no armed io_uring SQE, so the destination can simply adopt
 *      the fd onto its own ring. The hand-off of the VC pointer from old owner to
 *      new owner travels through whatever synchronized structure pooled it (the
 *      pool's lock), which supplies the happens-before edge — same as ATS relying
 *      on the session-pool lock. (Contrast epoll's migrateToCurrentThread, which
 *      can yank the fd off the source thread's poll set from the destination via
 *      ep.stop(); io_uring has no thread-movable registration, so we instead
 *      require quiescence and pull the bare fd.)
 */
#pragma once

#include "async_socket.h"
#include "reactor.h"

#include <cassert>
#include <coroutine>
#include <cstdint>
#include <functional>

namespace coronet
{

enum VcEvent {
  VC_READ_READY     = 1,
  VC_READ_COMPLETE  = 2,
  VC_WRITE_COMPLETE = 3,
  VC_EOS            = 4,
  VC_ERROR          = 5,
};

using Continuation = std::function<void(int event)>;

// One-shot wakeup awaitable used to park drive() between VIOs and to wake it on
// a do_io_* call (or close, or post-migration adoption). It stores no reactor:
// the caller passes the *current* owner at notify() time, which is what lets a
// parked drive() be resumed on a different thread after migration.
class Event
{
public:
  bool
  await_ready() const noexcept
  {
    return _signaled;
  }
  void
  await_suspend(std::coroutine_handle<> h) noexcept
  {
    _waiter = h;
  }
  void
  await_resume() noexcept
  {
    _signaled = false;
  }

  // Park an externally-driven coroutine on this Event (used by ParkAndRelease so
  // a later do_io_* on the adopting thread resumes drive()). Clears any stale
  // signal so the next real notify is the one that resumes.
  void
  park(std::coroutine_handle<> h) noexcept
  {
    _waiter   = h;
    _signaled = false;
  }

  void
  notify(Reactor &owner)
  {
    if (_waiter) {
      auto h  = _waiter;
      _waiter = {};
      owner.resume_soon(h);
    } else {
      _signaled = true;
    }
  }

private:
  std::coroutine_handle<> _waiter{};
  bool                    _signaled{false};
};

class CoroNetVConnection
{
public:
  CoroNetVConnection(Reactor &owner, int fd, int id, std::function<void()> on_freed = {});

  CoroNetVConnection(const CoroNetVConnection &)            = delete;
  CoroNetVConnection &operator=(const CoroNetVConnection &) = delete;

  // NetVConnection facade. Must be called on the owner thread.
  void do_io_read(void *buf, size_t len, Continuation cont);
  void do_io_write(const void *buf, size_t len, Continuation cont);
  void do_io_close();

  // Adopt this connection onto the calling thread's reactor — the synchronous,
  // destination-pulled migration (cf. ATS migrateToCurrentThread). MUST be called
  // on `dest`'s thread, and only on a quiescent connection (no in-flight op),
  // which the caller must have obtained through a synchronized hand-off (e.g. a
  // session pool) so the previous owner's writes are visible here. Returns with
  // the VC owned by `dest`; the caller then drives the next transaction normally.
  void migrate_here(Reactor &dest);

  // Quiesce this connection and, once drive() has parked, invoke `on_parked(this)`
  // to publish it (e.g. push into a session pool) for a future migrate_here().
  // Called on the owner thread from within a continuation (drive() running). The
  // parked connection holds NO armed io_uring op — that is what makes a later
  // destination-pull adoption possible.
  void park_and_release(std::function<void(CoroNetVConnection *)> on_parked);

  size_t
  read_done() const
  {
    return _read.done;
  }
  int
  id() const
  {
    return _id;
  }
  Reactor &
  owner() const
  {
    return *_owner;
  }

private:
  struct VIO {
    enum Kind { NONE, READ, WRITE } kind{NONE};
    uint8_t *base{nullptr};
    size_t   len{0};
    size_t   done{0};
    bool
    active() const
    {
      return kind != NONE && done < len;
    }
  };

  struct ParkAndRelease; // defined in .cc; parks drive() then publishes the VC

  DetachedTask drive();
  void         finalize();
  void
  assert_owner() const
  {
    assert(_owner->on_owner_thread() && "VC touched off its owner thread");
  }

  Reactor    *_owner; // rebindable: changes on migration
  int         _fd;
  int         _id;
  AsyncSocket _sock;
  Event       _work;
  VIO         _read;
  VIO         _write;

  Continuation                              _read_cont;
  Continuation                              _write_cont;
  bool                                      _closing{false};
  std::function<void(CoroNetVConnection *)> _on_parked; // set by park_and_release
  std::function<void()>                     _on_freed;
};

} // namespace coronet
