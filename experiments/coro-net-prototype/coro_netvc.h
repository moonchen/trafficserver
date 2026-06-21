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
 *    - A VC may be MIGRATED to another reactor/thread (migrate_to), but only at
 *      a quiescent point — no I/O in flight. This models ATS moving an idle
 *      keep-alive origin connection onto the client connection's thread for a
 *      global session pool. Migration is a message-pass (post_remote), not a
 *      lock: the source thread stops touching the VC, hands it across the one
 *      synchronized channel, and the destination thread adopts it.
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
  bool await_ready() const noexcept { return _signaled; }
  void await_suspend(std::coroutine_handle<> h) noexcept { _waiter = h; }
  void await_resume() noexcept { _signaled = false; }

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

  // Request migration to another reactor/thread. Must be called on the current
  // owner thread at a quiescent point (no in-flight I/O — true between
  // transactions). The actual hand-off happens inside drive(), which suspends
  // the coroutine and resumes it on `dest`; `on_adopted` then runs on the
  // destination thread (kick off the next transaction there). This models ATS
  // moving an idle keep-alive origin connection onto the client's thread.
  void request_migrate(Reactor &dest, std::function<void()> on_adopted);

  // Internal: invoked by the migration awaitable while the coroutine is
  // suspended. Re-homes the VC to `dest` and resumes `resume_me` on dest's
  // thread. Public only so the awaitable can reach it.
  void migrate_handoff(std::coroutine_handle<> resume_me, Reactor &dest);

  size_t   read_done() const { return _read.done; }
  int      id() const { return _id; }
  Reactor &owner() const { return *_owner; }

private:
  struct VIO {
    enum Kind { NONE, READ, WRITE } kind{NONE};
    uint8_t *base{nullptr};
    size_t   len{0};
    size_t   done{0};
    bool     active() const { return kind != NONE && done < len; }
  };

  DetachedTask drive();
  void         finalize();
  void         assert_owner() const { assert(_owner->on_owner_thread() && "VC touched off its owner thread"); }

  Reactor              *_owner;   // rebindable: changes on migration
  int                   _fd;
  int                   _id;
  AsyncSocket           _sock;
  Event                 _work;
  VIO                   _read;
  VIO                   _write;
  Continuation          _read_cont;
  Continuation          _write_cont;
  bool                  _closing{false};
  Reactor              *_migrate_dest{nullptr};
  std::function<void()> _migrate_cb;
  std::function<void()> _on_freed;
};

} // namespace coronet
