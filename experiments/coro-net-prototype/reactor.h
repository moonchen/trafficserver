/** @file
 *
 *  SEAM 2 — the coroutine / thread-affinity boundary.
 *
 *  The backend (Seam 1) only *detects* that ops finished. This layer decides
 *  what "finish" means: resume the waiting coroutine. The single most important
 *  line in this whole prototype is Reactor::resume(): that is the exact point
 *  where, in real ATS, you would (a) make sure you are on the EThread that owns
 *  the VConnection and (b) hold that VConnection's mutex before re-entering its
 *  code. Both WIP branches smear that lock/affinity logic across every
 *  completion handler (IOUringReader::handle_complete takes SCOPED_MUTEX_LOCK;
 *  TCPNetVConnection bounces through schedule_imm_local). Funnelling *all*
 *  resumes through one method means you solve affinity once.
 *
 *  This prototype runs single-threaded, so resume() can just call h.resume().
 *  The comments mark precisely what would change for the multi-threaded ATS net
 *  poll loop.
 */
#pragma once

#include "io_backend.h"

#include <coroutine>
#include <exception>
#include <functional>
#include <queue>
#include <vector>

namespace coronet
{

// A fire-and-forget coroutine. Eager start, self-cleaning frame (final_suspend
// is suspend_never, so the frame is destroyed automatically when the coroutine
// returns). We never need to juggle a coroutine_handle by hand. A coroutine that
// wants to signal "I'm fully done, my resources can be reclaimed" just calls a
// normal function as its last statement before returning — see
// CoroNetVConnection::drive().
struct DetachedTask {
  struct promise_type {
    DetachedTask        get_return_object() noexcept { return {}; }
    std::suspend_never  initial_suspend() noexcept { return {}; }
    std::suspend_never  final_suspend() noexcept { return {}; }
    void                return_void() noexcept {}
    void                unhandled_exception() { std::terminate(); }
  };
};

class Reactor
{
public:
  explicit Reactor(IBackend &backend) : _backend(backend) {}

  IBackend &backend() { return _backend; }

  // Schedule an in-process resume (used when something *other* than an I/O
  // completion needs to wake a coroutine — e.g. a do_io_read() call delivering a
  // new VIO to a driver coroutine that is parked on an internal signal). The
  // equivalent in ATS is EThread::schedule_imm_local().
  void
  resume_soon(std::coroutine_handle<> h)
  {
    if (h && !h.done()) {
      _ready.push(h);
    }
  }

  // Defer a plain callable to a later loop turn (after pending resumes). Used by
  // the demo to trigger a close only once a recv is genuinely in flight.
  void post(std::function<void()> fn) { _posts.push(std::move(fn)); }

  void stop() { _stop = true; }

  void
  run()
  {
    while (!_stop) {
      // 1. Run everything already queued for in-process resumption first. This
      //    drains driver coroutines so their I/O ops are actually submitted...
      while (!_ready.empty()) {
        auto h = _ready.front();
        _ready.pop();
        resume(h);
      }

      // 2. ...then run deferred callables (e.g. a do_io_close) against state
      //    that has already issued its operations.
      while (!_posts.empty()) {
        auto fn = std::move(_posts.front());
        _posts.pop();
        fn();
      }

      // 3. Ask the backend what I/O finished, then resume those waiters.
      _completed.clear();
      _backend.poll((_ready.empty() && _posts.empty()) ? POLL_BLOCK_MS : 0, _completed);
      for (IoOp *op : _completed) {
        resume(op->waiter);
      }
    }
  }

private:
  // *** THE AFFINITY / MUTEX SEAM ***
  // In this single-threaded prototype, resuming a coroutine is just h.resume().
  // In ATS this method is where you would:
  //   - confirm this EThread owns the target VConnection (else re-post the handle
  //     to the owner's local queue and return);
  //   - take SCOPED_MUTEX_LOCK on the VConnection's mutex for the duration of the
  //     resume, so the resumed coroutine body runs with the same locking
  //     guarantees the old Continuation handlers had.
  // Because every resume in the system goes through here, that policy is written
  // exactly once instead of being duplicated in each completion handler.
  void
  resume(std::coroutine_handle<> h)
  {
    if (h && !h.done()) {
      h.resume();
    }
  }

  static constexpr int POLL_BLOCK_MS = 50;

  IBackend                              &_backend;
  std::queue<std::coroutine_handle<>>    _ready;
  std::queue<std::function<void()>>      _posts;
  std::vector<IoOp *>                    _completed;
  bool                                   _stop{false};
};

} // namespace coronet
