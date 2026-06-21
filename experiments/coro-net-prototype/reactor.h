/** @file
 *
 *  SEAM 2 — the coroutine / thread-affinity boundary (multi-threaded).
 *
 *  This is the version that takes the EThread model seriously. The design rule,
 *  borrowed straight from ATS net threads, is:
 *
 *      A connection is OWNED by exactly one reactor (one OS thread). Every byte
 *      of its coroutine, and every I/O op it issues, runs on that thread. The
 *      backend (ring / epoll set) is thread-local and is only ever touched by
 *      its owner thread.
 *
 *  That single rule buys an enormous simplification: because each thread submits
 *  to its own ring, completions for a connection are *always* drained on the
 *  owner thread. There is no cross-thread resume on the I/O hot path — affinity
 *  is free. The only place another thread legitimately needs to influence a
 *  connection is a hand-off (the acceptor giving a new fd to a worker), and that
 *  goes through exactly one synchronized channel: post_remote().
 *
 *  Note what is deliberately ABSENT: a per-connection mutex on the resume path.
 *  ATS puts a ProxyMutex on every VConnection because its event system is
 *  general — any continuation may be scheduled onto any thread, so MUTEX_TRY_LOCK
 *  is the universal serialization primitive. Here we instead *confine* each
 *  connection to one thread and forbid touching it from anywhere else. With that
 *  invariant, resuming a coroutine is a plain thread-local call; the lock would
 *  only ever be taken uncontended, so we drop it. The cost is discipline: every
 *  cross-thread influence MUST go through post_remote(), the one synchronized
 *  channel. (Asserts below enforce the confinement invariant in debug builds.)
 */
#pragma once

#include "io_backend.h"

#include <atomic>
#include <chrono>
#include <coroutine>
#include <cstdint>
#include <exception>
#include <fcntl.h>
#include <functional>
#include <mutex>
#include <queue>
#include <sys/socket.h>
#include <thread>
#include <unistd.h>
#include <vector>

namespace coronet
{

// A fire-and-forget coroutine: eager start, self-cleaning frame. Used for
// coroutines that run to completion (accept loop, client, a VC's drive()).
struct DetachedTask {
  struct promise_type {
    DetachedTask        get_return_object() noexcept { return {}; }
    std::suspend_never  initial_suspend() noexcept { return {}; }
    std::suspend_never  final_suspend() noexcept { return {}; }
    void                return_void() noexcept {}
    void                unhandled_exception() { std::terminate(); }
  };
};

// An owned coroutine: eager start, but the frame is kept alive at completion so
// the owner can destroy it explicitly. Used for the reactor's wakeup loop, which
// never returns on its own (it parks on a recv) and so must be torn down.
struct OwnedTask {
  struct promise_type {
    OwnedTask
    get_return_object() noexcept
    {
      return OwnedTask{std::coroutine_handle<promise_type>::from_promise(*this)};
    }
    std::suspend_never  initial_suspend() noexcept { return {}; }
    std::suspend_always final_suspend() noexcept { return {}; }
    void                return_void() noexcept {}
    void                unhandled_exception() { std::terminate(); }
  };
  std::coroutine_handle<promise_type> h{};
};

class Reactor
{
public:
  explicit Reactor(IBackend &backend, int id = 0) : _backend(backend), _id(id), _owner(std::this_thread::get_id())
  {
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0, _wake) < 0) {
      std::terminate();
    }
    _wakeup = wakeup_loop(); // arm the cross-thread wakeup recv on _wake[0]
  }

  ~Reactor()
  {
    // Tear down the parked wakeup coroutine (it never returns on its own). Its
    // in-flight recv on _wake[0] is abandoned, but the backend is destroyed
    // immediately after this and never dereferences the freed op.
    if (_wakeup.h) {
      _wakeup.h.destroy();
    }
    ::close(_wake[0]);
    ::close(_wake[1]);
  }

  IBackend &backend() { return _backend; }
  int       id() const { return _id; }

  // ---- same-thread scheduling (used by I/O completions and VC signals) ------

  // Resume `h` later, on this thread. No lock: the connection is confined to
  // this thread, so this is the only place its coroutine is ever resumed.
  void
  resume_soon(std::coroutine_handle<> h)
  {
    if (h && !h.done()) {
      _ready.push(h);
    }
  }

  // Defer a plain callable to a later turn on THIS thread.
  void post(std::function<void()> fn) { _posts.push(std::move(fn)); }

  // Run `fn` periodically on this thread (the inactivity-cop pattern: each net
  // thread scans its own connections). Backend-agnostic, so it works the same on
  // epoll and io_uring without needing timerfd / IORING_OP_TIMEOUT here.
  void
  every(std::chrono::milliseconds interval, std::function<void()> fn)
  {
    _timers.push_back(Timer{interval, Clock::now() + interval, std::move(fn)});
  }

  // ---- cross-thread scheduling (THE synchronized hand-off channel) ----------

  // Thread-safe. Any thread may call this; `fn` runs on the owner thread.
  void
  post_remote(std::function<void()> fn)
  {
    {
      std::lock_guard<std::mutex> g(_remote_mu);
      _remote.push_back(std::move(fn));
    }
    signal_wake();
  }

  // Thread-safe stop. Deliberately does NOT poke the wakeup pipe: run()'s poll
  // has a bounded timeout (POLL_BLOCK_MS) and re-checks _stop each turn, so it
  // exits on its own within that window. Avoiding the fd write here means the
  // owner thread is the *only* thing that ever touches its wakeup fds, so tearing
  // them down in ~Reactor can never race a writer. (The pipe is still poked by
  // post_remote during normal operation, which is synchronized with the owner
  // via the recv completion.)
  void
  stop()
  {
    _stop.store(true);
  }

  bool on_owner_thread() const { return std::this_thread::get_id() == _owner; }

  void
  run()
  {
    while (!_stop.load()) {
      drain_ready();
      drain_posts();
      int timeout = next_timeout_ms();
      _completed.clear();
      _backend.poll(timeout, _completed);
      for (IoOp *op : _completed) {
        resume(op->waiter);
      }
      fire_timers();
    }
    // Best-effort: run anything queued so coroutines can observe stop and unwind.
    drain_ready();
    drain_posts();
  }

  // A minimal awaitable used internally to keep a recv armed on the wakeup pipe.
  struct RawRecv {
    Reactor &r;
    IoOp     op;
    bool     await_ready() const noexcept { return false; }
    void
    await_suspend(std::coroutine_handle<> h) noexcept
    {
      op.waiter = h;
      r._backend.submit(&op);
    }
    int await_resume() noexcept { return op.result; }
  };

private:
  using Clock = std::chrono::steady_clock;

  struct Timer {
    std::chrono::milliseconds interval;
    Clock::time_point         next;
    std::function<void()>     fn;
  };

  // *** THE AFFINITY SEAM ***
  // The single place coroutine bodies are re-entered, always on the owner
  // thread. No lock: thread confinement is the serialization mechanism.
  void
  resume(std::coroutine_handle<> h)
  {
    if (h && !h.done()) {
      h.resume();
    }
  }

  void
  drain_ready()
  {
    while (!_ready.empty()) {
      auto h = _ready.front();
      _ready.pop();
      resume(h);
    }
  }

  void
  drain_posts()
  {
    while (!_posts.empty()) {
      auto fn = std::move(_posts.front());
      _posts.pop();
      fn();
    }
    // Pull cross-thread work in and run it on this (owner) thread.
    std::vector<std::function<void()>> remote;
    {
      std::lock_guard<std::mutex> g(_remote_mu);
      remote.swap(_remote);
    }
    for (auto &fn : remote) {
      fn();
    }
  }

  int
  next_timeout_ms()
  {
    int t = (_ready.empty() && _posts.empty()) ? POLL_BLOCK_MS : 0;
    for (auto &tm : _timers) {
      auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(tm.next - Clock::now()).count();
      if (ms < 0) {
        ms = 0;
      }
      t = std::min<int>(t, static_cast<int>(ms));
    }
    return t;
  }

  void
  fire_timers()
  {
    auto now = Clock::now();
    for (auto &tm : _timers) {
      if (now >= tm.next) {
        tm.fn();
        tm.next = now + tm.interval;
      }
    }
  }

  void
  signal_wake()
  {
    uint8_t b = 1;
    ssize_t n = ::write(_wake[1], &b, 1);
    (void)n; // a full pipe already means "wake pending"
  }

  // Keeps one recv permanently armed on _wake[0]; every cross-thread post writes
  // a byte that completes it, and we re-arm. The scratch buffer lives in this
  // coroutine's frame, pinned across the await.
  OwnedTask
  wakeup_loop()
  {
    uint8_t scratch[64];
    while (!_stop.load()) {
      co_await RawRecv{*this, IoOp{.type = IoOp::Type::Recv, .fd = _wake[0], .buf = scratch, .len = sizeof scratch}};
      // The actual cross-thread work is drained in drain_posts() each turn; this
      // recv exists only to break the backend out of its blocking poll.
    }
  }

  static constexpr int POLL_BLOCK_MS = 50;

  IBackend                           &_backend;
  int                                 _id;
  std::thread::id                     _owner;
  int                                 _wake[2]{-1, -1};

  std::queue<std::coroutine_handle<>> _ready;
  std::queue<std::function<void()>>   _posts;
  std::vector<Timer>                  _timers;
  std::vector<IoOp *>                 _completed;

  std::mutex                          _remote_mu;
  std::vector<std::function<void()>>  _remote;

  OwnedTask                           _wakeup;
  std::atomic<bool>                   _stop{false};
};

} // namespace coronet
