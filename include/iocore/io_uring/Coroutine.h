/** @file

  A minimal C++20 coroutine runtime for the per-thread io_uring context.

  It provides just enough to drive an io_uring operation from a coroutine that
  is suspended and resumed on its owning EThread, reusing the existing
  IOUringContext (one ring per net thread, already pumped by
  NetHandler::waitForActivity) --- no new thread and no new event loop.

  Three pieces:
    - Task<T> / DetachedTask: coroutine return types (owned vs. fire-and-forget).
    - UringOp:    an awaitable that *is* an IOUringCompletionHandler. It submits a
                  caller-prepared SQE to this thread's ring and resumes the
                  awaiting coroutine from handle_complete() with the CQE result.
    - UringMultishotOp: the multishot form --- one submitted SQE awaited in a
                  loop, resuming once per CQE until a terminal completion.

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

#pragma once

#include "tscore/ink_config.h"

#if TS_USE_LINUX_IO_URING

#include "iocore/io_uring/IO_URING.h"
#include "tscore/ink_assert.h"
#include "tscore/ink_queue.h"

#include <cerrno>
#include <coroutine>
#include <type_traits>
#include <utility>
#include <cstddef>

namespace ts::iouring
{

namespace detail
{
  // A per-thread, bounded cache of coroutine frames keyed by frame size. Each
  // io_uring drive (_read/_write/_connect) allocates one frame (~1 KB: an iovec
  // array + msghdr + locals) and frees it at completion; at saturation that
  // malloc/free stream is the dominant cost of the io_uring net path (measured
  // ~15-27% throughput vs epoll, recovered by this pool). Frames are allocated and
  // freed on the same EThread (VCs are thread-confined), so the cache is
  // thread_local --- no atomics. It is bounded per size class so it cannot grow
  // with peak connection count: the worst case is MAX_CLASSES * CAP frames per
  // thread (8 * 1024 * ~1 KB, about 8 MB), with CAP sized so roughly a thousand
  // concurrent in-flight drives on one thread --- a saturated net thread --- stay
  // pooled before spilling to malloc. It uses an intrusive free list (the next
  // pointer lives in the freed frame) so it needs no bookkeeping allocation of
  // its own.
  // Honors traffic_server -f/-F (ink_freelist_global_disabled) so a debug/ASan run
  // routes every frame through malloc/free.
  class FramePool
  {
  public:
    static constexpr std::size_t MAX_CLASSES = 8;    // distinct frame sizes (one per coroutine type)
    static constexpr std::size_t CAP         = 1024; // frames cached per size class per thread

    void *
    allocate(std::size_t n)
    {
      if (Slot *s = slot(n); s != nullptr && s->head != nullptr) {
        void *p = s->head;
        s->head = *static_cast<void **>(p);
        --s->count;
        return p;
      }
      return ::operator new(n);
    }

    void
    deallocate(void *p, std::size_t n) noexcept
    {
      if (Slot *s = slot(n); s != nullptr && s->count < CAP) {
        *static_cast<void **>(p) = s->head;
        s->head                  = p;
        ++s->count;
        return;
      }
      ::operator delete(p);
    }

    // The pool is a per-thread (thread_local) object; its destructor runs when the
    // net thread exits at shutdown. Free only the cached (already-deallocated)
    // frames on the free list --- those are what leaks at exit. A frame belonging to
    // a coroutine still suspended on an in-flight op is live, not on this list (it is
    // only pushed here by deallocate(), i.e. after the coroutine completed), so
    // draining the free list can never free a frame the kernel still references ---
    // no thread-quiesce assumption is needed.
    ~FramePool()
    {
      for (Slot &s : slots_) {
        while (s.head != nullptr) {
          void *p = s.head;
          s.head  = *static_cast<void **>(p);
          ::operator delete(p);
        }
        s.count = 0;
      }
    }

  private:
    struct Slot {
      std::size_t size  = 0;
      void       *head  = nullptr;
      std::size_t count = 0;
    };
    Slot slots_[MAX_CLASSES];

    // Find (or lazily claim) the slot for size n; nullptr if more than MAX_CLASSES
    // distinct sizes appear (then the caller falls back to malloc).
    Slot *
    slot(std::size_t n)
    {
      Slot *vacancy = nullptr;
      for (Slot &s : slots_) {
        if (s.size == n) {
          return &s;
        }
        if (s.size == 0 && vacancy == nullptr) {
          vacancy = &s;
        }
      }
      if (vacancy != nullptr) {
        vacancy->size = n;
        return vacancy;
      }
      return nullptr;
    }
  };

  inline FramePool &
  frame_pool() noexcept
  {
    static thread_local FramePool p;
    return p;
  }

  // Resolved once: -f/-F is a startup switch set before any coroutine runs.
  inline bool
  frame_pool_enabled() noexcept
  {
    static const bool on = !ink_freelist_global_disabled();
    return on;
  }

  // Promise mixin carrying a coroutine's return channel: a stored value for
  // Task<T>, nothing for Task<void>. Kept as separate (specialized) types so the
  // void path never instantiates a `void _value` member.
  template <typename T> struct task_return {
    T _value{};
    void
    return_value(T v)
    {
      _value = std::move(v);
    }
  };
  template <> struct task_return<void> {
    void
    return_void() noexcept
    {
    }
  };
} // namespace detail

// A fire-and-forget coroutine: eager start, self-cleaning frame (final_suspend
// does not suspend, so the frame is freed the moment the body returns). Use for
// coroutines that run to completion on their own and whose handle the caller does
// not need to hold --- e.g. a connection's read/write drive loop.
struct DetachedTask {
  struct promise_type {
    // Frames come from the per-thread bounded pool (see detail::FramePool): one
    // frame is allocated per drive and freed at completion, so this malloc/free
    // stream is hot. The pool transparently falls back to ::operator new when a
    // size class is cold or full, or when freelists are globally disabled (-f/-F).
    static void *
    operator new(std::size_t n)
    {
      return detail::frame_pool_enabled() ? detail::frame_pool().allocate(n) : ::operator new(n);
    }
    static void
    operator delete(void *p, std::size_t n) noexcept
    {
      if (detail::frame_pool_enabled()) {
        detail::frame_pool().deallocate(p, n);
      } else {
        ::operator delete(p);
      }
    }

    DetachedTask
    get_return_object() noexcept
    {
      return {};
    }
    std::suspend_never
    initial_suspend() noexcept
    {
      return {};
    }
    std::suspend_never
    final_suspend() noexcept
    {
      return {};
    }
    void
    return_void() noexcept
    {
    }
    void
    unhandled_exception() noexcept
    {
      std::terminate();
    }
  };
};

// An owned coroutine: eager start, but its frame is kept alive at completion
// (final_suspend suspends) so the owner can observe done() and reclaim the frame
// deterministically when the Task is destroyed. Move-only; the handle is unique.
// Task frames come from plain ::operator new --- only DetachedTask, the per-drive
// hot path, pools its frames.
//
// Teardown precondition: only destroy a Task once it is done(); the destructor
// release-asserts it. Destroying one whose coroutine is still suspended on an
// in-flight op would free the awaitable that is the kernel's SQE user_data, and
// the later completion would dereference freed memory. Drive it to done() ---
// cancelling the in-flight op first if need be, so it resumes with -ECANCELED and
// the coroutine unwinds --- before letting the Task go.
template <typename T = void> class Task
{
public:
  // Inherits return_value(T) / return_void() from task_return<T>.
  struct promise_type : detail::task_return<T> {
    Task
    get_return_object() noexcept
    {
      return Task{std::coroutine_handle<promise_type>::from_promise(*this)};
    }
    std::suspend_never
    initial_suspend() noexcept
    {
      return {};
    }
    std::suspend_always
    final_suspend() noexcept
    {
      return {};
    }
    // A coroutine driving I/O has no sane way to propagate an exception back to
    // the EThread loop, so the contract is: don't throw out of one.
    void
    unhandled_exception() noexcept
    {
      std::terminate();
    }
  };

  using handle_type = std::coroutine_handle<promise_type>;

  Task() = default;
  explicit Task(handle_type h) : _h(h) {}

  Task(Task &&other) noexcept : _h(std::exchange(other._h, {})) {}
  Task &
  operator=(Task &&other) noexcept
  {
    if (this != &other) {
      if (_h) {
        _h.destroy();
      }
      _h = std::exchange(other._h, {});
    }
    return *this;
  }

  Task(const Task &)            = delete;
  Task &operator=(const Task &) = delete;

  ~Task()
  {
    // A coroutine still suspended on an in-flight op is the kernel's SQE
    // user_data; destroying the frame here would turn the eventual completion
    // into a use-after-free. Crash loudly instead.
    ink_release_assert(!_h || _h.done());
    if (_h) {
      _h.destroy();
    }
  }

  bool
  done() const noexcept
  {
    return _h && _h.done();
  }

  // The co_returned value. Only valid once done() is true. Absent for Task<void>.
  T
  result() const
    requires(!std::is_void_v<T>)
  {
    return _h.promise()._value;
  }

private:
  handle_type _h{};
};

// A single in-flight io_uring operation, awaited from a coroutine. It IS an
// IOUringCompletionHandler, so the existing IOUringContext::service() resumes it.
//
// The awaitable lives in the coroutine frame across the suspension point, so it
// (and any buffer the prep callable references) is pinned for exactly as long as
// the op is in flight. That holds for both ways it is used: a temporary in the
// `co_await UringOp(prep)` full-expression (whose lifetime spans the suspension),
// and a named local awaited as an lvalue (an ordinary frame local --- the form the
// cancel-then-unwind path uses, so the in-flight op stays reachable for cancel).
// This is the structural lifetime guarantee --- no class-scope msghdr hoisting, no
// per-op heap allocation. The prep callable is held by value (templated, not a
// std::function) to keep that allocation-free.
//
// Non-movable on purpose: `this` is registered as the SQE user_data, so the object
// must not relocate after submission. Neither usage needs a move --- the temporary
// is materialized directly into the frame (guaranteed copy elision) and the named
// local never moves --- so the move/copy operations are deleted.
template <typename Prep> class UringOp : public IOUringCompletionHandler
{
public:
  explicit UringOp(Prep prep) : _prep(std::move(prep)) {}

  UringOp(const UringOp &)            = delete;
  UringOp &operator=(const UringOp &) = delete;
  UringOp(UringOp &&)                 = delete;
  UringOp &operator=(UringOp &&)      = delete;

  bool
  await_ready() const noexcept
  {
    return false;
  }

  bool
  await_suspend(std::coroutine_handle<> h) noexcept
  {
    _waiter           = h;
    io_uring_sqe *sqe = IOUringContext::local_context()->next_sqe(this); // user_data = this
    if (sqe == nullptr) {
      // The submission queue is full and could not be flushed. Surface it like a
      // failed syscall rather than suspending forever; resume immediately.
      _result = -ENOBUFS;
      return false;
    }
    _prep(sqe);
    // No submit() here: waitForActivity() flushes the ring once per loop, and
    // next_sqe() auto-flushes a full ring.
    return true;
  }

  int
  await_resume() const noexcept
  {
    return _result;
  }

  // CQE flags from the last completion. For a provided-buffer (IOSQE_BUFFER_SELECT)
  // op, the selected buffer id is `flags() >> IORING_CQE_BUFFER_SHIFT`. Valid after
  // the co_await returns (the awaitable outlives the resume).
  unsigned
  flags() const noexcept
  {
    return _flags;
  }

  void
  handle_complete(io_uring_cqe *cqe) override
  {
    _result = cqe->res; // bytes / accepted-fd on success, -errno (or -ECANCELED) on failure
    _flags  = cqe->flags;
    // Resume on the owning EThread (this CQE drained on the same thread that
    // submitted it). Touch nothing after this: resuming may run the coroutine
    // past the co_await and destroy *this (the awaitable temporary).
    _waiter.resume();
  }

private:
  Prep                    _prep;
  std::coroutine_handle<> _waiter{};
  int                     _result{0};
  unsigned                _flags{0};
};

template <typename Prep> UringOp(Prep) -> UringOp<Prep>;

// A multishot io_uring operation: one submitted SQE that the kernel completes
// repeatedly (multishot accept, multishot recv, multishot poll). Awaited in a
// loop, each co_await yields the next completion; more() reports whether the
// stream is still armed.
//
//   UringMultishotOp stream([&](io_uring_sqe *s){ io_uring_prep_multishot_accept(s, fd, ...); });
//   for (;;) {
//     int res = co_await stream;     // resumes once per CQE
//     if (!stream.more()) break;     // terminal CQE: stream ended (cancel/error)
//     ... use res (a new fd / byte count / -ENOBUFS) ...
//   }
//
// Every CQE the one SQE generates carries this object's `this` as user_data, so
// --- unlike UringOp, which is a temporary spanning a single suspension --- a
// multishot op must be a *named frame local* that outlives the whole stream. The
// kernel keeps the op armed while it sets IORING_CQE_F_MORE on each CQE; the first
// CQE without F_MORE is terminal (the op was cancelled, hit an error, or, for
// recv, exhausted its provided-buffer ring with -ENOBUFS). After a terminal CQE
// the op is disarmed and the next co_await re-arms a fresh SQE, so the same object
// is a reusable stream.
//
// One completion slot, by contract: the awaiting coroutine must consume each
// completion and re-await synchronously, without suspending on another awaitable
// mid-stream. That holds for the net drives (a recv/accept completion is processed
// straight-line --- hand the buffer/fd off, signal the VIO --- then the loop
// re-awaits), and it means a CQE never arrives while the coroutine is parked
// elsewhere, so a single pending result cannot be overwritten. A stream consumed
// concurrently with another suspending await would need a queue sized to the CQ
// depth; that is deliberately out of scope here.
//
// Non-movable for the same reason as UringOp: `this` is the SQE user_data.
template <typename Prep> class UringMultishotOp : public IOUringCompletionHandler
{
public:
  explicit UringMultishotOp(Prep prep) : _prep(std::move(prep)) {}

  UringMultishotOp(const UringMultishotOp &)            = delete;
  UringMultishotOp &operator=(const UringMultishotOp &) = delete;
  UringMultishotOp(UringMultishotOp &&)                 = delete;
  UringMultishotOp &operator=(UringMultishotOp &&)      = delete;

  // Resume without suspending if a completion is already pending (the kernel
  // delivered one before the coroutine came back to await it).
  bool
  await_ready() const noexcept
  {
    return _ready;
  }

  bool
  await_suspend(std::coroutine_handle<> h) noexcept
  {
    _waiter = h;
    if (!_armed) {
      // First await, or re-arming after a terminal CQE.
      io_uring_sqe *sqe = IOUringContext::local_context()->next_sqe(this); // user_data = this
      if (sqe == nullptr) {
        // SQ full and unflushable: surface a terminal error rather than parking
        // forever, mirroring UringOp. _flags stays 0, so more() is false.
        _result = -ENOBUFS;
        _ready  = true;
        return false;
      }
      _prep(sqe);
      _armed = true;
    }
    return true;
  }

  int
  await_resume() noexcept
  {
    _ready = false;
    return _result;
  }

  // Whether the op is still armed (this completion had IORING_CQE_F_MORE). False
  // marks the terminal completion --- stop the loop (or re-await to re-arm).
  bool
  more() const noexcept
  {
    return (_flags & IORING_CQE_F_MORE) != 0;
  }

  // The raw CQE flags of this completion. For a provided-buffer op the selected
  // buffer id is `flags() >> IORING_CQE_BUFFER_SHIFT`.
  unsigned
  flags() const noexcept
  {
    return _flags;
  }

  void
  handle_complete(io_uring_cqe *cqe) override
  {
    _result = cqe->res;
    _flags  = cqe->flags;
    if ((_flags & IORING_CQE_F_MORE) == 0) {
      _armed = false; // kernel ended the multishot; a later co_await re-arms
    }
    _ready = true;
    if (_waiter) {
      // Resume on the owning EThread. Touch nothing after: a terminal CQE may run
      // the coroutine to completion and free the frame that holds *this.
      std::coroutine_handle<> w = std::exchange(_waiter, {});
      w.resume();
    }
  }

private:
  Prep                    _prep;
  std::coroutine_handle<> _waiter{};
  int                     _result{0};
  unsigned                _flags{0};
  bool                    _armed{false};
  bool                    _ready{false};
};

template <typename Prep> UringMultishotOp(Prep) -> UringMultishotOp<Prep>;

} // namespace ts::iouring

#endif // TS_USE_LINUX_IO_URING
