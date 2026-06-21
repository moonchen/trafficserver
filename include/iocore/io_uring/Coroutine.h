/** @file

  A minimal C++20 coroutine runtime for the per-thread io_uring context.

  This is the in-tree descendant of the standalone coroutine net spike under
  experiments/coro-net-prototype/. It provides just enough to drive an io_uring
  operation from a coroutine that is suspended and resumed on its owning EThread,
  reusing the existing IOUringContext (one ring per net thread, already pumped by
  NetHandler::waitForActivity) --- no new thread and no new event loop.

  Three pieces:
    - Task<T> / DetachedTask: coroutine return types (owned vs. fire-and-forget).
    - UringOp:    an awaitable that *is* an IOUringCompletionHandler. It submits a
                  caller-prepared SQE to this thread's ring and resumes the
                  awaiting coroutine from handle_complete() with the CQE result.
    - UringCancel: cancels an in-flight op (io_uring_prep_cancel) so a connection
                  can drain it before teardown (cancel-then-unwind).

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

#include <cerrno>
#include <coroutine>
#include <type_traits>
#include <utility>

namespace ts::iouring
{

namespace detail
{
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
//
// Teardown precondition: only destroy a Task once it is done(). Destroying one
// whose coroutine is still suspended on an in-flight op would free the awaitable
// that is the kernel's SQE user_data, and the later completion would dereference
// freed memory. Drive it to done() --- or cancel-then-unwind (see UringCancel) and
// then drive to done() --- before letting the Task go.
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
      _res = -ENOBUFS;
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
    return _res;
  }

  void
  handle_complete(io_uring_cqe *cqe) override
  {
    _res = cqe->res; // bytes / accepted-fd on success, -errno (or -ECANCELED) on failure
    // Resume on the owning EThread (this CQE drained on the same thread that
    // submitted it). Touch nothing after this: resuming may run the coroutine
    // past the co_await and destroy *this (the awaitable temporary).
    _waiter.resume();
  }

private:
  Prep                    _prep;
  std::coroutine_handle<> _waiter{};
  int                     _res{0};
};

template <typename Prep> UringOp(Prep) -> UringOp<Prep>;

// Cancels an in-flight UringOp by submitting io_uring_prep_cancel keyed on the
// target op's SQE user_data (which is the target UringOp's `this`). The kernel
// completes the *original* op with -ECANCELED; the coroutine awaiting it resumes
// and unwinds. This awaitable resumes when the cancel SQE itself completes
// (res 0 = found, -ENOENT = not found, -EALREADY = already completing).
//
// Unlike the standalone prototype, which tagged the cancel SQE with a sentinel
// user_data and filtered it out, here the cancel SQE must carry a real
// IOUringCompletionHandler: IOUringContext::service() calls handle_complete() on
// every CQE's user_data unconditionally, so a sentinel would be dereferenced.
class UringCancel : public IOUringCompletionHandler
{
public:
  explicit UringCancel(IOUringCompletionHandler *target) : _target(target) {}

  UringCancel(const UringCancel &)            = delete;
  UringCancel &operator=(const UringCancel &) = delete;
  UringCancel(UringCancel &&)                 = delete;
  UringCancel &operator=(UringCancel &&)      = delete;

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
      _res = -ENOBUFS;
      return false;
    }
    io_uring_prep_cancel(sqe, _target, 0);
    return true;
  }

  int
  await_resume() const noexcept
  {
    return _res;
  }

  void
  handle_complete(io_uring_cqe *cqe) override
  {
    _res = cqe->res;
    _waiter.resume();
  }

private:
  IOUringCompletionHandler *_target;
  std::coroutine_handle<>   _waiter{};
  int                       _res{0};
};

} // namespace ts::iouring

#endif // TS_USE_LINUX_IO_URING
