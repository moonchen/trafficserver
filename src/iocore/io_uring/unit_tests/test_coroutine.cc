/** @file

  Unit tests for the io_uring coroutine runtime (Task / UringOp / UringCancel).

  These drive a coroutine over a real per-thread IOUringContext, pumped by hand
  exactly the way NetHandler::waitForActivity pumps it (submit queued SQEs, wait
  for a completion, drain the CQEs which resumes the awaiting coroutine).

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

#include <catch2/catch_test_macros.hpp>

#include "iocore/io_uring/Coroutine.h"
#include "tscore/ink_hrtime.h"

#include <cstring>
#include <sys/socket.h>
#include <unistd.h>
#include <liburing.h>

using ts::iouring::DetachedTask;
using ts::iouring::Task;
using ts::iouring::UringCancel;
using ts::iouring::UringOp;

namespace
{

// Pump THIS thread's io_uring context until `done()` is true or we run out of
// iterations. Mirrors NetHandler::waitForActivity: submit_and_wait flushes the
// queued SQEs, blocks for at least one completion, and drains the CQEs --- which
// calls handle_complete() and resumes the awaiting coroutine. The iteration cap
// turns a hung coroutine into a loud test failure instead of an infinite wait.
template <typename Pred>
bool
pump_until(Pred done, int max_iters = 1000)
{
  auto *ur = IOUringContext::local_context();
  for (int i = 0; i < max_iters && !done(); ++i) {
    ur->submit_and_wait(50 * HRTIME_MSECOND);
  }
  return done();
}

// A server-side coroutine: recv one request, echo it straight back. The buffer
// lives in the coroutine frame, pinned across both suspension points.
Task<>
echo_once(int fd, int *out_recv, int *out_send)
{
  char buf[64];
  *out_recv = co_await UringOp([&](io_uring_sqe *s) { io_uring_prep_recv(s, fd, buf, sizeof buf, 0); });
  if (*out_recv > 0) {
    *out_send = co_await UringOp([&](io_uring_sqe *s) { io_uring_prep_send(s, fd, buf, *out_recv, MSG_NOSIGNAL); });
  }
}

// A fire-and-forget version: same echo, but the frame self-destructs at
// completion. Completion is observed through *done, written just before return.
DetachedTask
echo_once_detached(int fd, bool *done)
{
  char buf[64];
  int  n = co_await UringOp([&](io_uring_sqe *s) { io_uring_prep_recv(s, fd, buf, sizeof buf, 0); });
  if (n > 0) {
    co_await UringOp([&](io_uring_sqe *s) { io_uring_prep_send(s, fd, buf, n, MSG_NOSIGNAL); });
  }
  *done = true;
}

// A value-returning owned coroutine: recv once and hand back the byte count.
Task<int>
recv_count(int fd)
{
  char buf[64];
  int  n = co_await UringOp([&](io_uring_sqe *s) { io_uring_prep_recv(s, fd, buf, sizeof buf, 0); });
  co_return n;
}

// Its destructor flips a flag, so an outside observer can confirm the coroutine
// frame's locals were destroyed --- i.e. the coroutine unwound cleanly.
struct Sentinel {
  bool *destroyed;
  ~Sentinel() { *destroyed = true; }
};

// Arms a recv that will never complete on its own (the peer sends nothing) and
// parks on it, after publishing the in-flight op so an outside caller can cancel
// it. On cancel the recv resumes with -ECANCELED and the coroutine unwinds as
// ordinary straight-line code --- the prototype's cancel-then-unwind, the fix for
// net-iouring's `delete this`-with-an-op-in-flight use-after-free.
Task<int>
cancellable_recv(int fd, IOUringCompletionHandler **publish, bool *sentinel_destroyed)
{
  Sentinel guard{sentinel_destroyed};
  char     buf[64];

  UringOp op([&](io_uring_sqe *s) { io_uring_prep_recv(s, fd, buf, sizeof buf, 0); });
  *publish = &op; // expose the in-flight op (its `this` is the SQE user_data)
  int n    = co_await op;
  *publish = nullptr;
  co_return n;
}

DetachedTask
do_cancel(IOUringCompletionHandler *target, int *cancel_res)
{
  *cancel_res = co_await UringCancel(target);
}

} // namespace

TEST_CASE("coroutine echoes one request over a socketpair", "[io_uring][coroutine]")
{
  IOUringConfig cfg = {.queue_entries = 32};
  IOUringContext::set_config(cfg);

  int sv[2];
  REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

  int recv_n = -1, send_m = -1;

  // Eager-start: by the time echo_once() returns, the coroutine has already armed
  // its recv SQE and suspended.
  Task<> server = echo_once(sv[1], &recv_n, &send_m);

  const char req[] = "ping";
  REQUIRE(::send(sv[0], req, 4, 0) == 4);

  REQUIRE(pump_until([&] { return server.done(); }));

  REQUIRE(recv_n == 4);
  REQUIRE(send_m == 4);

  char echo[64] = {};
  REQUIRE(::recv(sv[0], echo, sizeof echo, 0) == 4);
  REQUIRE(std::memcmp(echo, "ping", 4) == 0);

  ::close(sv[0]);
  ::close(sv[1]);
}

TEST_CASE("an in-flight recv is cancelled and the coroutine unwinds cleanly", "[io_uring][coroutine]")
{
  IOUringConfig cfg = {.queue_entries = 32};
  IOUringContext::set_config(cfg);

  int sv[2];
  REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

  IOUringCompletionHandler *in_flight          = nullptr;
  bool                      sentinel_destroyed = false;

  Task<int> reader = cancellable_recv(sv[1], &in_flight, &sentinel_destroyed);
  REQUIRE(in_flight != nullptr); // armed and parked on the recv

  // Flush the recv to the kernel so it is genuinely in flight before we cancel.
  IOUringContext::local_context()->submit();

  int cancel_res = -1;
  do_cancel(in_flight, &cancel_res);

  REQUIRE(pump_until([&] { return reader.done(); }));

  REQUIRE(reader.result() == -ECANCELED); // the parked recv was cancelled
  REQUIRE(sentinel_destroyed);            // the frame's locals were destroyed (clean unwind)
  REQUIRE(cancel_res >= 0);               // the cancel itself was accepted by the kernel

  ::close(sv[0]);
  ::close(sv[1]);
}

TEST_CASE("a Task<int> hands back its co_returned value", "[io_uring][coroutine]")
{
  IOUringConfig cfg = {.queue_entries = 32};
  IOUringContext::set_config(cfg);

  int sv[2];
  REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

  Task<int> counter = recv_count(sv[1]);

  REQUIRE(::send(sv[0], "abcde", 5, 0) == 5);

  REQUIRE(pump_until([&] { return counter.done(); }));
  REQUIRE(counter.result() == 5);

  ::close(sv[0]);
  ::close(sv[1]);
}

TEST_CASE("a DetachedTask runs to completion and self-cleans", "[io_uring][coroutine]")
{
  IOUringConfig cfg = {.queue_entries = 32};
  IOUringContext::set_config(cfg);

  int sv[2];
  REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

  bool finished = false;
  echo_once_detached(sv[1], &finished); // fire and forget: no handle is kept

  const char req[] = "pong";
  REQUIRE(::send(sv[0], req, 4, 0) == 4);

  REQUIRE(pump_until([&] { return finished; }));

  char echo[64] = {};
  REQUIRE(::recv(sv[0], echo, sizeof echo, 0) == 4);
  REQUIRE(std::memcmp(echo, "pong", 4) == 0);

  ::close(sv[0]);
  ::close(sv[1]);
}
