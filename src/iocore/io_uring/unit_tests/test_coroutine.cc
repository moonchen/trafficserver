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
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <liburing.h>

using ts::iouring::DetachedTask;
using ts::iouring::Task;
using ts::iouring::UringCancel;
using ts::iouring::UringMultishotOp;
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

// Arms ONE multishot poll on fd and loops, resuming once per readiness edge: each
// time the socket becomes readable the kernel posts another CQE for the same SQE
// (IORING_CQE_F_MORE stays set), so a single co_await object yields a stream of
// completions. The coroutine drains the socket each edge so the next send is a
// fresh edge, and bumps *edges. It stops when a terminal CQE arrives (F_MORE
// cleared --- here, because the op was cancelled), publishing the terminal result.
// The stream object is a named frame local: its `this` is the SQE user_data and it
// must outlive every CQE the one SQE generates.
Task<int>
poll_edges(int fd, IOUringCompletionHandler **publish, int *edges, int *terminal_res)
{
  UringMultishotOp stream([&](io_uring_sqe *s) { io_uring_prep_poll_multishot(s, fd, POLLIN); });
  *publish = &stream;
  for (;;) {
    int res = co_await stream;
    if (!stream.more()) { // terminal CQE: the multishot ended (cancel / error)
      *terminal_res = res;
      break;
    }
    char buf[64];
    while (::recv(fd, buf, sizeof buf, MSG_DONTWAIT) > 0) {}
    ++*edges;
  }
  *publish = nullptr;
  co_return *edges;
}

// Arms ONE multishot recv against a provided-buffer ring (buffer group bgid): the
// kernel picks a buffer from the ring for each arriving message and reports its id
// in the CQE flags. This is the read-path primitive --- recv without a per-op
// buffer handoff. It deliberately does not recycle consumed buffers, so once the
// ring drains the next arrival has nowhere to land and the kernel ends the stream
// with -ENOBUFS: that terminal is the read path's natural backpressure signal.
Task<int>
recv_into_ring(int fd, int bgid, int *count, int *lens, int *bufids, int max, int *terminal_res)
{
  UringMultishotOp stream([&](io_uring_sqe *s) {
    io_uring_prep_recv_multishot(s, fd, nullptr, 0, 0);
    s->buf_group  = bgid;
    s->flags     |= IOSQE_BUFFER_SELECT;
  });
  for (;;) {
    int res = co_await stream;
    if (!stream.more()) { // terminal: -ENOBUFS once the ring is exhausted
      *terminal_res = res;
      break;
    }
    if (*count < max) {
      lens[*count]   = res;
      bufids[*count] = stream.flags() >> IORING_CQE_BUFFER_SHIFT; // ring buffer the kernel chose
    }
    ++*count;
  }
  co_return *count;
}

// Like recv_into_ring, but recycles each consumed buffer straight back to the ring
// (the read path's release-on-drain). A two-buffer ring then serves an unbounded
// stream of messages: this is the steady-state read loop.
Task<int>
recv_recycling(int fd, int bgid, io_uring_buf_ring *br, char (*bufs)[64], unsigned nbuf, int *count, int *lens, int max,
               int *terminal_res)
{
  UringMultishotOp stream([&](io_uring_sqe *s) {
    io_uring_prep_recv_multishot(s, fd, nullptr, 0, 0);
    s->buf_group  = bgid;
    s->flags     |= IOSQE_BUFFER_SELECT;
  });
  for (;;) {
    int res = co_await stream;
    if (!stream.more()) {
      *terminal_res = res;
      break;
    }
    int id = stream.flags() >> IORING_CQE_BUFFER_SHIFT;
    if (*count < max) {
      lens[*count] = res;
    }
    ++*count;
    io_uring_buf_ring_add(br, bufs[id], sizeof bufs[id], id, io_uring_buf_ring_mask(nbuf), 0);
    io_uring_buf_ring_advance(br, 1);
  }
  co_return *count;
}

// Models read backpressure recovery: it does NOT recycle, so the ring drains and
// the next arrival ends the stream with -ENOBUFS. On that terminal it hands every
// buffer back and re-awaits --- which re-arms a fresh multishot recv --- and the
// data that could not land before is then delivered. This is the read path's
// "consumer caught up, resume reading" path.
Task<int>
recv_recovering(int fd, int bgid, io_uring_buf_ring *br, char (*bufs)[64], unsigned nbuf, int *count, int *lens, int max,
                bool *recovered, int *terminal_res)
{
  UringMultishotOp stream([&](io_uring_sqe *s) {
    io_uring_prep_recv_multishot(s, fd, nullptr, 0, 0);
    s->buf_group  = bgid;
    s->flags     |= IOSQE_BUFFER_SELECT;
  });
  for (;;) {
    int res = co_await stream;
    if (!stream.more()) {
      if (res == -ENOBUFS) {
        for (unsigned i = 0; i < nbuf; ++i) {
          io_uring_buf_ring_add(br, bufs[i], sizeof bufs[i], i, io_uring_buf_ring_mask(nbuf), i);
        }
        io_uring_buf_ring_advance(br, nbuf);
        *recovered = true;
        continue; // re-await -> the awaitable re-arms a new recv multishot
      }
      *terminal_res = res;
      break;
    }
    if (*count < max) {
      lens[*count] = res;
    }
    ++*count;
  }
  co_return *count;
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

TEST_CASE("a multishot poll yields one completion per readiness edge, then cancels", "[io_uring][coroutine][multishot]")
{
  IOUringConfig cfg = {.queue_entries = 32};
  IOUringContext::set_config(cfg);

  int sv[2];
  REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

  IOUringCompletionHandler *in_flight = nullptr;
  int                       edges = 0, terminal = 0;

  // Eager-start: by return the coroutine has armed its one multishot-poll SQE.
  Task<int> poller = poll_edges(sv[1], &in_flight, &edges, &terminal);
  REQUIRE(in_flight != nullptr);             // armed and parked on the stream
  IOUringContext::local_context()->submit(); // genuinely in flight before we drive it

  // Three readiness edges from one SQE: each send -> drain -> one multishot CQE.
  for (int edge = 1; edge <= 3; ++edge) {
    REQUIRE(::send(sv[0], "x", 1, 0) == 1);
    REQUIRE(pump_until([&] { return edges == edge; }));
  }
  REQUIRE(!poller.done()); // F_MORE kept the stream armed across all three edges

  // Cancel the still-armed multishot -> terminal CQE (-ECANCELED, F_MORE clear).
  int cancel_res = -1;
  do_cancel(in_flight, &cancel_res);
  REQUIRE(pump_until([&] { return poller.done(); }));

  REQUIRE(poller.result() == 3);   // exactly three edges consumed before the terminal
  REQUIRE(terminal == -ECANCELED); // the stream ended because it was cancelled
  REQUIRE(cancel_res >= 0);        // the cancel op itself was accepted

  ::close(sv[0]);
  ::close(sv[1]);
}

TEST_CASE("multishot recv consumes a provided-buffer ring and ends with -ENOBUFS", "[io_uring][coroutine][multishot]")
{
  IOUringConfig cfg = {.queue_entries = 32};
  IOUringContext::set_config(cfg);
  auto *ur = IOUringContext::local_context();

  int sv[2];
  REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

  // A tiny provided-buffer ring: two 64-byte buffers in buffer group `bgid`.
  constexpr int      bgid = 7;
  constexpr unsigned nbuf = 2; // power of two, required by io_uring_buf_ring_mask
  char               bufs[nbuf][64];
  int                err = 0;
  io_uring_buf_ring *br  = ur->setup_buf_ring(nbuf, bgid, &err);
  REQUIRE(br != nullptr);
  for (unsigned i = 0; i < nbuf; ++i) {
    io_uring_buf_ring_add(br, bufs[i], sizeof bufs[i], i, io_uring_buf_ring_mask(nbuf), i);
  }
  io_uring_buf_ring_advance(br, nbuf);

  int       count = 0, lens[4] = {}, bufids[4] = {}, terminal = 0;
  Task<int> reader = recv_into_ring(sv[1], bgid, &count, lens, bufids, 4, &terminal);
  ur->submit(); // arm the multishot recv before driving it

  // Two messages, separated in time so each is its own CQE; the coroutine does not
  // recycle, so both ring buffers are now consumed.
  REQUIRE(::send(sv[0], "aaa", 3, 0) == 3);
  REQUIRE(pump_until([&] { return count == 1; }));
  REQUIRE(::send(sv[0], "bbbb", 4, 0) == 4);
  REQUIRE(pump_until([&] { return count == 2; }));
  REQUIRE(!reader.done()); // F_MORE kept the recv armed across both

  REQUIRE(lens[0] == 3);
  REQUIRE(lens[1] == 4);
  REQUIRE(bufids[0] != bufids[1]);                      // kernel picked two distinct buffers
  REQUIRE(std::memcmp(bufs[bufids[0]], "aaa", 3) == 0); // and wrote the data into them
  REQUIRE(std::memcmp(bufs[bufids[1]], "bbbb", 4) == 0);

  // Ring is empty: the next arrival has nowhere to land -> -ENOBUFS ends the stream.
  REQUIRE(::send(sv[0], "c", 1, 0) == 1);
  REQUIRE(pump_until([&] { return reader.done(); }));

  REQUIRE(terminal == -ENOBUFS); // backpressure terminal, the read path's stop signal
  REQUIRE(reader.result() == 2); // exactly the two buffered messages were delivered

  ur->free_buf_ring(br, nbuf, bgid);
  ::close(sv[0]);
  ::close(sv[1]);
}

TEST_CASE("multishot recv recycles a small ring to serve more messages than it holds", "[io_uring][coroutine][multishot]")
{
  IOUringConfig cfg = {.queue_entries = 32};
  IOUringContext::set_config(cfg);
  auto *ur = IOUringContext::local_context();

  int sv[2];
  REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

  constexpr int      bgid = 8;
  constexpr unsigned nbuf = 2;
  char               bufs[nbuf][64];
  io_uring_buf_ring *br = ur->setup_buf_ring(nbuf, bgid, nullptr);
  REQUIRE(br != nullptr);
  for (unsigned i = 0; i < nbuf; ++i) {
    io_uring_buf_ring_add(br, bufs[i], sizeof bufs[i], i, io_uring_buf_ring_mask(nbuf), i);
  }
  io_uring_buf_ring_advance(br, nbuf);

  int       count = 0, lens[8] = {}, terminal = 1;
  Task<int> reader = recv_recycling(sv[1], bgid, br, bufs, nbuf, &count, lens, 8, &terminal);
  ur->submit();

  // Five messages through a two-buffer ring: recycling is what keeps it armed.
  const char *msgs[5] = {"a", "bb", "ccc", "dddd", "eeeee"};
  for (int i = 0; i < 5; ++i) {
    REQUIRE(::send(sv[0], msgs[i], i + 1, 0) == i + 1);
    REQUIRE(pump_until([&] { return count == i + 1; }));
    REQUIRE(lens[i] == i + 1);
  }

  // Peer close ends the stream with EOF (res 0, F_MORE clear).
  ::close(sv[0]);
  REQUIRE(pump_until([&] { return reader.done(); }));
  REQUIRE(reader.result() == 5);
  REQUIRE(terminal == 0);

  ur->free_buf_ring(br, nbuf, bgid);
  ::close(sv[1]);
}

TEST_CASE("multishot recv re-arms after -ENOBUFS once the ring is refilled", "[io_uring][coroutine][multishot]")
{
  IOUringConfig cfg = {.queue_entries = 32};
  IOUringContext::set_config(cfg);
  auto *ur = IOUringContext::local_context();

  int sv[2];
  REQUIRE(::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0);

  constexpr int      bgid = 9;
  constexpr unsigned nbuf = 2;
  char               bufs[nbuf][64];
  io_uring_buf_ring *br = ur->setup_buf_ring(nbuf, bgid, nullptr);
  REQUIRE(br != nullptr);
  for (unsigned i = 0; i < nbuf; ++i) {
    io_uring_buf_ring_add(br, bufs[i], sizeof bufs[i], i, io_uring_buf_ring_mask(nbuf), i);
  }
  io_uring_buf_ring_advance(br, nbuf);

  int       count = 0, lens[8] = {}, terminal = 1;
  bool      recovered = false;
  Task<int> reader    = recv_recovering(sv[1], bgid, br, bufs, nbuf, &count, lens, 8, &recovered, &terminal);
  ur->submit();

  // Drain the ring: two messages consume both buffers and are not recycled.
  REQUIRE(::send(sv[0], "a", 1, 0) == 1);
  REQUIRE(pump_until([&] { return count == 1; }));
  REQUIRE(::send(sv[0], "bb", 2, 0) == 2);
  REQUIRE(pump_until([&] { return count == 2; }));

  // A third arrival has no buffer -> -ENOBUFS terminal -> the coroutine refills the
  // ring and re-arms, and only then does this message land.
  REQUIRE(::send(sv[0], "ccc", 3, 0) == 3);
  REQUIRE(pump_until([&] { return count == 3; }));
  REQUIRE(recovered);    // the stream came back from -ENOBUFS
  REQUIRE(lens[2] == 3); // and delivered the message that had triggered it

  ::close(sv[0]);
  REQUIRE(pump_until([&] { return reader.done(); }));
  REQUIRE(terminal == 0); // clean EOF after recovery

  ur->free_buf_ring(br, nbuf, bgid);
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
