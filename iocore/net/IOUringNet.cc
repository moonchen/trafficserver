/** @file IOUringNet

  Implementation of io_uring net handler.

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
#include "P_IOUringNet.h"
#include "P_IOUringNetVConnection.h"
#include "tscore/Diags.h"
#include "tscore/ink_assert.h"
#include <optional>
#include <liburing.h>

constexpr auto TAG = "io_uring";

// Only has value on net threads
thread_local std::optional<IOUringNetHandler> inh;

IOUringNetHandler &
IOUringNetHandler::get_NetHandler()
{
  return inh.value();
}

struct io_uring *
IOUringNetHandler::get_ring()
{
  return &inh->ring;
}

int
IOUringNetHandler::startRead(IOUringNetVConnection *vc)
{
  auto sqe = io_uring_get_sqe(&ring);
  if (sqe == nullptr) {
    Fatal("ring size is too small!");
    return EVENT_ERROR;
  }
  // io_uring_prep_read(sqe, vc->con.fd, buf, nbytes, offset);
  return 0;
}

void
IOUringNetHandler::signalActivity()
{
  static uint64_t counter = 1;
  auto ret                = write(thread->evfd, &counter, sizeof counter);
  Debug(TAG, "signalActivity on fd=%d returned %zu", thread->evfd, ret);
  if (ret < 0) {
    Warning("io_uring: failed to write to event fd");
  }
}

static void
prep_eventfd_read(struct io_uring *ring, EThread *thread)
{
  static thread_local uint64_t counter; // There is only one outstanding eventfd read per ring
  auto sqe = io_uring_get_sqe(ring);
  if (sqe) {
    io_uring_prep_read(sqe, thread->evfd, &counter, sizeof counter, -1);
    io_uring_sqe_set_data64(sqe, 0);
    Debug(TAG, "reading eventfd, fd=%d", thread->evfd);
  } else {
    Fatal("prep_eventfd_read: Could not get an SQE");
  }
}

int
IOUringNetHandler::waitForActivity(ink_hrtime timeout)
{
  struct io_uring_cqe *cqe;
  ink_release_assert(this_thread() == thread);

  // In the case when the work queue is empty, an incoming event should
  // send a notification to the ring via eventfd to wake the thread up
  // from this sleep.
  Debug(TAG, "waiting for cqe");
  auto ret = io_uring_submit(&ring);
  if (ret < 0) {
    Warning("Failed to io_uring_submit: %s", strerror(-ret));
  }
  ret = io_uring_wait_cqe(&ring, &cqe);
  if (ret < 0) {
    Warning("io_uring_wait_cqe failed: %s", strerror(-ret));
  } else {
    // pending--;
    // TODO: handle completed I/O
    // TODO: break here if new events are scheduled by I/O completion handlers
    Debug(TAG, "processing cqes");
    while (io_uring_peek_cqe(&ring, &cqe) == 0) {
      Debug(TAG, "cqe->res = %d", cqe->res);
      if (io_uring_cqe_get_data64(cqe) == 0) {
        // eventfd
        Debug(TAG, "Read from eventfd:");
        prep_eventfd_read(&ring, thread);
      }
      io_uring_cqe_seen(&ring, cqe);
    }
  }

  return 0;
}

void
initialize_thread_for_iouring(EThread *thread)
{
  ink_release_assert(!inh);
  inh.emplace();
  ink_release_assert(inh);

  // TODO: replace placeholder values
  const int queue_depth = 1024;
  io_uring_params p{};

  Debug(TAG, "Started io_uring thread");

  auto ret = io_uring_queue_init_params(queue_depth, &inh->ring, &p);
  if (ret < 0) {
    Fatal("Failed to initialize io_uring: %s", strerror(-ret));
    return;
  }
  inh->thread = thread;
  prep_eventfd_read(&inh->ring, thread);

  thread->set_tail_handler(&inh.value());
}
