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
#include "tscore/ink_assert.h"
#include <liburing.h>

constexpr auto TAG = "io_uring";

thread_local IOUringNetHandler *inh = nullptr;

void
IOUringNetHandler::signalActivity()
{
}

int
IOUringNetHandler::waitForActivity(ink_hrtime timeout)
{
  struct io_uring_cqe *cqe;

  // In the case when the work queue is empty, an incoming event should
  // send a notification to the ring via eventfd to wake the thread up
  // from this sleep.
  Debug(TAG, "waiting for cqe");
  auto ret = io_uring_wait_cqe(&ring, &cqe);
  if (ret < 0) {
    Warning("io_uring_wait_cqe failed: %s", strerror(-ret));
  } else {
    pending--;
    // TODO: handle completed I/O
    // TODO: break here if new events are scheduled by I/O completion handlers
  }

  return 0;
}

void
initialize_thread_for_iouring(EThread *thread)
{
  ink_release_assert(inh == nullptr);
  inh = new IOUringNetHandler();
  ink_release_assert(inh != nullptr);

  // TODO: replace placeholder values
  const int queue_depth = 1024;
  io_uring_params p{};

  Debug(TAG, "Started io_uring thread");

  auto ret = io_uring_queue_init_params(queue_depth, &inh->ring, &p);
  if (ret < 0) {
    Fatal("Failed to initialize io_uring: %s", strerror(-ret));
    return;
  }

  thread->set_tail_handler(inh);
}