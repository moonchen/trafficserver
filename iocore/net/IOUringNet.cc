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
#include "I_IO_URING.h"
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
  if (thread != nullptr && thread->evfd != ts::NO_FD) {
    auto ret = write(thread->evfd, &counter, sizeof counter);
    Debug(TAG, "signalActivity on fd=%d returned %zu", thread->evfd, ret);
    if (ret < 0) {
      Warning("io_uring: failed to write to event fd");
    }
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
  IOUringContext *ur = IOUringContext::local_context();

  ur->submit_and_wait(timeout);
  return 0;
}

void
initialize_thread_for_iouring(EThread *thread)
{
  ink_release_assert(!inh);
  inh.emplace();
  ink_release_assert(inh);

  thread->set_tail_handler(&inh.value());
}
