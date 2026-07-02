/** @file

Linux io_uring helper library

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

#include <liburing.h>
#include <utility>
#include "tscore/ink_hrtime.h"

struct IOUringConfig {
  int queue_entries = 32;
  int sq_poll_ms    = 0;
  int attach_wq     = 0;
  int wq_bounded    = 0;
  int wq_unbounded  = 0;
};

class IOUringCompletionHandler
{
public:
  virtual void handle_complete(io_uring_cqe *) = 0;
};

class IOUringContext
{
public:
  IOUringContext();
  ~IOUringContext();

  IOUringContext(const IOUringContext &) = delete;

  io_uring_sqe *
  next_sqe(IOUringCompletionHandler *handler)
  {
    io_uring_sqe *result = io_uring_get_sqe(&ring);
    if (result == nullptr) {
      submit();
      result = io_uring_get_sqe(&ring);
    }
    if (result != nullptr) {
      io_uring_sqe_set_data(result, handler);
    }
    return result;
  }

  bool supports_op(int op) const;

  int                 set_wq_max_workers(unsigned int bounded, unsigned int unbounded);
  std::pair<int, int> get_wq_max_workers();

  void submit();
  void service();
  void submit_and_wait(ink_hrtime ms);

  int  register_eventfd();
  void disable_eventfd();

  // Provided-buffer ring for a buffer group: the kernel selects a buffer from this
  // ring for each completion of a BUFFER_SELECT op (e.g. multishot recv), removing
  // the per-op buffer handoff. Returns the mapped ring (nullptr on failure, with
  // -errno in *err if non-null); the caller seeds it with io_uring_buf_ring_add /
  // io_uring_buf_ring_advance and recycles consumed buffers the same way.
  io_uring_buf_ring *setup_buf_ring(unsigned entries, int bgid, int *err);
  void               free_buf_ring(io_uring_buf_ring *br, unsigned entries, int bgid);

  // Register a fixed ("registered") buffer region on this ring so send_zc_fixed can DMA
  // from it without a per-send pin/IOMMU-map. Returns 0 on success or -errno. The region
  // becomes registered buffer index 0 on this ring.
  int register_fixed_buffers(void *base, size_t len);

  // Clone the fixed-buffer registration from another ring (IORING_REGISTER_CLONE_BUFFERS): the
  // arena's pinned pages are registered once on a source ring, then shared into this ring's buffer
  // table at the same index, so N rings pin the region 1x instead of N times. Returns 0 on success
  // or -errno (the caller falls back to register_fixed_buffers). src_ring_fd must be a ring that has
  // already registered the region.
  int clone_fixed_buffers(int src_ring_fd);

  // This ring's fd, for publishing as a clone source. Valid only after a successful setup.
  int
  ring_fd() const
  {
    return ring.ring_fd;
  }

  // assigns the global iouring config
  static void            set_config(const IOUringConfig &);
  static IOUringContext *local_context();
  static void            set_main_queue(IOUringContext *);
  static int             get_main_queue_fd();

  bool
  valid()
  {
    return ring.ring_fd > 0;
  }

private:
  io_uring        ring  = {};
  io_uring_probe *probe = nullptr;
  int             evfd  = -1;

  void                 handle_cqe(io_uring_cqe *);
  static IOUringConfig config;
};
