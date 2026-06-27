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

#include <sys/eventfd.h>
#include <atomic>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

#include <unistd.h>

#include "iocore/io_uring/IO_URING.h"
#include "tscore/ink_hrtime.h"
#include "tscore/Diags.h"

#include <tsutil/Metrics.h>
using ts::Metrics;

std::atomic<int> main_wq_fd;

namespace
{
DbgCtl dbg_ctl_io_uring{"io_uring"};

} // end anonymous namespace

IOUringConfig IOUringContext::config;

struct IOUringStatsBlock {
  Metrics::Counter::AtomicType *io_uring_submitted;
  Metrics::Counter::AtomicType *io_uring_completed;
};

static IOUringStatsBlock io_uring_rsb = []() {
  return IOUringStatsBlock{Metrics::Counter::createPtr("proxy.process.io_uring.submitted"),
                           Metrics::Counter::createPtr("proxy.process.io_uring.completed")};
}();

void
IOUringContext::set_config(const IOUringConfig &cfg)
{
  config = cfg;
}

static io_uring_probe probe_unsupported             = {};
constexpr int         MAX_SUPPORTED_OP_BEFORE_PROBE = 20;

IOUringContext::IOUringContext()
{
  io_uring_params p{};

  if (config.attach_wq > 0) {
    int wq_fd = get_main_queue_fd();
    if (wq_fd > 0) {
      p.flags = IORING_SETUP_ATTACH_WQ;
      p.wq_fd = wq_fd;
    }
  }

  if (config.sq_poll_ms > 0) {
    p.flags          |= IORING_SETUP_SQPOLL;
    p.sq_thread_idle  = config.sq_poll_ms;
  }

  int ret = io_uring_queue_init_params(config.queue_entries, &ring, &p);
  if (ret < 0) {
    char *err = strerror(-ret);
    Dbg(dbg_ctl_io_uring, "io_uring_queue_init_params failed: (%d) %s", -ret, err);
    ring.ring_fd = -1;
  } else {
    /* no sharing for non-fixed either */
    if (config.sq_poll_ms && !(p.features & IORING_FEAT_SQPOLL_NONFIXED)) {
      Dbg(dbg_ctl_io_uring, "No SQPOLL sharing with nonfixed");
    }
  }

  // Fetch the probe info so we can check for op support
  probe = io_uring_get_probe_ring(&ring);
  if (probe == nullptr) {
    probe = &probe_unsupported;
  }
}

IOUringContext::~IOUringContext()
{
  if (evfd != -1) {
    ::close(evfd);
    evfd = -1;
  }
  if (probe != &probe_unsupported) {
    io_uring_free_probe(probe);
  }
  io_uring_queue_exit(&ring);
}

void
IOUringContext::set_main_queue(IOUringContext *dh)
{
  dh->set_wq_max_workers(config.wq_bounded, config.wq_unbounded);
  main_wq_fd.store(dh->ring.ring_fd);
}

int
IOUringContext::get_main_queue_fd()
{
  return main_wq_fd.load();
}

int
IOUringContext::set_wq_max_workers(unsigned int bounded, unsigned int unbounded)
{
  if (bounded == 0 && unbounded == 0) {
    return 0;
  }
  unsigned int args[2] = {bounded, unbounded};
  int          result  = io_uring_register_iowq_max_workers(&ring, args);
  return result;
}

std::pair<int, int>
IOUringContext::get_wq_max_workers()
{
  unsigned int args[2] = {0, 0};
  io_uring_register_iowq_max_workers(&ring, args);
  return std::make_pair(args[0], args[1]);
}

void
IOUringContext::submit()
{
  Metrics::Counter::increment(io_uring_rsb.io_uring_submitted, io_uring_submit(&ring));
}

void
IOUringContext::handle_cqe(io_uring_cqe *cqe)
{
  auto *op = reinterpret_cast<IOUringCompletionHandler *>(io_uring_cqe_get_data(cqe));

  op->handle_complete(cqe);
}

void
IOUringContext::service()
{
  io_uring_cqe *cqe = nullptr;
  io_uring_peek_cqe(&ring, &cqe);
  while (cqe) {
    handle_cqe(cqe);
    Metrics::Counter::increment(io_uring_rsb.io_uring_completed);
    io_uring_cqe_seen(&ring, cqe);

    cqe = nullptr;
    io_uring_peek_cqe(&ring, &cqe);
  }

  if (evfd != -1) {
    uint64_t val = 0;
    ::read(evfd, &val, sizeof(val));
  }
}

void
IOUringContext::submit_and_wait(ink_hrtime t)
{
  timespec          ts      = ink_hrtime_to_timespec(t);
  __kernel_timespec timeout = {ts.tv_sec, ts.tv_nsec};
  io_uring_cqe     *cqe     = nullptr;

  int count = io_uring_submit_and_wait_timeout(&ring, &cqe, 1, &timeout, nullptr);

  Metrics::Counter::increment(io_uring_rsb.io_uring_submitted, count);
  while (cqe) {
    handle_cqe(cqe);
    Metrics::Counter::increment(io_uring_rsb.io_uring_completed);
    io_uring_cqe_seen(&ring, cqe);

    cqe = nullptr;
    io_uring_peek_cqe(&ring, &cqe);
  }
}

int
IOUringContext::register_eventfd()
{
  if (evfd == -1) {
    evfd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);

    io_uring_register_eventfd(&ring, evfd);
  }
  return evfd;
}

void
IOUringContext::disable_eventfd()
{
  // When the net thread blocks directly in io_uring_enter (submit_and_wait), the
  // completion eventfd --- registered only to bridge io_uring completions into an
  // epoll wait --- is dead weight: io_uring still eventfd_signal()s it on every CQE
  // for a waiter that no longer exists. Unregister and close it so that overhead is
  // gone. The fd is auto-removed from any epoll set on close (it is never polled).
  if (evfd != -1) {
    io_uring_unregister_eventfd(&ring);
    ::close(evfd);
    evfd = -1;
  }
}

io_uring_buf_ring *
IOUringContext::setup_buf_ring(unsigned entries, int bgid, int *err)
{
  // liburing 2.4 lacks the io_uring_setup_buf_ring/io_uring_free_buf_ring
  // convenience wrappers (added in 2.5), so allocate the page-aligned ring
  // ourselves and register it. The ring is entries * sizeof(io_uring_buf), and
  // entries must be a power of two (io_uring_register_buf_ring requires it).
  auto fail = [err](int e) -> io_uring_buf_ring * {
    if (err != nullptr) {
      *err = e;
    }
    return nullptr;
  };

  std::size_t ring_size = entries * sizeof(io_uring_buf);
  void       *ring_mem  = nullptr;
  if (posix_memalign(&ring_mem, sysconf(_SC_PAGESIZE), ring_size) != 0) {
    return fail(-ENOMEM);
  }

  io_uring_buf_ring *br = static_cast<io_uring_buf_ring *>(ring_mem);
  io_uring_buf_ring_init(br);

  io_uring_buf_reg reg = {};
  reg.ring_addr        = reinterpret_cast<__u64>(br);
  reg.ring_entries     = entries;
  reg.bgid             = bgid;
  if (int ret = io_uring_register_buf_ring(&ring, &reg, 0); ret != 0) {
    ::free(ring_mem);
    return fail(ret);
  }

  if (err != nullptr) {
    *err = 0;
  }
  return br;
}

void
IOUringContext::free_buf_ring(io_uring_buf_ring *br, unsigned /* entries */, int bgid)
{
  io_uring_unregister_buf_ring(&ring, bgid);
  ::free(br);
}

int
IOUringContext::register_fixed_buffers(void *base, size_t len)
{
  struct iovec iov {
    base, len
  };
  return io_uring_register_buffers(&ring, &iov, 1);
}

IOUringContext *
IOUringContext::local_context()
{
  thread_local IOUringContext threadContext;

  return &threadContext;
}

bool
IOUringContext::supports_op(int op) const
{
  // If we don't have a probe, we can only support the ops that were supported
  // before the probe was added.
  if (probe == &probe_unsupported) {
    return op <= MAX_SUPPORTED_OP_BEFORE_PROBE;
  }

  return io_uring_opcode_supported(probe, op);
}
