/** @file

  A brief file description

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
#include "IOUringNetAccept.h"
#include "I_Event.h"
#include "tscore/ink_assert.h"
#include <optional>
#include <unordered_set>

static constexpr auto TAG = "io_uring_accept";

static constexpr int queue_depth = 8;
thread_local std::optional<io_uring> ring;
thread_local std::vector<Connection> cons{queue_depth};

IOUringNetAccept::IOUringNetAccept(NetProcessor::AcceptOptions const &opt) : NetAccept(opt) {}

void
IOUringNetAccept::init_accept_loop()
{
  int i, n;
  char thr_name[MAX_THREAD_NAME_LENGTH];
  size_t stacksize;
  if (do_listen(BLOCKING)) {
    return;
  }
  REC_ReadConfigInteger(stacksize, "proxy.config.thread.default.stacksize");
  SET_CONTINUATION_HANDLER(this, &IOUringNetAccept::acceptLoop);

  n = opt.accept_threads;
  // Fill in accept thread from configuration if necessary.
  if (n < 0) {
    REC_ReadConfigInteger(n, "proxy.config.accept_threads");
  }

  if (n > 1) {
    Warning("proxy.config.accept_threads is at most 1 with io_uring enabled.");
    n = 1;
  }

  for (i = 0; i < n; i++) {
    NetAccept *a = (i < n - 1) ? clone() : this;

    // Stick some accepts in there

    snprintf(thr_name, MAX_THREAD_NAME_LENGTH, "[ACCEPT %d:%d]", i, ats_ip_port_host_order(&server.accept_addr));
    eventProcessor.spawn_thread(a, thr_name, stacksize);
    Debug("io_uring_accept", "Created accept thread #%d for port %d", i, ats_ip_port_host_order(&server.accept_addr));
  }
}

static void
queue_accept(int idx)
{
  io_uring_sqe accept_sqe{};
  Debug(TAG, "queueing accept");

  ink_release_assert(idx < queue_depth);
  auto &con   = cons[idx];
  con.addrlen = sizeof(con.addr);
  io_uring_prep_accept(&accept_sqe, 0, &con.addr.sa, &con.addrlen, SOCK_CLOEXEC);
  accept_sqe.user_data = idx;
}

int
IOUringNetAccept::acceptLoop(int event, void *ep)
{
  int ret = 0;
  ink_release_assert(!ring);
  // Create a new iouring
  ring.emplace();
  io_uring_params p{};

  ink_release_assert(ring);
  p.cq_entries = queue_depth;
  ret          = io_uring_queue_init_params(queue_depth, &ring.value(), &p);
  if (ret < 0) {
    Fatal("Failed to initialize io_uring for accept: %s", strerror(-ret));
    return EVENT_ERROR;
  }

  // TODO: use multishot when available
  // TODO: use direct for more efficiency
  for (int i = 0; i < queue_depth; i++) {
    queue_accept(i);
  }
  ret = io_uring_submit(&ring.value());
  if (ret < 0) {
    Fatal("accept: io_uring_submit failed: %s", strerror(-ret));
    return EVENT_ERROR;
  }

  do {
    io_uring_cqe *pcqe = nullptr;
    io_uring_cqe cqe;
    ret = io_uring_wait_cqe(&ring.value(), &pcqe);
    if (ret < 0) {
      Fatal("accept: io_uring_wait_cqe failed: %s", strerror(-ret));
      return EVENT_ERROR;
    }
    ink_assert(pcqe);
    cqe = *pcqe;
    io_uring_cqe_seen(&ring.value(), pcqe);
    auto idx = cqe.user_data;
    queue_accept(idx);
  } while (true);

  ink_release_assert(ring);
  return EVENT_DONE;
}

void
IOUringNetAccept::init_accept_per_thread()
{
}

int
IOUringNetAccept::acceptEvent(int event, void *e)
{
  return EVENT_DONE;
}