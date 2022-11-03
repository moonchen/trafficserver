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
#include "P_IOUringNetVConnection.h"
#include "P_Net.h"
#include "tscore/ink_assert.h"
#include <liburing.h>
#include <optional>
#include <unordered_set>
#include "I_IO_URING.h"

static constexpr auto TAG = "io_uring_accept";

// Number of sq entries for accept threads
static constexpr int queue_depth = 1;
// Ring for accept threads
static thread_local std::optional<io_uring> ring;
// Connection buffers for accept thread
static thread_local std::vector<Connection> cons{queue_depth};

IOUringNetAccept::IOUringNetAccept(NetProcessor::AcceptOptions const &opt) : NetAccept(opt), connections(queue_depth) {}

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
  SET_CONTINUATION_HANDLER(this, &IOUringNetAccept::acceptLoopEvent);

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

    snprintf(thr_name, MAX_THREAD_NAME_LENGTH, "[IOU_AC %d %d]", i, ats_ip_port_host_order(&server.accept_addr));
    eventProcessor.spawn_thread(a, thr_name, stacksize);
    Debug("io_uring_accept", "Created accept thread #%d for port %d", i, ats_ip_port_host_order(&server.accept_addr));
  }
}

static void
queue_accept(int fd, int idx)
{
  io_uring_sqe *accept_sqe = nullptr;
  Debug(TAG, "queueing accept: fd = %d, idx = %d", fd, idx);

  ink_release_assert(idx < queue_depth);
  auto &con   = cons[idx];
  con.addrlen = sizeof(con.addr);

  accept_sqe = io_uring_get_sqe(&ring.value());
  ink_release_assert(accept_sqe != nullptr);
  io_uring_prep_accept(accept_sqe, fd, &con.addr.sa, &con.addrlen, SOCK_CLOEXEC);
  io_uring_sqe_set_data64(accept_sqe, idx);
}

void
IOUringNetAccept::safe_delay(int msec)
{
  // TODO: determine if this delay is needed in io_uring.  It may only be needed for syscall accept.
}

int
IOUringNetAccept::acceptLoopEvent(int event, void *ep)
{
  int ret    = 0;
  EThread *t = this_ethread();
  bool stop  = false;

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
    queue_accept(server.fd, i);
  }

  do {
    ret = io_uring_submit(&ring.value());
    if (ret < 0) {
      Fatal("accept: io_uring_submit failed: %s", strerror(-ret));
      return EVENT_ERROR;
    }
    io_uring_cqe *pcqe = nullptr;
    io_uring_cqe cqe;
    ret = io_uring_wait_cqe(&ring.value(), &pcqe);
    if (ret == -EINTR) {
      Debug(TAG, "accept: iouring_wait_cqe interrupted by signal.");
      continue;
    } else if (ret < 0) {
      Fatal("accept: io_uring_wait_cqe failed: %s", strerror(-ret));
      return EVENT_ERROR;
    }
    ink_assert(pcqe);
    cqe = *pcqe;
    io_uring_cqe_seen(&ring.value(), pcqe);
    auto idx        = io_uring_cqe_get_data64(pcqe);
    Connection &con = cons[idx];

    char buf[INET6_ADDRSTRLEN];
    ats_ip_ntop(con.addr, buf, sizeof buf);
    Debug(TAG, "Accepted a connection %s:%u.", buf, con.addr.host_order_port());
    stop = process_accept(cqe.res, t, con);
    queue_accept(server.fd, idx);
  } while (!stop);
  Warning("Accept loop stopped!");

  ink_release_assert(ring);
  return EVENT_DONE;
}

int
IOUringNetAccept::accept_startup(int, void *)
{
  IOUringContext *ctx = IOUringContext::local_context();
  if (do_listen(BLOCKING)) {
    return 1;
  }

  for (auto &con : connections) {
    con.conn.addrlen = sizeof(con.conn.addr);
    con.na           = this;
    auto *sqe        = ctx->next_sqe(&con);

    ink_release_assert(sqe != nullptr);
    io_uring_prep_accept(sqe, server.fd, &con.conn.addr.sa, &con.conn.addrlen, SOCK_CLOEXEC);
  }
  return 0;
}

void
IOUringNetAccept::init_accept_per_thread()
{
  int i, n;

  SET_HANDLER(&IOUringNetAccept::accept_startup);
  n = eventProcessor.thread_group[opt.etype]._count;

  for (i = 0; i < n; i++) {
    IOUringNetAccept *na;
    na  = new IOUringNetAccept(opt);
    *na = *this;
    SET_CONTINUATION_HANDLER(na, &IOUringNetAccept::accept_startup);

    EThread *t = eventProcessor.thread_group[opt.etype]._thread[i];
    // shouldnt need a mutex for
    // a->mutex     = get_NetHandler(t)->mutex;
    t->schedule_imm(na);
  }
}

int
IOUringNetAccept::acceptEvent(int event, void *e)
{
  return EVENT_DONE;
}

void
IOUringNetAccept::initialize_vc(NetVConnection *_vc, Connection &con, EThread *localt)
{
  IOUringNetVConnection *vc = dynamic_cast<IOUringNetVConnection *>(_vc);
  ink_release_assert(vc != nullptr);

  NET_SUM_GLOBAL_DYN_STAT(net_connections_currently_open_stat, 1);
  vc->con.move(con);
  vc->set_remote_addr(con.addr);
  vc->action_ = *action_;
  vc->set_is_transparent(opt.f_inbound_transparent);
  vc->set_is_proxy_protocol(opt.f_proxy_protocol);
  vc->options.sockopt_flags        = opt.sockopt_flags;
  vc->options.packet_mark          = opt.packet_mark;
  vc->options.packet_tos           = opt.packet_tos;
  vc->options.packet_notsent_lowat = opt.packet_notsent_lowat;
  vc->options.ip_family            = opt.ip_family;
  vc->apply_options();
  vc->set_context(NET_VCONNECTION_IN);
  if (opt.f_mptcp) {
    vc->set_mptcp_state(); // Try to get the MPTCP state, and update accordingly
  }
  vc->accept_object = this;

  SET_CONTINUATION_HANDLER(vc, &IOUringNetVConnection::acceptEvent);

  // TODO: Does vc need the mutex from its NetProcessor?
}
void
IOUringNetAccept::handle_complete(io_uring_cqe *sqe)
{
}
void
IOUringAcceptConnection::handle_complete(io_uring_cqe *cqe)
{
  IOUringContext *ctx = IOUringContext::local_context();

  char buf[INET6_ADDRSTRLEN];
  ats_ip_ntop(conn.addr, buf, sizeof buf);
  Debug(TAG, "Accepted a connection %s:%u with fd %d.", buf, conn.addr.host_order_port(), conn.fd);

  auto stop = na->process_accept(cqe->res, this_ethread(), conn);

  if (!stop) {
    auto *sqe = ctx->next_sqe(this);
    ink_release_assert(sqe != nullptr);
    io_uring_prep_accept(sqe, na->server.fd, &conn.addr.sa, &conn.addrlen, SOCK_CLOEXEC);
  }
}
