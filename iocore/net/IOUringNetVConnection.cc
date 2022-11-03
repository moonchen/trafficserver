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

#include "I_Continuation.h"
#include "I_NetVConnection.h"
#include "P_IOUringNet.h"
#include "P_IOUringNetVConnection.h"
#include "liburing.h"
#include "tscore/ink_assert.h"
#include <liburing/io_uring.h>

constexpr auto TAG = "io_uring";
static int
get_next_connection_id()
{
  static std::atomic<int> next_connection_id{0};
  return next_connection_id++;
}

IOUringNetVConnection::IOUringNetVConnection() : id(get_next_connection_id()), closed(false)
{
  SET_HANDLER(&IOUringNetVConnection::startEvent);
}

IOUringNetVConnection::~IOUringNetVConnection() {}

int
IOUringNetVConnection::prep_read(int event, Event *e)
{
  ink_assert(thread == this_ethread());
  MUTEX_TRY_LOCK(lock, read_vio.mutex, thread);
  if (!lock.is_locked()) {
    // Reschedule
    SET_HANDLER(&IOUringNetVConnection::prep_read);
    this_ethread()->schedule_imm(this);
    return EVENT_DONE;
  }

  io_uring_sqe *sqe      = io_uring_get_sqe(IOUringNetHandler::get_ring());
  MIOBufferAccessor &buf = read_vio.buffer;
  ink_assert(buf.writer());

  // if there is nothing to do, do nothing
  int64_t ntodo = read_vio.ntodo();
  if (ntodo <= 0) {
    return EVENT_DONE;
  }

  int64_t toread = buf.writer()->write_avail();
  if (toread > ntodo) {
    toread = ntodo;
  }

  // prepare an sqe to read data
  int64_t rattempted = 0, total_read = 0;
  unsigned niov = 0;
  IOVec tiovec[NET_MAX_IOV];
  if (toread) {
    IOBufferBlock *b = buf.writer()->first_write_block();
    niov             = 0;
    rattempted       = 0;
    while (b && niov < NET_MAX_IOV) {
      int64_t a = b->write_avail();
      if (a > 0) {
        tiovec[niov].iov_base = b->_end;
        int64_t togo          = toread - total_read - rattempted;
        if (a > togo) {
          a = togo;
        }
        tiovec[niov].iov_len = a;
        rattempted += a;
        niov++;
        if (a >= togo) {
          break;
        }
      }
      b = b->next.get();
    }

    ink_assert(niov > 0);
    ink_assert(niov <= countof(tiovec));
    struct msghdr msg;

    ink_zero(msg);
    msg.msg_name    = const_cast<sockaddr *>(get_remote_addr());
    msg.msg_namelen = ats_ip_size(get_remote_addr());
    msg.msg_iov     = &tiovec[0];
    msg.msg_iovlen  = niov;

    io_uring_prep_recvmsg(sqe, con.fd, &msg, 0);

    NET_INCREMENT_DYN_STAT(net_calls_to_read_stat);

    total_read += rattempted;
  }
  // TODO: do we queue multiple reads?

  return EVENT_DONE;
}

VIO *
IOUringNetVConnection::do_io_read(Continuation *c, int64_t nbytes, MIOBuffer *buf)
{
  Debug(TAG, "%s", __FUNCTION__);
  ink_assert(thread == this_ethread());

  read_vio.op        = VIO::READ;
  read_vio.mutex     = c ? c->mutex : this->mutex;
  read_vio.cont      = c;
  read_vio.nbytes    = nbytes;
  read_vio.ndone     = 0;
  read_vio.vc_server = this;

  if (buf) {
    read_vio.buffer.writer_for(buf);
  } else {
    // TODO: caller wants to cancel, but read might still be in progress
    read_vio.buffer.clear();
  }

  return &read_vio;
}

VIO *
IOUringNetVConnection::do_io_write(Continuation *c, int64_t nbytes, IOBufferReader *buf, bool owner)
{
  Debug(TAG, "%s", __FUNCTION__);
  return nullptr;
}

void
IOUringNetVConnection::do_io_close(int lerrno)
{
  Debug(TAG, "%s", __FUNCTION__);
}

void
IOUringNetVConnection::do_io_shutdown(ShutdownHowTo_t howto)
{
  Debug(TAG, "%s", __FUNCTION__);
}

void
IOUringNetVConnection::set_active_timeout(ink_hrtime timeout_in)
{
  Debug(TAG, "%s", __FUNCTION__);
}

void
IOUringNetVConnection::set_inactivity_timeout(ink_hrtime timeout_in)
{
  Debug(TAG, "%s", __FUNCTION__);
}

void
IOUringNetVConnection::set_default_inactivity_timeout(ink_hrtime timeout_in)
{
  Debug(TAG, "%s", __FUNCTION__);
}

bool
IOUringNetVConnection::is_default_inactivity_timeout()
{
  Debug(TAG, "%s", __FUNCTION__);
  return false;
}

void
IOUringNetVConnection::cancel_active_timeout()
{
  Debug(TAG, "%s", __FUNCTION__);
}

void
IOUringNetVConnection::cancel_inactivity_timeout()
{
  Debug(TAG, "%s", __FUNCTION__);
}

void
IOUringNetVConnection::add_to_keep_alive_queue()
{
  Debug(TAG, "%s", __FUNCTION__);
}

void
IOUringNetVConnection::remove_from_keep_alive_queue()
{
  Debug(TAG, "%s", __FUNCTION__);
}

bool
IOUringNetVConnection::add_to_active_queue()
{
  Debug(TAG, "%s", __FUNCTION__);
  return true;
}

ink_hrtime
IOUringNetVConnection::get_active_timeout()
{
  Debug(TAG, "%s", __FUNCTION__);
  return 0;
}

ink_hrtime
IOUringNetVConnection::get_inactivity_timeout()
{
  Debug(TAG, "%s", __FUNCTION__);
  return 0;
}

void
IOUringNetVConnection::apply_options()
{
  Debug(TAG, "%s", __FUNCTION__);
}

void
IOUringNetVConnection::reenable(VIO *vio)
{
  Debug(TAG, "%s", __FUNCTION__);
}

void
IOUringNetVConnection::reenable_re(VIO *vio)
{
  Debug(TAG, "%s", __FUNCTION__);
}

SOCKET
IOUringNetVConnection::get_socket()
{
  Debug(TAG, "%s", __FUNCTION__);
  return 0;
}

int
IOUringNetVConnection::set_tcp_congestion_control(int side)
{
  Debug(TAG, "%s", __FUNCTION__);
  return 0;
}

void
IOUringNetVConnection::set_local_addr()
{
  Debug(TAG, "%s", __FUNCTION__);
}

void
IOUringNetVConnection::set_remote_addr()
{
  Debug(TAG, "%s", __FUNCTION__);
}

void
IOUringNetVConnection::set_remote_addr(const sockaddr *)
{
  Debug(TAG, "%s", __FUNCTION__);
}

void
IOUringNetVConnection::set_mptcp_state()
{
  Debug(TAG, "%s", __FUNCTION__);
}

int
IOUringNetVConnection::acceptEvent(int event, Event *e)
{
  Debug(TAG, "%s", __FUNCTION__);
  EThread *t = (e == nullptr) ? this_ethread() : e->ethread;
  thread     = t;

  // Should only be called from the local thread
  ink_assert(this_ethread()->is_event_type(ET_NET));
  mutex = nullptr;

  // Setup a timeout callback handler.
  SET_HANDLER(&IOUringNetVConnection::mainEvent);

  ink_release_assert(action_.continuation);
  if (action_.continuation->mutex != nullptr) {
    MUTEX_TRY_LOCK(lock, action_.continuation->mutex, t);
    if (!lock.is_locked()) {
      // TODO: can this happen?
      ink_release_assert(0);
    }
    action_.continuation->handleEvent(NET_EVENT_ACCEPT, this);
  } else {
    action_.continuation->handleEvent(NET_EVENT_ACCEPT, this);
  }
  return EVENT_DONE;
}

int
IOUringNetVConnection::startEvent(int event, Event *e)
{
  Debug(TAG, "startEvent");
  return EVENT_DONE;
}

int
IOUringNetVConnection::mainEvent(int event, Event *e)
{
  Debug(TAG, "mainEvent");
  return EVENT_DONE;
}
