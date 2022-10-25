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

constexpr auto TAG = "iouring";
static int
get_next_connection_id()
{
  static std::atomic<int> next_connection_id{0};
  return next_connection_id++;
}

IOUringNetVConnection::IOUringNetVConnection() : id(get_next_connection_id())
{
  SET_HANDLER(&IOUringNetVConnection::startEvent);
}

IOUringNetVConnection::~IOUringNetVConnection() {}

VIO *
IOUringNetVConnection::do_io_read(Continuation *c, int64_t nbytes, MIOBuffer *buf)
{
  return nullptr;
}

VIO *
IOUringNetVConnection::do_io_write(Continuation *c, int64_t nbytes, IOBufferReader *buf, bool owner)
{
  return nullptr;
}

void
IOUringNetVConnection::do_io_close(int lerrno)
{
}

void
IOUringNetVConnection::do_io_shutdown(ShutdownHowTo_t howto)
{
}

void
IOUringNetVConnection::set_active_timeout(ink_hrtime timeout_in)
{
}

void
IOUringNetVConnection::set_inactivity_timeout(ink_hrtime timeout_in)
{
}

void
IOUringNetVConnection::set_default_inactivity_timeout(ink_hrtime timeout_in)
{
}

bool
IOUringNetVConnection::is_default_inactivity_timeout()
{
  return false;
}

void
IOUringNetVConnection::cancel_active_timeout()
{
}

void
IOUringNetVConnection::cancel_inactivity_timeout()
{
}

void
IOUringNetVConnection::add_to_keep_alive_queue()
{
}

void
IOUringNetVConnection::remove_from_keep_alive_queue()
{
}

bool
IOUringNetVConnection::add_to_active_queue()
{
  return true;
}

ink_hrtime
IOUringNetVConnection::get_active_timeout()
{
  return 0;
}

ink_hrtime
IOUringNetVConnection::get_inactivity_timeout()
{
  return 0;
}

void
IOUringNetVConnection::apply_options()
{
}

void
IOUringNetVConnection::reenable(VIO *vio)
{
}

void
IOUringNetVConnection::reenable_re(VIO *vio)
{
}

SOCKET
IOUringNetVConnection::get_socket()
{
  return 0;
}

int
IOUringNetVConnection::set_tcp_congestion_control(int side)
{
  return 0;
}

void
IOUringNetVConnection::set_local_addr()
{
}

void
IOUringNetVConnection::set_remote_addr()
{
}

void
IOUringNetVConnection::set_remote_addr(const sockaddr *)
{
}

void
IOUringNetVConnection::set_mptcp_state()
{
}

int
IOUringNetVConnection::acceptEvent(int event, Event *e)
{
  EThread *t = (e == nullptr) ? this_ethread() : e->ethread;
  thread     = t;

  // Should only be called from the local thread
  ink_assert(this_ethread()->is_event_type(ET_NET));

  // TODO: queue io_uring for reading and writing
  auto sqe = io_uring_get_sqe(&IOUringNetHandler::get_NetHandler().ring);
  if (sqe == nullptr) {
    Fatal("ring size is too small!");
    return EVENT_ERROR;
  }
  // io_uring_prep_read(sqe, fd, buf, nbytes, offset);

  // Setup a timeout callback handler.
  SET_HANDLER(&IOUringNetVConnection::mainEvent);

  ink_release_assert(action_.continuation);
  if (action_.continuation->mutex != nullptr) {
    MUTEX_TRY_LOCK(lock3, action_.continuation->mutex, t);
    if (!lock3.is_locked()) {
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
