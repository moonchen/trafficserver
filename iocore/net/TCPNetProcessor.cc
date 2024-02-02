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

#include "TCPNetProcessor.h"
#include "tscore/TSSystemState.h"
#include "P_SSLNextProtocolAccept.h"

#include "TCPNetVConnection.h"

namespace
{

DbgCtl dbg_ctl_iocore_tcp_processor{"iocore_tcp_processor"};
DbgCtl dbg_ctl_iocore_tcp_accept{"iocore_tcp_accept"};
DbgCtl dbg_ctl_http_tproxy{"http_tproxy"};
DbgCtl dbg_ctl_Socks{"Socks"};

} // end anonymous namespace

// Remove this once NetAccept can use TCPNetVConnection, and unify to
// allocate_vc
static TCPNetVConnection *
allocate_tcp_vc(EThread *t)
{
  TCPNetVConnection *vc;

  if (t) {
    vc = THREAD_ALLOC_INIT(tcpNetVCAllocator, t);
  } else {
    if (likely(vc = tcpNetVCAllocator.alloc())) {
    }
  }

  return vc;
}

Action *
TCPNetProcessor::connect_re(Continuation *cont, sockaddr const *target, NetVCOptions const &opt)
{
  if (TSSystemState::is_event_system_shut_down()) {
    return nullptr;
  }

  EThread *t            = eventProcessor.assign_affinity_by_type(cont, opt.etype);
  TCPNetVConnection *vc = allocate_tcp_vc(t);

  vc->options = opt;

  vc->set_context(NET_VCONNECTION_OUT);
  bool using_socks = (socks_conf_stuff->socks_needed && opt.socks_support != NO_SOCKS);

  // SOCKS is not supported yet
  ink_release_assert(!using_socks);

  vc->id          = net_next_connection_number();
  vc->submit_time = ink_get_hrtime();
  vc->mutex       = cont->mutex;
  Action *result  = &vc->action_;
  // Copy target to con.addr,
  //   then con.addr will copy to vc->remote_addr by set_remote_addr()
  vc->setRemote(target);

  vc->action_ = cont;

  MUTEX_TRY_LOCK(lock, cont->mutex, t);
  if (lock.is_locked()) {
    MUTEX_TRY_LOCK(lock2, get_NetHandler(t)->mutex, t);
    if (lock2.is_locked()) {
      vc->connectUp(t, NO_FD);
      return ACTION_RESULT_DONE;
    }
  }

  t->schedule_imm(vc);
  return result;
}

NetVConnection *
TCPNetProcessor::allocate_vc(EThread *t)
{
  NetVConnection *vc;

  if (t) {
    vc = THREAD_ALLOC_INIT(tcpNetVCAllocator, t);
  } else {
    if (likely(vc = unixNetVCAllocator.alloc())) {
      TCPNetVConnection *tvc  = static_cast<TCPNetVConnection *>(vc);
      tvc->from_accept_thread = true;
    }
  }

  return vc;
}

TCPNetProcessor tcp_netProcessor;
bool net_use_io_uring = false;
