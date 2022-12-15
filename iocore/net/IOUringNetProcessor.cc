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

#include "I_Action.h"
#include "I_EventProcessor.h"
#include "I_NetVConnection.h"
#include "P_IOUringNet.h"
#include "P_IOUringNetProcessor.h"
#include "P_IOUringNetVConnection.h"
#include "P_Socks.h"
#include "StatPages.h"
#include "IOUringNetAccept.h"
#include "tscore/ink_assert.h"

constexpr auto TAG = "io_uring";
IOUringNetProcessor ioUringNetProcessor;

#if TS_USE_LINUX_IO_URING
NetProcessor &netProcessor = ioUringNetProcessor;
#endif

IOUringNetProcessor::IOUringNetProcessor() {}

IOUringNetProcessor::~IOUringNetProcessor() {}

void
IOUringNetProcessor::init()
{
  EventType etype = ET_NET;

  if (0 == accept_mss) {
    REC_ReadConfigInteger(accept_mss, "proxy.config.net.sock_mss_in");
  }

  // NetHandler - do the global configuration initialization and then
  // schedule per thread start up logic. Global init is done only here.
  NetHandler::init_for_process();
  NetHandler::active_thread_types[ET_NET] = true;
  eventProcessor.schedule_spawn(&initialize_thread_for_iouring, etype);

  RecData d;
  d.rec_int = 0;
  change_net_connections_throttle(nullptr, RECD_INT, d, nullptr);

  /*
   * Stat pages
   */
  extern Action *register_ShowNet(Continuation * c, HTTPHdr * h);
  if (etype == ET_NET) {
    statPagesManager.register_http("net", register_ShowNet);
  }
}

NetVConnection *
IOUringNetProcessor::allocate_vc(EThread *) const
{
  Debug(TAG, "allocate_vc()");
  auto vc                = new IOUringNetVConnection();
  vc->from_accept_thread = true;
  return vc;
}

int
IOUringNetProcessor::stop()
{
  Debug(TAG, "stop()");
  return 0;
}

NetAccept *
IOUringNetProcessor::createNetAccept(NetProcessor::AcceptOptions const &opt)
{
  // TODO:
  Debug(TAG, "createNetAccept()");
  return new IOUringNetAccept(opt);
}

Action *
IOUringNetProcessor::connect(Continuation *cont, sockaddr const *target, NetVCOptions *opt)
{
  if (TSSystemState::is_event_system_shut_down()) {
    return nullptr;
  }

  ink_release_assert(opt);
  EThread *t = eventProcessor.assign_affinity_by_type(cont, opt->etype);
  auto vc    = dynamic_cast<IOUringNetVConnection *>(allocate_vc(t));

  ink_release_assert(vc);
  vc->options = *opt;
  vc->set_context(NET_VCONNECTION_OUT);

  // TODO: SOCKS
  vc->mutex      = cont->mutex;
  Action *result = &vc->action_;
  vc->con.setRemote(target);
  vc->action_ = cont;

  MUTEX_TRY_LOCK(lock, cont->mutex, t);
  if (lock.is_locked()) {
    auto ret = vc->connectUp(t, NO_FD);
    if (ret != CONNECT_SUCCESS) {
      Error("connect: connectUp failed");
      return ACTION_IO_ERROR;
    }
    return result;
  }

  // Try to open later
  t->schedule_imm(vc);

  return result;
}
