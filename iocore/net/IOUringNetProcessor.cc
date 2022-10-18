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

#include "I_EventProcessor.h"
#include "P_IOUringNet.h"
#include "P_IOUringNetProcessor.h"
#include "P_IOUringNetVConnection.h"
#include "P_Socks.h"
#include "StatPages.h"

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
IOUringNetProcessor::allocate_vc(EThread *)
{
  Debug(TAG, "allocate_vc()");
  return new IOUringNetVConnection();
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
  return new NetAccept(opt);
}