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

constexpr auto TAG = "io_uring";

IOUringNetProcessor::IOUringNetProcessor() {}

IOUringNetProcessor::~IOUringNetProcessor() {}

void
IOUringNetProcessor::init()
{
  // TODO: accept_mss

  // TODO: Similar to NetHandler::init_for_process(), read configs

  // TODO: change_net_connections_throttle

  // TODO: stats
}

int
IOUringNetProcessor::start(int threads, size_t stacksize)
{
  if (threads <= 0) {
    return 0;
  }

  auto ET_IOURING = eventProcessor.register_event_type("ET_IOURING");
  // TODO: NetHandler::active_thread_types[ET_IOURING] = true;

  eventProcessor.schedule_spawn(initialize_thread_for_iouring, ET_IOURING);
  eventProcessor.spawn_event_threads(ET_IOURING, threads, stacksize);
  return 0;
}

void
IOUringNetProcessor::init_socks()
{
  if (!netProcessor.socks_conf_stuff) {
    socks_conf_stuff = new socks_conf_struct;
    loadSocksConfiguration(socks_conf_stuff);
    if (!socks_conf_stuff->socks_needed && socks_conf_stuff->accept_enabled) {
      Warning("We can not have accept_enabled and socks_needed turned off"
              " disabling Socks accept\n");
      socks_conf_stuff->accept_enabled = 0;
    } else {
      // this is sslNetprocessor
      socks_conf_stuff = netProcessor.socks_conf_stuff;
    }
  }
}

Action *
IOUringNetProcessor::accept(Continuation *cont, NetProcessor::AcceptOptions const &opt)
{
  Debug(TAG, "accept()");
  return nullptr;
}

Action *
IOUringNetProcessor::main_accept(Continuation *cont, SOCKET listen_socket_in, NetProcessor::AcceptOptions const &opt)
{
  Debug(TAG, "main_accept()");
  return nullptr;
}

void
IOUringNetProcessor::stop_accept()
{
  Debug(TAG, "stop_accept()");
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

IOUringNetProcessor ioUringNetProcessor;