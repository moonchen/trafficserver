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

#pragma once
#include "I_NetProcessor.h"
#include "P_UnixNetProcessor.h"

class TCPNetVConnection;

//////////////////////////////////////////////////////////////////
//
//  class TCPNetProcessor
//
//////////////////////////////////////////////////////////////////
struct TCPNetProcessor : public UnixNetProcessor {
public:
  Action *connect_re(Continuation *cont, sockaddr const *addr, NetVCOptions const &opts) override;
  NetVConnection *allocate_vc(EThread *t) override;
};

extern TCPNetProcessor tcp_netProcessor;

//
// Set up a thread to receive events from the NetProcessor
// This function should be called for all threads created to
// accept such events by the EventProcessor.
//
extern void initialize_thread_for_net(EThread *thread);
extern bool net_use_io_uring;
