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
#include "I_Net.h"
#include "I_NetProcessor.h"
#include "I_SessionAccept.h"
#include "tscore/ink_config.h"

//////////////////////////////////////////////////////////////////
//
//  class IOUringNetProcessor
//
//////////////////////////////////////////////////////////////////
struct IOUringNetProcessor : public NetProcessor {
public:
  IOUringNetProcessor();
  ~IOUringNetProcessor() override;

  // NetProcessor
  void init() override;
  void init_socks() override;
  Action *accept(Continuation *cont, AcceptOptions const &opt = DEFAULT_ACCEPT_OPTIONS) override;
  Action *main_accept(Continuation *cont, SOCKET listen_socket_in, AcceptOptions const &opt = DEFAULT_ACCEPT_OPTIONS) override;
  void stop_accept() override;
  NetVConnection *allocate_vc(EThread *) override;

  // Processor
  int start(int threads, size_t stacksize) override;

private:
  int stop() override;
};

// Singleton
extern IOUringNetProcessor ioUringNetProcessor;

extern int ET_IOURING;