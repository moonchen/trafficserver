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

#include "P_IOUringNetProcessor.h"
#include "P_NetAccept.h"
#include "P_IOUringNetProcessor.h"
#include "I_EThread.h"
#include "liburing.h"
#include "I_IO_URING.h"

class IOUringAcceptConnection : public IOUringCompletionHandler
{
public:
  IOUringAcceptConnection() = default;
  IOUringAcceptConnection(const IOUringAcceptConnection &other)
  {
    conn.addr    = other.conn.addr;
    conn.addrlen = other.conn.addrlen;
  }
  virtual ~IOUringAcceptConnection() = default;

  void handle_complete(io_uring_cqe *) override;

  IOUringAcceptConnection &
  operator=(const IOUringAcceptConnection &other)
  {
    conn.addr    = other.conn.addr;
    conn.addrlen = other.conn.addrlen;
    return *this;
  }

  Connection conn;
};

class IOUringNetAccept : public NetAccept, public IOUringCompletionHandler
{
public:
  IOUringNetAccept(NetProcessor::AcceptOptions const &opt);
  void init_accept_loop() override;
  void init_accept_per_thread() override;

  NetProcessor *
  getNetProcessor() const override
  {
    return &ioUringNetProcessor;
  }

  int accept_startup(int, void *);

  void handle_complete(io_uring_cqe *) override;

protected:
  void safe_delay(int msec) override;
  void initialize_vc(NetVConnection *_vc, Connection &con, EThread *localt) override;

private:
  // Runfunc for an accept thread
  int acceptLoopEvent(int event, void *ep);

  // Handler for per-thread accepts
  int acceptEvent(int event, void *ep) override;

  std::vector<IOUringAcceptConnection> connections;
};
