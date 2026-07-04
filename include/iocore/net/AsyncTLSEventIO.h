/**@file

   A way to wait for async TLS fds.

 @section license License

   Licensed to the Apache Software
   Foundation(ASF) under one
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

#include "tscore/ink_config.h"

#if TS_USE_TLS_ASYNC

#include "iocore/net/EventIO.h"
#include <span>
#include <openssl/async.h>
#include <openssl/ssl.h>

class AsyncTLSEventCallback
{
public:
  virtual void handle_async_tls_ready() = 0;
  virtual ~AsyncTLSEventCallback()      = default;
};

class AsyncTLSEventIO : public EventIO
{
public:
  AsyncTLSEventIO(AsyncTLSEventCallback &c) : EventIO(), _c(c) {}
  int start(EventLoop l, std::span<OSSL_ASYNC_FD> fds);

  void process_event(int flags) override;

private:
  AsyncTLSEventCallback &_c;
};

#endif // TS_USE_TLS_ASYNC
