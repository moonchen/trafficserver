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

#include "tscore/ink_config.h"

#if TS_USE_TLS_ASYNC

#include "iocore/net/AsyncTLSEventIO.h"

int
AsyncTLSEventIO::start(EventLoop l, std::span<OSSL_ASYNC_FD> fds)
{
  for (OSSL_ASYNC_FD fd : fds) {
    int ret = start_common(l, fd, EVENTIO_READ);
    if (ret != 0) {
      return ret;
    }
  }
  return 0;
}

void
AsyncTLSEventIO::process_event(int)
{
  // According to OpenSSL docs:
  // A completed operation will result in data appearing as "read ready" on the file descriptor
  // (no actual data should be read from the file descriptor)
  _c.handle_async_tls_ready();
}

#endif // TS_USE_TLS_ASYNC
