/** @file

  An io_uring accept path: each ET_NET thread accepts on its own ring with
  io_uring_prep_accept (single-shot + throttle-gated re-arm), so the accepted VC
  stays thread-local (no cross-thread hand-off). Selected by
  proxy.config.net.io_uring.enabled (see UnixNetProcessor::createNetAccept).

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

#include "tscore/ink_config.h"

#if TS_USE_LINUX_IO_URING

#include "P_NetAccept.h"
#include "iocore/io_uring/IO_URING.h"

#include <netinet/in.h>

// Accepts via io_uring instead of accept4(2). Cloned per ET_NET thread (like the
// per-thread accept path); each clone keeps one accept in flight on its own ring
// and re-arms after handling the completion, checking the accept throttle each
// time (single-shot, so the gate is honored --- unlike a multishot accept).
struct IOUringNetAccept : public NetAccept, public IOUringCompletionHandler {
  explicit IOUringNetAccept(const NetProcessor::AcceptOptions &opt) : NetAccept(opt) {}

  NetAccept *clone() const override;
  int        accept_per_thread(int event, void *e) override;
  void       handle_complete(io_uring_cqe *cqe) override;

private:
  void _submit_accept();    // arm one io_uring accept on this thread's ring
  int  _retry(int, void *); // re-arm trampoline when the SQ is momentarily full

  sockaddr_storage _peer{};                  // peer address filled by the accept
  socklen_t        _peerlen = sizeof(_peer); // in/out, reset before each submit
};

#endif // TS_USE_LINUX_IO_URING
