/** @file P_IOUringNet.h

  A net handler for io_uring.

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

#include "I_Continuation.h"
#include "I_EThread.h"
#include "P_UnixNet.h"
#include <liburing.h>

class IOUringNetHandler : public NetHandler
{
public:
  IOUringNetHandler() {}
  // EThread::LoopTailHandler
  void signalActivity() override;
  int waitForActivity(ink_hrtime timeout) override;

  // noncopyable
  IOUringNetHandler(const IOUringNetHandler &) = delete;
  IOUringNetHandler &operator=(const IOUringNetHandler &) = delete;

  struct io_uring ring;
  // number of submissions pending completion
  int pending = 0;
};

void initialize_thread_for_iouring(EThread *thread);