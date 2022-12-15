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
#include "P_IOUringNetVConnection.h"
#include "P_UnixNet.h"
#include <liburing.h>

class IOUringWakeUpAlarm : public IOUringCompletionHandler
{
public:
  IOUringWakeUpAlarm(EThread *thread) : _thread(thread) { prep_eventfd_read(); }

  void prep_eventfd_read();
  void handle_complete(io_uring_cqe *) override;

  std::string
  id() const override
  {
    return "wakeup";
  }

private:
  const EThread *_thread;
};

class IOUringNetHandler : public NetHandler
{
public:
  IOUringNetHandler(EThread *thread) : _alarm{thread} { this->thread = thread; }

  // EThread::LoopTailHandler
  void signalActivity() override;
  int waitForActivity(ink_hrtime timeout) override;

  // noncopyable
  IOUringNetHandler(const IOUringNetHandler &) = delete;
  IOUringNetHandler &operator=(const IOUringNetHandler &) = delete;

  static IOUringNetHandler &get_NetHandler();

private:
  IOUringWakeUpAlarm _alarm;
};

void initialize_thread_for_iouring(EThread *thread);
