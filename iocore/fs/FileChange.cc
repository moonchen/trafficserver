/** @file FileChange.cc

  Watch for file system changes.

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

#include "FileChange.h"
#include "tscore/Diags.h"

// Globals
FileChangeManager fileChangeManager;
static constexpr int EPOLL_EVENTS_MAX = 1000;

#if TS_USE_EPOLL
static void
epoll_thread(int epoll_fd)
{
  struct epoll_event events[EPOLL_EVENTS_MAX];
  for (;;) {
    int rc = epoll_wait(epoll_fd, events, EPOLL_EVENTS_MAX, -1);
    if (rc == -1) {
      Error("File change notify thread epoll error: %d", errno);
      if (errno != EINTR) {
        break;
      }
    }
    for (int i = 0; i < rc; i++) {
      struct epoll_event *event = &events[i];
      // TODO: process event
    }
  }
}
#else
// Implement this
#endif

void
FileChangeManager::init()
{
#if TS_USE_EPOLL
  epoll_fd    = epoll_create1(FD_CLOEXEC);
  poll_thread = std::thread(epoll_thread, epoll_fd);
  poll_thread.detach();
#else
  // Implement this
  Warning("File change notification is not supported for this OS".);
#endif
}
