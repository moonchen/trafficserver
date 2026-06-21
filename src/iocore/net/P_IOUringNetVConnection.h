/** @file

  A NetVConnection whose socket I/O is (incrementally) moved onto io_uring.

  IOUringNetVConnection derives from UnixNetVConnection and, for now, is a
  behavioral clone of it: every do_io_* / read / write path is inherited
  unchanged. Pieces are then swapped to io_uring (driven by the per-thread
  IOUringContext via the coroutine runtime in iocore/io_uring/Coroutine.h) one
  at a time, so each step is independently testable against the inherited
  baseline. Selected at accept time by proxy.config.net.io_uring.enabled (see
  UnixNetProcessor::allocate_vc).

  This mirrors how SSLNetVConnection derives from UnixNetVConnection and
  overrides only the seams it needs (net_read_io, load_buffer_and_write,
  do_io_close).

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

#include "P_UnixNetVConnection.h"
#include "iocore/io_uring/Coroutine.h"

class IOUringNetVConnection : public UnixNetVConnection
{
  using super = UnixNetVConnection;

public:
  IOUringNetVConnection()           = default;
  ~IOUringNetVConnection() override = default;

  // Return the object to this subclass's own allocator. The base's free_thread
  // hardcodes netVCAllocator, which is sized/typed for UnixNetVConnection.
  void free_thread(EThread *t) override;

  // The read path is driven by io_uring instead of a synchronous recvmsg on
  // epoll readiness: net_read_io submits an asynchronous recvmsg and returns;
  // the completion (drained by IOUringContext::service() on this EThread) fills
  // the buffer and signals the VIO. The epoll-readiness trigger is reused as-is.
  void net_read_io(NetHandler *nh) override;

  // If a recvmsg is in flight, cancel it and defer teardown until the (cancelled)
  // completion resumes the read coroutine --- freeing now would resume into a
  // freed `this` (the net-iouring branch's use-after-free).
  void do_io_close(int lerrno = -1) override;

private:
  // The asynchronous read: builds the iovec from the read VIO buffer, awaits one
  // io_uring recvmsg, then fills + signals. Fire-and-forget (DetachedTask); its
  // frame self-cleans at completion.
  ts::iouring::DetachedTask _read();

  // Reimplementations of the file-static read_signal_* helpers in
  // UnixNetVConnection.cc (not visible here). Same recursion/closed/free contract.
  int _read_signal_and_update(int event);
  int _read_signal_done(int event);

  // The in-flight recvmsg op, reachable for cancellation. Its address is the SQE
  // user_data; non-null only while a recv is actually in flight.
  IOUringCompletionHandler *_read_op          = nullptr;
  bool                      _read_closing     = false;
  int                       _read_close_errno = -1;
};

extern ClassAllocator<IOUringNetVConnection> ioUringNetVCAllocator;

#endif // TS_USE_LINUX_IO_URING
