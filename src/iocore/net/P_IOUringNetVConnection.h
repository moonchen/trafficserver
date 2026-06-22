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
  // Disable epoll for this VC: both directions are driven by io_uring
  // completions, which need no readiness signal. ep.syscall == false makes
  // EventIO::start/modify/stop no-ops, so startIO never registers the fd with
  // epoll and no epoll edge ever fires for it (the same opt-out QUIC uses).
  IOUringNetVConnection() { ep.syscall = false; }
  ~IOUringNetVConnection() override = default;

  // Return the object to this subclass's own allocator. The base's free_thread
  // hardcodes netVCAllocator, which is sized/typed for UnixNetVConnection.
  void free_thread(EThread *t) override;

  // Re-arm via the io_uring path. With epoll off, nothing sets read/write
  // .triggered (that was the epoll edge); an io_uring VC is always "armable"
  // (no readiness to wait for), so mark triggered before delegating. The base
  // reenable then enqueues us to the ready/enable list, which drives
  // net_read_io / net_write_io --- with no epoll edge involved.
  void reenable(VIO *vio) override;
  void reenable_re(VIO *vio) override;

  // The read path is driven by io_uring instead of a synchronous recvmsg on
  // epoll readiness: net_read_io submits an asynchronous recvmsg and returns;
  // the completion (drained by IOUringContext::service() on this EThread) fills
  // the buffer and signals the VIO.
  void net_read_io(NetHandler *nh) override;

  // Symmetric to net_read_io: submit an asynchronous sendmsg and return; the
  // completion consumes the reader and signals the write VIO.
  void net_write_io(NetHandler *nh) override;

  // If a recvmsg and/or sendmsg is in flight, cancel it and defer teardown until
  // the (cancelled) completion(s) resume the coroutine(s) --- freeing or clearing
  // the I/O buffers now would corrupt an op the kernel still owns.
  void do_io_close(int lerrno = -1) override;

private:
  // The asynchronous read/write coroutines: build the iovec from the VIO buffer,
  // await one io_uring recvmsg/sendmsg, then fill/consume + signal. Fire-and-forget
  // (DetachedTask); the frame self-cleans at completion.
  ts::iouring::DetachedTask _read();
  ts::iouring::DetachedTask _write();

  // Reimplementations of the file-static read_signal_* / write_signal_* helpers in
  // UnixNetVConnection.cc (not visible here). Same recursion/closed/free contract.
  int _read_signal_and_update(int event);
  int _read_signal_done(int event);
  int _write_signal_and_update(int event);
  int _write_signal_done(int event);

  // The real teardown (the base free_thread body): close the fd, clear, and return
  // the VC to the allocator. Deferred until no io_uring op is in flight, since an
  // op's completion resumes a coroutine that touches `this` and its buffers.
  void _do_free(EThread *t);

  // The in-flight recvmsg / sendmsg ops, reachable for cancellation. Each address
  // is the SQE user_data; non-null only while that op is actually in flight.
  IOUringCompletionHandler *_read_op  = nullptr;
  IOUringCompletionHandler *_write_op = nullptr;
  // Teardown was requested while an op was in flight; the last op completion to
  // observe both ops drained runs _do_free. _freed guards against a double free.
  bool _want_free = false;
  bool _freed     = false;
};

extern ClassAllocator<IOUringNetVConnection> ioUringNetVCAllocator;

#endif // TS_USE_LINUX_IO_URING
