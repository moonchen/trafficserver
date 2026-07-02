/** @file

  A NetVConnection whose full socket lifecycle is driven by io_uring
  completions instead of epoll readiness.

  IOUringNetVConnection derives from UnixNetVConnection and overrides every
  do_io_* / read / write / connect seam to submit an io_uring op and resume a
  coroutine (driven by the per-thread IOUringContext via the coroutine
  runtime in iocore/io_uring/Coroutine.h) on its completion; epoll plays no
  part once a VC is on this path (see the constructor's ep.syscall = false).
  Selected at accept time by proxy.config.net.io_uring.enabled (see
  UnixNetProcessor::allocate_vc).

  TLS is not converted: SSLNetVConnection still runs the epoll-driven base
  path unchanged, so this class only ever carries plain (non-TLS)
  connections.

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
  //
  // reenable_re routes through the same deferred path rather than the base's
  // synchronous drive: a completion-driven drive coroutine may be mid-loop when a
  // VIO signal it delivers calls reenable_re, and an inline nested drive could arm
  // a second op for the same direction (see the definition).
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

  // Connect to the origin with io_uring instead of a connect(2) syscall. connectUp
  // creates+binds the socket, then _connect submits io_uring_prep_connect (with a
  // linked timeout) and delivers NET_EVENT_OPEN on the success CQE or
  // NET_EVENT_OPEN_FAILED on failure/timeout --- so NET_EVENT_OPEN means the
  // handshake is actually done (the ConnectingEntry write-ready probe is then
  // accurate). A fd handed in by the TS API is already connected; that path
  // delivers NET_EVENT_OPEN synchronously, like the base.
  int connectUp(EThread *t, int fd) override;

  // If an io_uring op is in flight, cancel it and defer teardown until the
  // (cancelled) completion(s) resume the coroutine(s): an in-flight op holds a
  // pointer into this VC, so freeing before the completion is observed is a
  // use-after-free when it later resumes.
  void do_io_close(int lerrno = -1) override;

  // do_io_write(this, 0, nullptr) is the epoll-era "stop writing" a tunnel teardown relies on
  // (e.g. abort_tunnel). On epoll the send is synchronous so it stops immediately; an in-flight
  // io_uring send cannot. Cancel it and mark it abandoned so the resuming _write skips its
  // now-stale consume + signal against the source buffer the caller is about to free. The
  // source blocks stay pinned across the await, so the send itself is always safe regardless.
  VIO *do_io_write(Continuation *c, int64_t nbytes, IOBufferReader *buf, bool owner = false) override;

  // Cancel every in-flight op for a deferred close; returns false (and parks this VC on
  // the per-thread cancel-retry list) if any cancel SQE could not be submitted because
  // the SQ was unflushable. Public so the file-local retry list can link this VC and
  // iouring_drain_pending_cancels can re-drive it.
  bool                   _try_cancel_inflight_ops();
  IOUringNetVConnection *_cancel_retry_next    = nullptr;
  bool                   _cancel_retry_pending = false;

private:
  // The asynchronous read/write/connect coroutines: drive one io_uring op, await
  // it, then signal. Fire-and-forget (DetachedTask); the frame self-cleans at
  // completion.
  ts::iouring::DetachedTask _read();
  ts::iouring::DetachedTask _write();
  ts::iouring::DetachedTask _connect();

  // Read drive (proxy.config.net.io_uring.read_provided_buffers): demand-driven
  // single-shot recv that selects a buffer from a shared per-thread provided-buffer
  // ring (late binding), attaching each kernel-filled buffer to the read MIOBuffer
  // zero-copy (recycled when the consumer releases it). Capped to ntodo; -ENOBUFS is
  // the backpressure signal. Selected in net_read_io.
  ts::iouring::DetachedTask _read_provided();

  // Reimplementations of the file-static read_signal_* / write_signal_* helpers in
  // UnixNetVConnection.cc (not visible here). Same recursion/closed/free contract.
  int _read_signal_and_update(int event);
  int _read_signal_done(int event);
  int _write_signal_and_update(int event);
  int _write_signal_done(int event);

  // Deferred-close completion: free the VC once no io_uring op is still in flight
  // (cancel-then-unwind, see do_io_close).
  void _complete_deferred_close();

  // The in-flight recvmsg / sendmsg / connect ops, reachable for cancellation. Each
  // address is the SQE user_data; non-null only while that op is actually in flight.
  IOUringCompletionHandler *_read_op         = nullptr;
  IOUringCompletionHandler *_write_op        = nullptr;
  IOUringCompletionHandler *_connect_op      = nullptr;
  bool                      _closing         = false;
  int                       _close_errno     = -1;
  bool                      _write_abandoned = false; // do_io_write(null) stopped the write VIO mid-send
  // A single-shot recv that completed while the consumer could not take it (the read was
  // disabled, the VIO had no usable buffer, or the VIO lock was contended): the kernel already
  // pulled the bytes off the socket (destructive, unrecoverable), so the VC owns them until
  // delivery. _held_read_chain is a chain of IOBufferBlock refs over the kernel-filled regions
  // of the recv's destination blocks; the refs keep the underlying IOBufferData alive even if
  // the consumer frees the destination MIOBuffer while the bytes are parked (e.g. a POST-body
  // buffer torn down on an early origin response). _read delivers on re-enable: in place
  // (fill()) when the armed buffer is still the recv's destination with an unmoved write
  // cursor, otherwise attached zero-copy (append_block) to the re-targeted buffer. If the VC
  // is freed first, free_thread drops the refs and the data goes with them.
  Ptr<IOBufferBlock> _held_read_chain;
  int64_t            _held_read_bytes = 0;
  // Identity tag for in-place delivery: the MIOBuffer the recv filled. Compared, never
  // dereferenced --- it may dangle once the consumer frees that buffer.
  MIOBuffer *_held_read_buf = nullptr;
  // The provided-buffer analogue (_read_provided): a buffer-select recv that completed while the
  // read was disabled already pulled bytes off the socket (destructive, unrecoverable). Wrap the
  // kernel-filled ring buffer in a block and hold it here; deliver it to the consumer's buffer when
  // the read re-enables, so the stream behaves as if the bytes had stayed in the socket. If the VC
  // is freed first, the Ptr releases and the ring buffer recycles automatically.
  Ptr<IOBufferBlock> _held_pbuf_block;
  int64_t            _held_pbuf_bytes = 0;
};

extern ClassAllocator<IOUringNetVConnection> ioUringNetVCAllocator;

// Retry deferred-close cancels that could not be submitted when the SQ was full.
// Called from NetHandler::waitForActivity's io_uring branch once the ring has space.
void iouring_drain_pending_cancels();

#endif // TS_USE_LINUX_IO_URING
