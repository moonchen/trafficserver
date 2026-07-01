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

  // Connect to the origin with io_uring instead of a connect(2) syscall. connectUp
  // creates+binds the socket, then _connect submits io_uring_prep_connect (with a
  // linked timeout) and delivers NET_EVENT_OPEN on the success CQE or
  // NET_EVENT_OPEN_FAILED on failure/timeout --- so NET_EVENT_OPEN means the
  // handshake is actually done (the ConnectingEntry write-ready probe is then
  // accurate). A fd handed in by the TS API is already connected; that path
  // delivers NET_EVENT_OPEN synchronously, like the base.
  int connectUp(EThread *t, int fd) override;

  // If an io_uring op is in flight, cancel it and defer teardown until the
  // (cancelled) completion(s) resume the coroutine(s) --- freeing now would
  // resume into a freed `this` (the net-iouring branch's use-after-free).
  void do_io_close(int lerrno = -1) override;

  // do_io_write(this, 0, nullptr) is the epoll-era "stop writing" a tunnel teardown relies on
  // (e.g. abort_tunnel). On epoll the send is synchronous so it stops immediately; an in-flight
  // io_uring send cannot. Cancel it and mark it abandoned so the resuming _write skips its
  // now-stale consume + signal against the source buffer the caller is about to free. The
  // source blocks stay pinned across the await, so the send itself is always safe regardless.
  VIO *do_io_write(Continuation *c, int64_t nbytes, IOBufferReader *buf, bool owner = false) override;

  // Re-targeting a read to a DIFFERENT buffer while a recv is in flight (e.g. the origin
  // keep-alive pool re-arm onto the session read_buffer, while a chunked read-ahead recv is still
  // filling the tunnel body buffer) records a redirect; _read copies the recv's bytes into the
  // new buffer when it completes, rather than mis-placing them (a fill through the new buffer
  // would expose its stale bytes) or losing them. A SAME-buffer re-arm while a recv is in flight
  // is routine (the keep-alive teardown re-arms the session's single read_buffer while its
  // abort-watch recv is still pending) and needs no redirect. do_io_read(c,0,nullptr), the
  // disable/pause, keeps buf==nullptr and is handled by holding the recv (see _read).
  VIO *do_io_read(Continuation *c, int64_t nbytes, MIOBuffer *buf) override;

  // Re-arm a multishot read that parked on -ENOBUFS (shared ring exhausted). Called
  // by the file-local read buffer ring when a buffer recycles. Public so the ring can
  // reach it; _rbuf_* are the ring's intrusive wait-list bookkeeping for this VC.
  void                   rearm_read_for_buffers();
  IOUringNetVConnection *_rbuf_wait_next = nullptr;
  bool                   _rbuf_waiting   = false;

  // Cancel every in-flight op for a deferred close; returns false (and parks this VC on
  // the per-thread cancel-retry list) if any cancel SQE could not be submitted because
  // the SQ was unflushable. Public so the file-local retry list can link this VC and
  // iouring_drain_pending_cancels can re-drive it, mirroring _rbuf_*.
  bool                   _try_cancel_inflight_ops();
  IOUringNetVConnection *_cancel_retry_next    = nullptr;
  bool                   _cancel_retry_pending = false;

  // Recv coalescing (T3.4, "pass-through send-ZC"): set SO_RCVLOWAT so reads return only once a large
  // contiguous chunk is buffered, and mark reads to use IORING_RECVSEND_POLL_FIRST (without which
  // io_uring's inline non-blocking recv ignores SO_RCVLOWAT). The recv is NOT zero-copy; paired with an
  // arena-backed read buffer, the coalesced chunk just becomes large enough to SEND as send_zc_fixed.
  void set_recv_coalesce(int64_t min_bytes) override;

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
  // A recv that completed while the read was disabled: its bytes are already in _held_read_buf
  // (written by the kernel, not yet fill()'d). Held here and delivered when the read re-enables,
  // so a disabled read produces no signal (the epoll contract) and no pulled bytes are lost.
  MIOBuffer *_held_read_buf   = nullptr;
  int64_t    _held_read_bytes = 0;
  // The provided-buffer analogue (_read_provided): a buffer-select recv that completed while the
  // read was disabled already pulled bytes off the socket (destructive, unrecoverable). Wrap the
  // kernel-filled ring buffer in a block and hold it here; deliver it to the consumer's buffer when
  // the read re-enables, so the stream behaves as if the bytes had stayed in the socket. If the VC
  // is freed first, the Ptr releases and the ring buffer recycles automatically.
  Ptr<IOBufferBlock> _held_pbuf_block;
  int64_t            _held_pbuf_bytes    = 0;
  MIOBuffer         *_read_inflight_buf  = nullptr; // buffer the in-flight recv is filling
  MIOBuffer         *_read_redirect_buf  = nullptr; // do_io_read re-targeted mid-recv: copy the recv's bytes here on resume
  bool               _recv_poll_first    = false;   // arm reads with IORING_RECVSEND_POLL_FIRST
  int64_t            _recv_coalesce_size = 0;       // SO_RCVLOWAT target for coalesced reads
  int                _recv_lowat_cur     = 0;       // last SO_RCVLOWAT we set (redundant-call guard)
};

extern ClassAllocator<IOUringNetVConnection> ioUringNetVCAllocator;

// Retry deferred-close cancels that could not be submitted when the SQ was full.
// Called from NetHandler::waitForActivity's io_uring branch once the ring has space.
void iouring_drain_pending_cancels();

#endif // TS_USE_LINUX_IO_URING
