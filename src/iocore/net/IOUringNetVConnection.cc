/** @file

  IOUringNetVConnection implementation. See P_IOUringNetVConnection.h.

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

#include "tscore/ink_config.h"

#if TS_USE_LINUX_IO_URING

#include "P_IOUringNetVConnection.h"
#include "P_Net.h"
#include "P_UnixNet.h"

#include "iocore/net/NetHandler.h"
#include "iocore/eventsystem/EThread.h"

#include "tscore/InkErrno.h"
#include "records/RecCore.h"

#include "tsutil/Metrics.h"

using ts::Metrics;

// Global
ClassAllocator<IOUringNetVConnection> ioUringNetVCAllocator("ioUringNetVCAllocator");

// Inline iovec capacity for the read/write coroutines. Unlike the base
// UnixNetVConnection --- whose IOVec tiovec[NET_MAX_IOV] (NET_MAX_IOV == UIO_MAXIOV
// == 1024 -> 16 KB) is a stack local reused at a fixed, cache-warm address every
// call --- these iovecs live in the heap coroutine frame, pinned across the await.
// Sizing them at 1024 would make every frame ~16 KB (4 pages), so each pooled
// frame cycled per op thrashes cache/dTLB. A cache-hit response is 1-2 blocks, so
// a small inline count covers the hot path; a larger buffer just sends fewer
// blocks per op and loops (a short "write"/"read" is already handled). 16 entries
// keep the frame near 300 B.
static constexpr unsigned IOU_FRAME_IOV = 16;

namespace
{
// Counts closes that had an io_uring op in flight and so deferred the free until
// the cancelled op's completion (the cancel-then-unwind path, INV-L2). A nonzero
// value means the UAF-prevention path is being exercised.
Metrics::Counter::AtomicType *deferred_close_stat = Metrics::Counter::createPtr("proxy.process.net.io_uring.vc_deferred_close");

} // namespace

namespace
{
// The cancel SQE needs a real completion handler, because IOUringContext::service()
// dispatches handle_complete() on every CQE's user_data. We do not care about the
// cancel's own result --- the original recv resumes the read coroutine with
// -ECANCELED --- so this one is a no-op.
struct NoopCompletion : public IOUringCompletionHandler {
  void
  handle_complete(io_uring_cqe *) override
  {
  }
};
NoopCompletion noop_completion;

// Submit an async cancel for an in-flight op (keyed on its SQE user_data); the
// op then completes with -ECANCELED and resumes its coroutine. No-op if null.
void
cancel_in_flight(IOUringCompletionHandler *op)
{
  if (op == nullptr) {
    return;
  }
  io_uring_sqe *sqe = IOUringContext::local_context()->next_sqe(&noop_completion);
  if (sqe != nullptr) {
    io_uring_prep_cancel(sqe, op, 0);
  }
}
} // namespace

void
IOUringNetVConnection::free_thread(EThread *t)
{
  // Teardown can reach free_thread (via NetHandler::free_netevent) from paths that
  // bypass our do_io_close override --- notably an inactivity/active timeout, which
  // the inherited mainEvent routes through the base file-static read/write_signal
  // helpers. If an io_uring op is still in flight here, a coroutine is suspended on
  // it and will resume into a freed VC (a use-after-free; ASan is blind because VCs
  // go to a ClassAllocator freelist, not malloc/free --- run with -F to surface it).
  // Defer: cancel the ops and let the resuming coroutine free via
  // _complete_deferred_close, exactly as the do_io_close-driven path does.
  if (_read_op != nullptr || _write_op != nullptr || _connect_op != nullptr) {
    if (!_closing) {
      _closing = true;
      cancel_in_flight(_read_op);
      cancel_in_flight(_write_op);
      cancel_in_flight(_connect_op);
    }
    return;
  }

  // A faithful copy of UnixNetVConnection::free_thread, differing only in the
  // allocator the object is returned to. The base hardcodes netVCAllocator, so
  // it cannot be reused for a differently-typed subclass without corrupting that
  // freelist.
  ink_release_assert(t == this_ethread());

  // close socket fd
  if (con.sock.is_ok()) {
    release_inbound_connection_tracking();
    Metrics::Gauge::decrement(net_rsb.connections_currently_open);
  }
  con.close();

  if (is_tunnel_endpoint()) {
    Metrics::Gauge::decrement(([&]() -> Metrics::Gauge::AtomicType * {
      switch (get_context()) {
      case NET_VCONNECTION_IN:
        return net_rsb.tunnel_current_client_connections_blind_tcp;
      case NET_VCONNECTION_OUT:
        return net_rsb.tunnel_current_server_connections_blind_tcp;
      default:
        ink_release_assert(false);
      }
    })());
  }

  clear();
  SET_CONTINUATION_HANDLER(this, &IOUringNetVConnection::startEvent);
  ink_assert(!con.sock.is_ok());
  ink_assert(t == this_ethread());

  // Return to the global allocator directly. Unlike UnixNetVConnection, this
  // subclass has no per-thread ProxyAllocator member on Thread, so it does not
  // use THREAD_FREE; the global ClassAllocator is itself thread-safe.
  ioUringNetVCAllocator.free(this);
}

// Reimplementations of the file-static read_signal_and_update / read_signal_done
// in UnixNetVConnection.cc (not visible here). Identical recursion/closed/free
// contract: the +/- recursion bracketing the upcall is what lets a do_io_close
// fired from inside the upcall defer the free to here.
int
IOUringNetVConnection::_read_signal_and_update(int event)
{
  this->recursion++;
  if (this->read.vio.cont && this->read.vio.mutex == this->read.vio.cont->mutex) {
    this->read.vio.cont->handleEvent(event, &this->read.vio);
  } else {
    if (this->read.vio.cont) {
      Note("_read_signal_and_update: mutexes are different? vc=%p, event=%d", this, event);
    }
    switch (event) {
    case VC_EVENT_EOS:
    case VC_EVENT_ERROR:
    case VC_EVENT_ACTIVE_TIMEOUT:
    case VC_EVENT_INACTIVITY_TIMEOUT:
      this->closed = 1;
      break;
    default:
      Error("Unexpected event %d for vc %p", event, this);
      ink_release_assert(0);
      break;
    }
  }
  // Free on the recursion unwind only when nothing is in flight. If an io_uring op
  // is still outstanding (e.g. a do_io_close fired from inside this read signal
  // while a sendmsg is pending), defer: that op's completion frees via
  // _complete_deferred_close once the kernel is done with the VC.
  if (!--this->recursion && this->closed && _read_op == nullptr && _write_op == nullptr) {
    ink_assert(this->thread == this_ethread());
    this->nh->free_netevent(this);
    return EVENT_DONE;
  }
  return EVENT_CONT;
}

int
IOUringNetVConnection::_read_signal_done(int event)
{
  this->read.enabled = 0;
  if (_read_signal_and_update(event) == EVENT_DONE) {
    return EVENT_DONE;
  }
  readReschedule(this->nh);
  return EVENT_CONT;
}

void
IOUringNetVConnection::reenable(VIO *vio)
{
  // io_uring is always armable (no readiness to wait for), so stand in for the
  // epoll edge that would otherwise set this. The base then enqueues us to the
  // ready/enable list, driving net_read_io / net_write_io.
  (vio == &read.vio ? read : write).triggered = 1;
  super::reenable(vio);
}

void
IOUringNetVConnection::reenable_re(VIO *vio)
{
  (vio == &read.vio ? read : write).triggered = 1;
  super::reenable_re(vio);
}

void
IOUringNetVConnection::net_read_io(NetHandler *nh)
{
  // A recv is already in flight; its completion continues reading. Don't start a
  // second one for the same VC.
  if (_read_op != nullptr) {
    nh->read_ready_list.remove(this);
    return;
  }

  // _read() does its own locking, drains the socket, and re-arms or disables.
  _read();

  // If a recv is now in flight, keep epoll from re-entering us until it completes.
  if (_read_op != nullptr) {
    nh->read_ready_list.remove(this);
  }
}

ts::iouring::DetachedTask
IOUringNetVConnection::_read()
{
  NetState   *s  = &this->read;
  NetHandler *nh = this->nh;

  // Read until a short read (socket has no more data right now), a full read
  // buffer (backpressure), or the read VIO is satisfied/disabled. A full recvmsg
  // (filled the iovec) may mean more is buffered, so loop; a short recvmsg means
  // the socket is drained and we re-arm (the next recv waits in the kernel for
  // new data --- no epoll, no readiness round-trip).
  for (;;) {
    // tiovec and msg live in this coroutine frame, pinned across the await for the
    // lifetime of the in-flight recvmsg (the structural lifetime guarantee).
    IOVec         tiovec[IOU_FRAME_IOV];
    struct msghdr msg;
    int           fd         = this->con.sock.get_fd();
    int64_t       rattempted = 0;

    // Build the next read request under the VIO mutex.
    {
      MUTEX_TRY_LOCK(lock, s->vio.mutex, this->thread);
      if (!lock.is_locked()) {
        readReschedule(nh);
        co_return;
      }
      if (this->closed) {
        nh->free_netevent(this);
        co_return;
      }
      if (!s->enabled || s->vio.op != VIO::READ || s->vio.is_disabled()) {
        read_disable(nh, this);
        co_return;
      }
      if (s->vio.ntodo() <= 0) {
        read_disable(nh, this);
        co_return;
      }
      MIOBufferAccessor &buf = s->vio.buffer;
      if (buf.writer() == nullptr || buf.writer()->write_avail() <= 0) {
        // Buffer full: stop. reenable() re-arms us once the consumer drains.
        read_disable(nh, this);
        co_return;
      }
      int64_t toread = buf.writer()->write_avail();
      if (toread > s->vio.ntodo()) {
        toread = s->vio.ntodo();
      }
      unsigned       niov = 0;
      IOBufferBlock *b    = buf.writer()->first_write_block();
      while (b && niov < IOU_FRAME_IOV) {
        int64_t a = b->write_avail();
        if (a > 0) {
          tiovec[niov].iov_base = b->end();
          int64_t togo          = toread - rattempted;
          if (a > togo) {
            a = togo;
          }
          tiovec[niov].iov_len  = a;
          rattempted           += a;
          niov++;
          if (a >= togo) {
            break;
          }
        }
        b = b->next.get();
      }
      if (niov == 0) {
        read_disable(nh, this);
        co_return;
      }
      ink_zero(msg);
      msg.msg_name    = const_cast<sockaddr *>(this->get_remote_addr());
      msg.msg_namelen = ats_ip_size(this->get_remote_addr());
      msg.msg_iov     = &tiovec[0];
      msg.msg_iovlen  = niov;
    }

    // Submit one recvmsg and suspend. No lock is held across the await. (A read is
    // almost always a genuine wait for the next request --- on keep-alive the next
    // request is not yet in the socket --- so an opportunistic non-blocking recvmsg
    // here just wastes a syscall on EAGAIN before falling back to this. Measured
    // net-negative; the read stays purely io_uring-driven.)
    // A single-block read (the common case: a request header fits in one block)
    // needs no msghdr --- recv is lighter in the kernel than recvmsg (no msghdr
    // copy, no peer-address fill-back on a connected socket).
    ts::iouring::UringOp op([&](io_uring_sqe *sqe) {
      if (msg.msg_iovlen == 1) {
        io_uring_prep_recv(sqe, fd, msg.msg_iov[0].iov_base, msg.msg_iov[0].iov_len, 0);
      } else {
        io_uring_prep_recvmsg(sqe, fd, &msg, 0);
      }
    });
    _read_op = &op;
    int r    = co_await op;
    _read_op = nullptr;

    // do_io_close deferred teardown to us (it cancelled this recv). Free once no
    // op is in flight (a sendmsg may still be outstanding), then stop touching `this`.
    if (_closing) {
      _complete_deferred_close();
      co_return;
    }

    // Fill + signal under the VIO mutex.
    {
      MUTEX_TRY_LOCK(lock, s->vio.mutex, this->thread);
      if (!lock.is_locked()) {
        readReschedule(nh);
        co_return;
      }
      if (this->closed) {
        nh->free_netevent(this);
        co_return;
      }

      if (r <= 0) {
        if (r == -EAGAIN || r == -ENOTCONN) {
          readReschedule(nh); // re-arm; the next recv waits for data
          co_return;
        }
        if (r == 0 || r == -ECONNRESET) {
          _read_signal_done(VC_EVENT_EOS);
          co_return;
        }
        this->_readSignalError(nh, static_cast<int>(-r));
        co_return;
      }

      Metrics::Counter::increment(net_rsb.read_bytes, r);
      Metrics::Counter::increment(net_rsb.read_bytes_count);
      s->vio.buffer.writer()->fill(r);
      s->vio.ndone += r;
      this->netActivity();

      if (s->vio.ntodo() <= 0) {
        _read_signal_done(VC_EVENT_READ_COMPLETE);
        co_return;
      }
      if (_read_signal_and_update(VC_EVENT_READ_READY) != EVENT_CONT) {
        co_return; // EVENT_DONE: the VC was freed during the signal
      }
      if (this->closed) {
        co_return;
      }
      if (r < static_cast<int>(rattempted)) {
        // Short read: the socket is drained for now. Re-arm; the next recv simply
        // waits in the kernel until more data arrives (no epoll round-trip).
        readReschedule(nh);
        co_return;
      }
      // Full read: there may be more in the socket --- loop and read again.
    }
  }
}

void
IOUringNetVConnection::_complete_deferred_close()
{
  // Free only once no io_uring op is still in flight; otherwise another op's
  // completion will resume into a freed `this`. The last coroutine to clear its
  // op performs the free.
  if (_read_op == nullptr && _write_op == nullptr && _connect_op == nullptr) {
    super::do_io_close(_close_errno);
  }
}

void
IOUringNetVConnection::do_io_close(int alerrno)
{
  if (_read_op != nullptr || _write_op != nullptr || _connect_op != nullptr) {
    // Cancel-then-unwind: an io_uring op is in flight. Mark closing and cancel it;
    // the resuming coroutine(s) do the actual free once nothing is in flight. Do
    // NOT clear the I/O buffers here --- the kernel may still touch them until the
    // cancels land.
    _closing            = true;
    _close_errno        = alerrno;
    this->read.enabled  = 0;
    this->write.enabled = 0;
    if (alerrno && alerrno != -1) {
      this->lerrno = alerrno;
    }
    this->closed = (alerrno == -1) ? 1 : -1;

    Metrics::Counter::increment(deferred_close_stat);
    cancel_in_flight(_read_op);
    cancel_in_flight(_write_op);
    cancel_in_flight(_connect_op);
    return;
  }
  super::do_io_close(alerrno);
}

void
IOUringNetVConnection::net_write_io(NetHandler *nh)
{
  // A sendmsg is already in flight; its completion continues writing. Don't start
  // a second one for the same VC.
  if (_write_op != nullptr) {
    nh->write_ready_list.remove(this);
    return;
  }

  _write();

  if (_write_op != nullptr) {
    nh->write_ready_list.remove(this);
  }
}

int
IOUringNetVConnection::_write_signal_and_update(int event)
{
  this->recursion++;
  if (this->write.vio.cont && this->write.vio.mutex == this->write.vio.cont->mutex) {
    this->write.vio.cont->handleEvent(event, &this->write.vio);
  } else {
    if (this->write.vio.cont) {
      Note("_write_signal_and_update: mutexes are different? vc=%p, event=%d", this, event);
    }
    switch (event) {
    case VC_EVENT_EOS:
    case VC_EVENT_ERROR:
    case VC_EVENT_ACTIVE_TIMEOUT:
    case VC_EVENT_INACTIVITY_TIMEOUT:
      this->closed = 1;
      break;
    default:
      Error("Unexpected event %d for vc %p", event, this);
      ink_release_assert(0);
      break;
    }
  }
  // See _read_signal_and_update: defer the free while any io_uring op is in flight.
  if (!--this->recursion && this->closed && _read_op == nullptr && _write_op == nullptr) {
    ink_assert(this->thread == this_ethread());
    this->nh->free_netevent(this);
    return EVENT_DONE;
  }
  return EVENT_CONT;
}

int
IOUringNetVConnection::_write_signal_done(int event)
{
  this->write.enabled = 0;
  if (_write_signal_and_update(event) == EVENT_DONE) {
    return EVENT_DONE;
  }
  writeReschedule(this->nh);
  return EVENT_CONT;
}

ts::iouring::DetachedTask
IOUringNetVConnection::_write()
{
  NetState   *s  = &this->write;
  NetHandler *nh = this->nh;

  // Drain the write VIO buffer to the socket per writability edge (edge-triggered
  // EPOLLOUT, same reasoning as the read path): keep sending until the socket
  // can't take more (short send), the buffer is empty, or the VIO is satisfied.
  for (;;) {
    IOVec         tiovec[IOU_FRAME_IOV];
    struct msghdr msg;
    int           fd           = this->con.sock.get_fd();
    int64_t       try_to_write = 0;

    // Build the next send under the VIO mutex.
    {
      MUTEX_TRY_LOCK(lock, s->vio.mutex, this->thread);
      if (!lock.is_locked() || lock.get_mutex() != s->vio.mutex.get()) {
        writeReschedule(nh);
        co_return;
      }
      if (this->closed) {
        nh->free_netevent(this);
        co_return;
      }
      if (this->has_error()) {
        this->lerrno = this->error;
        _write_signal_and_update(VC_EVENT_ERROR);
        co_return;
      }
      // Extra setup such as a TLS handshake (a no-op for a plain VC).
      if (!this->_isReadyToTransferData()) {
        this->_beReadyToTransferData();
        co_return;
      }
      if (!s->enabled || s->vio.op != VIO::WRITE) {
        write_disable(nh, this);
        co_return;
      }
      int64_t ntodo = s->vio.ntodo();
      if (ntodo <= 0) {
        write_disable(nh, this);
        co_return;
      }
      MIOBufferAccessor &buf     = s->vio.buffer;
      int64_t            towrite = buf.reader()->read_avail();
      if (towrite > ntodo) {
        towrite = ntodo;
      }
      // Demand-driven: if the buffer does not yet hold all the requested data and
      // is not at high water, signal WRITE_READY so the user can produce more
      // before we send (keeps the write moving without us buffering ahead).
      if (towrite != ntodo && !buf.writer()->high_water()) {
        if (_write_signal_and_update(VC_EVENT_WRITE_READY) != EVENT_CONT) {
          co_return; // EVENT_DONE: the VC was freed during the signal
        }
        if (this->closed) {
          co_return;
        }
        ntodo = s->vio.ntodo();
        if (ntodo <= 0) {
          write_disable(nh, this);
          co_return;
        }
        towrite = buf.reader()->read_avail();
        if (towrite > ntodo) {
          towrite = ntodo;
        }
      }
      if (towrite <= 0) {
        // Nothing to send right now; reenable re-arms us when the user produces.
        write_disable(nh, this);
        co_return;
      }

      // Build the iovec from a clone of the reader (so the real reader is not
      // consumed until the send actually completes). tiovec / msg live in this
      // coroutine frame, pinned across the await.
      IOBufferReader *tmp  = buf.reader()->clone();
      unsigned        niov = 0;
      while (niov < IOU_FRAME_IOV) {
        int64_t wavail = towrite - try_to_write;
        int64_t len    = tmp->block_read_avail();
        if (len <= 0) {
          break;
        }
        if (len > wavail) {
          len = wavail;
        }
        if (len == 0) {
          break;
        }
        tiovec[niov].iov_len  = len;
        tiovec[niov].iov_base = tmp->start();
        niov++;
        try_to_write += len;
        tmp->consume(len);
      }
      tmp->dealloc();
      if (niov == 0) {
        write_disable(nh, this);
        co_return;
      }
      ink_zero(msg);
      if (!ats_is_unix(this->get_local_addr())) {
        msg.msg_name    = const_cast<sockaddr *>(this->get_remote_addr());
        msg.msg_namelen = ats_ip_size(this->get_remote_addr());
      }
      msg.msg_iov    = &tiovec[0];
      msg.msg_iovlen = niov;
    }

    // Submit one send/sendmsg and suspend. The SQE rides the single submit_and_wait
    // per event-loop iteration, so at load many sends batch into one io_uring_enter
    // and the per-request sendmsg syscall disappears --- cheaper than a synchronous
    // non-blocking send once the coroutine frame is small enough that the CQE/resume
    // round-trip is nearly free.
    ts::iouring::UringOp op([&](io_uring_sqe *sqe) {
      if (msg.msg_iovlen == 1) {
        io_uring_prep_send(sqe, fd, msg.msg_iov[0].iov_base, msg.msg_iov[0].iov_len, MSG_NOSIGNAL);
      } else {
        io_uring_prep_sendmsg(sqe, fd, &msg, 0);
      }
    });
    _write_op = &op;
    int wr    = co_await op;
    _write_op = nullptr;

    if (_closing) {
      _complete_deferred_close();
      co_return;
    }

    // Consume + signal under the VIO mutex.
    {
      MUTEX_TRY_LOCK(lock, s->vio.mutex, this->thread);
      if (!lock.is_locked() || lock.get_mutex() != s->vio.mutex.get()) {
        writeReschedule(nh);
        co_return;
      }
      if (this->closed) {
        nh->free_netevent(this);
        co_return;
      }

      if (wr <= 0) {
        if (wr == -EAGAIN || wr == -ENOTCONN || wr == -EINPROGRESS) {
          writeReschedule(nh); // re-arm; the next sendmsg waits for socket space
          co_return;
        }
        this->_writeSignalError(nh, static_cast<int>(-wr));
        co_return;
      }

      Metrics::Counter::increment(net_rsb.write_bytes, wr);
      Metrics::Counter::increment(net_rsb.write_bytes_count);
      s->vio.buffer.reader()->consume(wr);
      s->vio.ndone += wr;
      this->netActivity();

      if (s->vio.ntodo() <= 0) {
        _write_signal_done(VC_EVENT_WRITE_COMPLETE);
        co_return;
      }
      if (wr < static_cast<int>(try_to_write)) {
        // Short send: the socket buffer is full. Re-arm; the next sendmsg waits in
        // the kernel until there is socket space (no epoll round-trip).
        writeReschedule(nh);
        co_return;
      }
      // Full send with more to do: loop (the demand WRITE_READY at the top asks
      // the user to produce more once the buffer runs low).
    }
  }
}

int
IOUringNetVConnection::connectUp(EThread *t, int fd)
{
  ink_assert(get_NetHandler(t)->mutex->thread_holding == this_ethread());
  int        res;
  UnixSocket sock{fd};

  thread = t;
  if (check_net_throttle(CONNECT)) {
    check_throttle_warning(CONNECT);
    res = -ENET_THROTTLING;
    Metrics::Counter::increment(net_rsb.connections_throttled_out);
    goto fail;
  }

  options.ip_family = con.addr.sa.sa_family;

  if (!sock.is_ok()) {
    // Create + bind the socket and apply options, but do NOT connect(2): _connect
    // drives the handshake with io_uring instead.
    res = con.open(options);
    if (res != 0) {
      goto fail;
    }
  } else {
    // TS API handed us an already-connected fd. Same as the base: adopt it and
    // deliver NET_EVENT_OPEN synchronously (no handshake to wait for).
    int len = sizeof(con.sock_type);
    safe_getsockopt(fd, SOL_SOCKET, SO_TYPE, reinterpret_cast<char *>(&con.sock_type), &len);
    sock.set_nonblocking();
    con.sock         = sock;
    con.is_connected = true;
    con.is_bound     = true;
  }

  if ((res = get_NetHandler(t)->startIO(this)) < 0) {
    goto fail;
  }

  if (!sock.is_ok()) {
    // Dynamic options Connection::connect would normally apply, then the io_uring
    // connect. NET_EVENT_OPEN / NET_EVENT_OPEN_FAILED is delivered from _connect.
    con.apply_options(options);
    _connect();
    return CONNECT_SUCCESS;
  }

  // Already-connected (TS API) path: complete synchronously like the base.
  Metrics::Gauge::increment(net_rsb.connections_currently_open);
  SET_HANDLER(&UnixNetVConnection::mainEvent);
  nh->startCop(this);
  set_inactivity_timeout(0);
  this->set_local_addr();
  action_.continuation->handleEvent(NET_EVENT_OPEN, this);
  return CONNECT_SUCCESS;

fail:
  lerrno = -res;
  action_.continuation->handleEvent(NET_EVENT_OPEN_FAILED, reinterpret_cast<void *>(static_cast<intptr_t>(res)));
  if (con.sock.is_ok()) {
    con.sock = UnixSocket{NO_FD};
  }
  if (nullptr != nh) {
    nh->free_netevent(this);
  } else {
    this->free_thread(t);
  }
  return CONNECT_FAILURE;
}

ts::iouring::DetachedTask
IOUringNetVConnection::_connect()
{
  int       fd   = con.sock.get_fd();
  sockaddr *addr = const_cast<sockaddr *>(&con.addr.sa);
  socklen_t alen = ats_ip_size(&con.addr.sa);

  // A linked timeout cancels a stuck handshake so a black-holed origin fails
  // instead of hanging. kts lives in the coroutine frame, pinned across the await.
  int64_t           secs = RecGetRecordInt("proxy.config.http.connect_attempts_timeout").value_or(30);
  __kernel_timespec kts  = {.tv_sec = secs, .tv_nsec = 0};

  ts::iouring::UringOp op([&](io_uring_sqe *sqe) {
    io_uring_prep_connect(sqe, fd, addr, alen);
    if (io_uring_sqe *tsqe = IOUringContext::local_context()->next_sqe(&noop_completion); tsqe != nullptr) {
      sqe->flags |= IOSQE_IO_LINK;
      io_uring_prep_link_timeout(tsqe, &kts, 0);
    }
  });
  _connect_op = &op;
  int res     = co_await op;
  _connect_op = nullptr;

  // do_io_close fired during the handshake (e.g. the client aborted): defer the
  // free until no op is in flight.
  if (_closing) {
    _complete_deferred_close();
    co_return;
  }

  // The connecting continuation is thread-confined to this EThread, so its mutex
  // is uncontended here (we resume on the owning thread from service()).
  MUTEX_TRY_LOCK(lock, action_.continuation->mutex, this_ethread());
  ink_release_assert(lock.is_locked());

  if (action_.cancelled) {
    nh->free_netevent(this);
    co_return;
  }

  if (res < 0) {
    // -ECANCELED == the linked timeout fired (treat as a connect timeout); other
    // negatives are the real connect error (-ECONNREFUSED, ...).
    int err      = (res == -ECANCELED) ? ETIMEDOUT : -res;
    this->lerrno = err;
    action_.continuation->handleEvent(NET_EVENT_OPEN_FAILED, reinterpret_cast<void *>(static_cast<intptr_t>(-err)));
    nh->free_netevent(this);
    co_return;
  }

  // Handshake complete: NET_EVENT_OPEN now means the connection is really up.
  con.is_connected = true;
  Metrics::Gauge::increment(net_rsb.connections_currently_open);
  SET_HANDLER(&UnixNetVConnection::mainEvent);
  nh->startCop(this);
  set_inactivity_timeout(0);
  this->set_local_addr();
  action_.continuation->handleEvent(NET_EVENT_OPEN, this);
}

#endif // TS_USE_LINUX_IO_URING
