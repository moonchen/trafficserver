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

#include "tsutil/Metrics.h"

using ts::Metrics;

// Global
ClassAllocator<IOUringNetVConnection> ioUringNetVCAllocator("ioUringNetVCAllocator");

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
} // namespace

void
IOUringNetVConnection::free_thread(EThread *t)
{
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
  if (!--this->recursion && this->closed) {
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
IOUringNetVConnection::net_read_io(NetHandler *nh)
{
  // A drain is already in flight; its completion continues reading. Don't start a
  // second one for the same VC.
  if (_read_op != nullptr) {
    this->read.triggered = 0;
    nh->read_ready_list.remove(this);
    return;
  }

  // _read() does its own locking, drains the socket, and re-arms or disables.
  _read();

  // If a recv is now in flight, keep epoll from re-entering us until it completes.
  if (_read_op != nullptr) {
    this->read.triggered = 0;
    nh->read_ready_list.remove(this);
  }
}

ts::iouring::DetachedTask
IOUringNetVConnection::_read()
{
  NetState   *s  = &this->read;
  NetHandler *nh = this->nh;

  // Drain the socket per epoll trigger. The net poll set is edge-triggered
  // (EPOLLIN | EPOLLET): it only re-notifies on NEW data, so a single recvmsg per
  // trigger would leave readable bytes behind and stall. Keep reading until a
  // short read (socket drained), a full read buffer (backpressure), or the read
  // VIO is satisfied/disabled.
  for (;;) {
    // tiovec and msg live in this coroutine frame, pinned across the await for the
    // lifetime of the in-flight recvmsg (the structural lifetime guarantee).
    IOVec         tiovec[NET_MAX_IOV];
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
      while (b && niov < NET_MAX_IOV) {
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

    // Submit one recvmsg and suspend. No lock is held across the await.
    ts::iouring::UringOp op([&](io_uring_sqe *sqe) { io_uring_prep_recvmsg(sqe, fd, &msg, 0); });
    _read_op = &op;
    int r    = co_await op;
    _read_op = nullptr;

    // do_io_close deferred teardown to us (it cancelled this recv). Free now that
    // no op is in flight, then stop touching `this`.
    if (_read_closing) {
      super::do_io_close(_read_close_errno);
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
          readReschedule(nh); // socket drained; epoll re-fires on new data
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
        // Short read: the socket is drained for now. epoll re-fires on new data.
        readReschedule(nh);
        co_return;
      }
      // Full read: there may be more in the socket --- loop and read again.
    }
  }
}

void
IOUringNetVConnection::do_io_close(int alerrno)
{
  if (_read_op != nullptr) {
    // Cancel-then-unwind: a recvmsg is in flight. Mark closing and cancel it; the
    // read coroutine's completion does the actual free. Do NOT clear the read
    // buffer here --- the kernel may still write into it until the cancel lands.
    _read_closing       = true;
    _read_close_errno   = alerrno;
    this->read.enabled  = 0;
    this->write.enabled = 0;
    if (alerrno && alerrno != -1) {
      this->lerrno = alerrno;
    }
    this->closed = (alerrno == -1) ? 1 : -1;

    io_uring_sqe *sqe = IOUringContext::local_context()->next_sqe(&noop_completion);
    if (sqe != nullptr) {
      io_uring_prep_cancel(sqe, _read_op, 0);
    }
    return;
  }
  super::do_io_close(alerrno);
}

#endif // TS_USE_LINUX_IO_URING
