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
#include "iocore/io_uring/UringFixedBufArena.h"
#include "iocore/eventsystem/EThread.h"
#include "iocore/eventsystem/IOBuffer.h"
#include "../eventsystem/P_IOBuffer.h"

#include "tscore/InkErrno.h"
#include "tscore/ink_memory.h"
#include "records/RecCore.h"

#include "tsutil/Metrics.h"

using ts::Metrics;

// Zero-copy-send constants, in case the kernel uapi header pulled in by liburing predates
// them (the io_uring_prep_send_zc helper is older than these report flags).
#ifndef IORING_SEND_ZC_REPORT_USAGE
#define IORING_SEND_ZC_REPORT_USAGE (1U << 3)
#endif
#ifndef IORING_NOTIF_USAGE_ZC_COPIED
#define IORING_NOTIF_USAGE_ZC_COPIED (1U << 31)
#endif

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

// --- Read path: single-shot recv into a shared provided-buffer ring (proxy.config.net.io_uring.read_provided_buffers) ---
namespace
{
// One buffer group per thread; every io_uring read coroutine on the thread arms its
// multishot recv against this group, and the kernel picks a buffer from the shared
// ring for each completion.
constexpr int IOU_READ_BGID = 1;

bool
read_provided_enabled()
{
  static const bool on = RecGetRecordInt("proxy.config.net.io_uring.read_provided_buffers").value_or(0) != 0;
  return on;
}

// Zero-copy send (IORING_OP_SEND_ZC) for writes at/above the threshold. The kernel DMAs
// from the source pages instead of copying into skbs; a second IORING_CQE_F_NOTIF CQE
// reports when the pages are free. Gated on size because below ~a page the copy is
// cheaper than the extra notification. No HDS / special NIC needed (only NETIF_F_SG).
bool
write_zc_enabled()
{
  static const bool on = RecGetRecordInt("proxy.config.net.io_uring.write_zerocopy").value_or(0) != 0;
  return on;
}

int64_t
write_zc_threshold()
{
  static const int64_t t = RecGetRecordInt("proxy.config.net.io_uring.write_zerocopy_threshold").value_or(4096);
  return t;
}

// write_zerocopy: sends issued on the zero-copy path. write_zerocopy_copied: of those, the
// ones the kernel fell back to copying (IORING_NOTIF_USAGE_ZC_COPIED in the notification) ---
// a nonzero ratio means the fast path is not actually engaging.
Metrics::Counter::AtomicType *write_zc_stat = Metrics::Counter::createPtr("proxy.process.net.io_uring.write_zerocopy");
// of the zero-copy sends, the ones issued as send_zc_fixed from the registered arena (no
// per-send pin / IOMMU map) --- the rest are anonymous send_zc (pinned per send).
Metrics::Counter::AtomicType *write_zc_fixed_stat = Metrics::Counter::createPtr("proxy.process.net.io_uring.write_zerocopy_fixed");
Metrics::Counter::AtomicType *write_zc_copied_stat =
  Metrics::Counter::createPtr("proxy.process.net.io_uring.write_zerocopy_copied");

struct ReadBufRing;

// An IOBufferData that wraps one provided-ring buffer rather than owning heap memory.
// free() (run by Ptr when the read MIOBuffer's last reader releases the block) recycles
// the buffer back to the ring and returns this descriptor to a freelist, instead of
// freeing anything --- the ring memory outlives every VC on the thread. Because
// IOBufferBlock::clone() shares the Ptr<IOBufferData> (it never copies the bytes), a
// buffer handed to several readers recycles only once, when the last one is done.
class RingBufferData : public IOBufferData
{
public:
  void            free() override;
  ReadBufRing    *_ring  = nullptr;
  RingBufferData *_flink = nullptr; // freelist link while idle
  int             _bid   = -1;
};

// The shared per-thread provided-buffer ring. Lazily set up on first use; if setup
// fails (old kernel / no memory) the read path falls back to single-shot recvmsg.
struct ReadBufRing {
  io_uring_buf_ring     *_br      = nullptr;
  char                  *_pool    = nullptr; // _nbuf contiguous buffers of _bufsize
  unsigned               _nbuf    = 0;
  unsigned               _bufsize = 0;
  int                    _mask    = 0;
  int64_t                _sizeidx = 0; // IOBufferData size index whose block_size() == _bufsize
  RingBufferData        *_free    = nullptr;
  IOUringNetVConnection *_wait    = nullptr; // intrusive stack of VCs parked on -ENOBUFS

  bool
  ok() const
  {
    return _br != nullptr;
  }

  char *
  addr(unsigned id) const
  {
    return _pool + static_cast<size_t>(id) * _bufsize;
  }

  // Park a VC whose multishot read stopped on -ENOBUFS; recycle() re-arms it.
  void
  add_waiter(IOUringNetVConnection *vc)
  {
    if (vc->_rbuf_waiting) {
      return;
    }
    vc->_rbuf_waiting   = true;
    vc->_rbuf_wait_next = _wait;
    _wait               = vc;
  }

  // Remove a VC from the wait list (it is being torn down, or was just woken).
  void
  remove_waiter(IOUringNetVConnection *vc)
  {
    if (!vc->_rbuf_waiting) {
      return;
    }
    for (IOUringNetVConnection **pp = &_wait; *pp != nullptr; pp = &(*pp)->_rbuf_wait_next) {
      if (*pp == vc) {
        *pp = vc->_rbuf_wait_next;
        break;
      }
    }
    vc->_rbuf_wait_next = nullptr;
    vc->_rbuf_waiting   = false;
  }

  // Hand buffer `id` back to the kernel's ring, then re-arm one VC waiting for a buffer.
  void
  recycle(int id)
  {
    io_uring_buf_ring_add(_br, addr(id), _bufsize, id, _mask, 0);
    io_uring_buf_ring_advance(_br, 1);
    if (IOUringNetVConnection *vc = _wait; vc != nullptr) {
      _wait               = vc->_rbuf_wait_next;
      vc->_rbuf_wait_next = nullptr;
      vc->_rbuf_waiting   = false;
      vc->rearm_read_for_buffers();
    }
  }

  RingBufferData *
  get_data()
  {
    if (RingBufferData *d = _free; d != nullptr) {
      _free     = d->_flink;
      d->_flink = nullptr;
      return d;
    }
    return new RingBufferData();
  }

  void
  put_data(RingBufferData *d)
  {
    d->_flink = _free;
    _free     = d;
  }

  // Wrap filled buffer `id` (`len` bytes) in a block, zero-copy, for append to a MIOBuffer.
  IOBufferBlock *
  wrap(int id, int len)
  {
    RingBufferData *d = get_data();
    d->_ring          = this;
    d->_bid           = id;
    d->_data          = addr(id);
    d->_size_index    = _sizeidx;
    d->_mem_type      = NO_ALLOC; // dealloc() (never reached --- free() is overridden) would not free it
    IOBufferBlock *b  = new_IOBufferBlock_internal("io_uring/read_bufring");
    b->set(d, len, 0); // Ptr-assign d (refcount -> 1); _start/_end/_buf_end from d
    return b;
  }

  bool
  setup()
  {
    unsigned nbuf    = static_cast<unsigned>(RecGetRecordInt("proxy.config.net.io_uring.read_buffer_count").value_or(1024));
    int64_t  bufsize = RecGetRecordInt("proxy.config.net.io_uring.read_buffer_size").value_or(32768);
    unsigned p       = 1;
    while (p * 2u <= nbuf) { // round down to a power of two (ring requirement)
      p *= 2u;
    }
    nbuf     = p < 2u ? 2u : p;
    _sizeidx = iobuffer_size_to_index(bufsize, MAX_BUFFER_SIZE_INDEX);
    _bufsize = BUFFER_SIZE_FOR_INDEX(_sizeidx); // exact, so block_size() matches the buffer

    int err = 0;
    _br     = IOUringContext::local_context()->setup_buf_ring(nbuf, IOU_READ_BGID, &err);
    if (_br == nullptr) {
      Warning("io_uring read_provided_buffers: buf_ring setup failed (%d); falling back to recvmsg", err);
      return false;
    }
    _nbuf = nbuf;
    _mask = io_uring_buf_ring_mask(nbuf);
    _pool = static_cast<char *>(ats_malloc(static_cast<size_t>(nbuf) * _bufsize));
    for (unsigned i = 0; i < nbuf; ++i) {
      io_uring_buf_ring_add(_br, addr(i), _bufsize, i, _mask, i);
    }
    io_uring_buf_ring_advance(_br, static_cast<int>(nbuf));
    return true;
  }
};

void
RingBufferData::free()
{
  ReadBufRing *r  = _ring;
  int          id = _bid;
  _ring           = nullptr;
  _bid            = -1;
  _data           = nullptr;
  _size_index     = BUFFER_SIZE_NOT_ALLOCATED;
  _mem_type       = NO_ALLOC;
  r->recycle(id);
  r->put_data(this);
}

// The thread's read ring, or nullptr if multishot read is off or setup failed.
ReadBufRing *
read_buf_ring()
{
  static thread_local ReadBufRing ring;
  static thread_local bool        tried = false;
  if (!tried) {
    tried = true;
    ring.setup();
  }
  return ring.ok() ? &ring : nullptr;
}
} // namespace

void
IOUringNetVConnection::free_thread(EThread *t)
{
  // If this VC parked on the read buffer ring's wait list (-ENOBUFS), unlink it before
  // the free so a later recycle does not wake a freed VC.
  if (_rbuf_waiting) {
    if (ReadBufRing *r = read_buf_ring(); r != nullptr) {
      r->remove_waiter(this);
    }
  }
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

  // The read drive does its own locking, drains the socket, and re-arms or disables.
  // With read_provided_buffers, each single-shot recv selects a buffer from a shared
  // provided-buffer ring (late binding + zero-copy attach); otherwise the per-edge
  // single-shot recvmsg loop into the VIO's own MIOBuffer.
  if (read_provided_enabled() && read_buf_ring() != nullptr) {
    _read_provided();
  } else {
    _read();
  }

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
    // lifetime of the in-flight recvmsg (the structural lifetime guarantee). The kernel
    // writes the received bytes into the destination blocks asynchronously, so those
    // blocks must outlive the recv too: hold a Ptr to each across the await. Unlike epoll
    // (whose recv is synchronous and touches the buffer only during the call) the consumer
    // can release the read VIO's MIOBuffer (e.g. a request-body tunnel abandoned when the
    // origin responds early) while this recv is still in flight; without these anchors the
    // kernel would write into freed memory --- invisible to ASan, surfacing later as
    // freelist corruption.
    IOVec              tiovec[IOU_FRAME_IOV];
    Ptr<IOBufferBlock> anchor[IOU_FRAME_IOV];
    struct msghdr      msg;
    int                fd         = this->con.sock.get_fd();
    int64_t            rattempted = 0;

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
          anchor[niov]          = b; // keep this destination block alive until the recv completes
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
    // Recv-coalescing (T3.4): cap SO_RCVLOWAT at the bytes we will actually read (rattempted) so the
    // recv never blocks waiting for more than the body has left -- the origin may keep-alive with no
    // FIN to flush a short tail. POLL_FIRST (skip io_uring's inline non-blocking recv, which ignores
    // SO_RCVLOWAT) is used only for a full coalesce chunk; for the partial tail the inline recv grabs
    // what is there immediately, and a sub-threshold chunk just ships as a copy (see _write re-gate).
    bool poll_first = false;
    if (_recv_poll_first && rattempted > 0) {
      int want = static_cast<int>(rattempted < _recv_coalesce_size ? rattempted : _recv_coalesce_size);
      if (want != _recv_lowat_cur) {
        setsockopt(fd, SOL_SOCKET, SO_RCVLOWAT, &want, sizeof(want));
        _recv_lowat_cur = want;
      }
      poll_first = rattempted >= _recv_coalesce_size;
    }

    ts::iouring::UringOp op([&](io_uring_sqe *sqe) {
      if (msg.msg_iovlen == 1) {
        io_uring_prep_recv(sqe, fd, msg.msg_iov[0].iov_base, msg.msg_iov[0].iov_len, 0);
      } else {
        io_uring_prep_recvmsg(sqe, fd, &msg, 0);
      }
      if (poll_first) {
        sqe->ioprio |= IORING_RECVSEND_POLL_FIRST;
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

// Single-shot recv into a shared provided-buffer ring (proxy.config.net.io_uring.
// read_provided_buffers). Demand-driven like _read --- one recv per loop iteration,
// re-armed on consumer reenable --- but the kernel selects a ring buffer at completion
// instead of reading into the VIO's MIOBuffer: an idle keep-alive connection holds no
// read buffer (late binding), and the filled buffer is attached to the read MIOBuffer
// zero-copy (RingBufferData recycles it once the consumer is done). sqe->len caps each
// recv to min(ntodo, bufsize) --- the kernel keeps a nonzero len <= the selected
// buffer's size --- so a content-length read stops at the boundary and leaves the next
// pipelined request in the socket. -ENOBUFS (shared ring exhausted) parks the VC on the
// ring wait list; a recycle re-arms it via rearm_read_for_buffers(). Nothing stays armed
// across the await, so unlike multishot there is no cancel/drain stop-the-stream window.
ts::iouring::DetachedTask
IOUringNetVConnection::_read_provided()
{
  NetState    *s    = &this->read;
  NetHandler  *nh   = this->nh;
  ReadBufRing *ring = read_buf_ring();
  int          fd   = this->con.sock.get_fd();

  for (;;) {
    int64_t want = 0;

    // Decide the next read under the VIO mutex.
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
      if (s->vio.buffer.writer() == nullptr) {
        // No destination buffer attached; don't read into a provided buffer we can't
        // place. reenable() re-arms us once the consumer attaches one.
        read_disable(nh, this);
        co_return;
      }
      // Cap the recv to the VIO's remaining bytes (and one buffer). The kernel keeps a
      // nonzero len <= the selected buffer's size, so this is an exact upper bound.
      want = s->vio.ntodo();
      if (want > static_cast<int64_t>(ring->_bufsize)) {
        want = ring->_bufsize;
      }
    }

    // Submit one buffer-select recv and suspend. No lock is held across the await.
    ts::iouring::UringOp op([&](io_uring_sqe *sqe) {
      io_uring_prep_recv(sqe, fd, nullptr, static_cast<unsigned>(want), 0);
      sqe->buf_group  = IOU_READ_BGID;
      sqe->flags     |= IOSQE_BUFFER_SELECT;
    });
    _read_op      = &op;
    int      r    = co_await op;
    unsigned flgs = op.flags();
    _read_op      = nullptr;

    // do_io_close deferred teardown to us (it cancelled this recv). Return any selected
    // buffer to the ring, then free once no op is in flight.
    if (_closing) {
      if (r > 0) {
        ring->recycle(flgs >> IORING_CQE_BUFFER_SHIFT);
      }
      _complete_deferred_close();
      co_return;
    }

    // Attach + signal under the VIO mutex.
    {
      MUTEX_TRY_LOCK(lock, s->vio.mutex, this->thread);
      if (!lock.is_locked()) {
        if (r > 0) {
          ring->recycle(flgs >> IORING_CQE_BUFFER_SHIFT);
        }
        readReschedule(nh);
        co_return;
      }
      if (this->closed) {
        if (r > 0) {
          ring->recycle(flgs >> IORING_CQE_BUFFER_SHIFT);
        }
        nh->free_netevent(this);
        co_return;
      }

      if (r <= 0) {
        if (r == -ENOBUFS) {
          // Shared ring exhausted (no buffer was consumed). Park on the wait list and
          // stop; a recycle re-arms us via rearm_read_for_buffers().
          ring->add_waiter(this);
          read_disable(nh, this);
          co_return;
        }
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

      // Re-validate after the recv suspension: a write-side completion (response sent ->
      // session release -> do_io_read(0,nullptr) then keep-alive read) can have stopped or
      // reconfigured the read while this recv was in flight. If it can still take data,
      // append to the current buffer (a freshly attached keep-alive buffer is fine --- the
      // bytes are the next request and belong there); otherwise drop the buffer and stop.
      if (!s->enabled || s->vio.op != VIO::READ || s->vio.is_disabled() || s->vio.ntodo() <= 0 ||
          s->vio.buffer.writer() == nullptr) {
        ring->recycle(flgs >> IORING_CQE_BUFFER_SHIFT);
        read_disable(nh, this);
        co_return;
      }
      s->vio.buffer.writer()->append_block(ring->wrap(flgs >> IORING_CQE_BUFFER_SHIFT, r));
      Metrics::Counter::increment(net_rsb.read_bytes, r);
      Metrics::Counter::increment(net_rsb.read_bytes_count);
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
      if (r < static_cast<int>(want)) {
        // Short read: the socket is drained for now. Re-arm; the next recv waits in the
        // kernel until more data arrives.
        readReschedule(nh);
        co_return;
      }
      // Filled the cap: there may be more buffered --- loop and read again.
    }
  }
}

void
IOUringNetVConnection::rearm_read_for_buffers()
{
  // A buffer recycled; the provided-buffer read that parked on -ENOBUFS can run again.
  // Re-trigger net_read_io via the ready list (it re-arms once the ring has a buffer).
  if (!this->closed) {
    readReschedule(this->nh);
  }
}

void
IOUringNetVConnection::set_recv_coalesce(int64_t min_bytes)
{
  _recv_poll_first    = true;
  _recv_coalesce_size = min_bytes;
  _recv_lowat_cur     = static_cast<int>(min_bytes);
  int fd              = con.sock.get_fd();
  if (fd < 0 || min_bytes <= 0) {
    return;
  }
  // SO_RCVLOWAT is capped near SO_RCVBUF/2 (and SO_RCVBUF at net.core.rmem_max), so widen the receive
  // buffer first. Disabling autotuning is acceptable here: a coalescing read wants a large fixed window.
  int want_rcvbuf = static_cast<int>(min_bytes * 2);
  setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &want_rcvbuf, sizeof(want_rcvbuf));
  int lowat = static_cast<int>(min_bytes);
  setsockopt(fd, SOL_SOCKET, SO_RCVLOWAT, &lowat, sizeof(lowat));
  // Warn (once) if the kernel capped the low-water below the target: reads then coalesce to less than
  // min_bytes, so the chunks fall under the send_zc threshold and ship as copies. Raising
  // net.core.rmem_max lets the coalescing reach the target.
  int       got = 0;
  socklen_t gl  = sizeof(got);
  if (getsockopt(fd, SOL_SOCKET, SO_RCVLOWAT, &got, &gl) == 0 && got < min_bytes) {
    SiteThrottledWarning("io_uring recv coalesce: SO_RCVLOWAT capped at %d B (< %" PRId64
                         " target); raise net.core.rmem_max for full coalescing",
                         got, min_bytes);
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

VIO *
IOUringNetVConnection::do_io_write(Continuation *c, int64_t nbytes, IOBufferReader *buf, bool owner)
{
  // A null reader is the "stop writing" call a tunnel teardown uses (abort_tunnel's
  // do_io_write(this, 0, nullptr)). On epoll that synchronously stops the write; an in-flight
  // io_uring send cannot be. Cancel it and mark it abandoned so the resuming _write skips its
  // stale consume + signal against the source buffer the caller is about to free (the source
  // blocks stay pinned, so the send itself is safe). This is the quick_server fix: the
  // early-response teardown freed the POST buffer while the origin body-write send was in
  // flight, and the resuming _write then consumed the recycled reader.
  //
  // Note this is NOT mirrored for do_io_read: do_io_read(0,nullptr) is also the routine
  // keep-alive "pause reading" call, made while a recv is legitimately in flight waiting for
  // the next request --- cancelling there loses the recv. A send never lingers that way, so
  // an in-flight send at do_io_write(0,nullptr) really is an abandoned transfer.
  if (_write_op != nullptr && buf == nullptr) {
    _write_abandoned = true;
    cancel_in_flight(_write_op);
  }
  return super::do_io_write(c, nbytes, buf, owner);
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
    IOVec              tiovec[IOU_FRAME_IOV];
    struct msghdr      msg;
    Ptr<IOBufferBlock> anchor[IOU_FRAME_IOV]; // zero-copy: hold the source pages until the NOTIF
    bool               use_zc       = false;
    int                reg_idx      = -1;      // registered buf_index of the source run (send_zc_fixed)
    bool               fixed_ok     = false;   // all iovec blocks are one registered buffer + contiguous
    char              *fixed_end    = nullptr; // running end pointer for the contiguity check
    int                fd           = this->con.sock.get_fd();
    int64_t            try_to_write = 0;

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

      // Zero-copy send is gated on size: below the threshold the per-byte copy is cheaper
      // than the extra notification CQE (and the page pinning).
      use_zc = write_zc_enabled() && towrite >= write_zc_threshold();

      // Build the iovec from a clone of the reader (so the real reader is not consumed
      // until the send actually completes). For zero-copy the kernel DMAs from these source
      // pages until the notification, so also hold a Ptr to each block until then. tiovec /
      // msg / anchor live in this coroutine frame, pinned across the await.
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
        // Pin the source block across the await: the kernel reads it asynchronously, and the
        // caller (a tunnel teardown such as abort_tunnel) may free the source MIOBuffer before
        // this send's CQE. The blocks are RefCountObj, so the MIOBuffer can go while these live.
        anchor[niov] = tmp->block;
        if (use_zc) {
          // send_zc_fixed needs one registered buffer over a contiguous range. Track whether
          // every iovec block so far is the same registered buf_index and abuts the previous
          // (e.g. the body windows of one cache fragment); the leading HTTP-header block, a
          // non-arena buffer, fails this and keeps that send on the copy/anonymous path.
          int   reg  = (tmp->block && tmp->block->data) ? tmp->block->data->registered_index() : -1;
          char *base = static_cast<char *>(tiovec[niov].iov_base);
          if (niov == 0) {
            reg_idx  = reg;
            fixed_ok = (reg >= 0);
          } else if (reg != reg_idx || base != fixed_end) {
            break; // stop the iovec at a registered-ness / contiguity boundary, so the leading
                   // HTTP-header block and the registered body run go out as separate sends
          }
          fixed_end = base + len;
        }
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

    // Re-gate zero-copy on the ACTUAL bytes in this iovec, not the total available: after the
    // header/body split, the leading HTTP-header send is tiny and below the threshold, so it
    // drops to a plain copy send rather than paying a notification + pin for a few hundred bytes.
    use_zc = use_zc && try_to_write >= write_zc_threshold();

    // Submit one send/sendmsg and suspend. The SQE rides the single submit_and_wait per
    // event-loop iteration, so at load many sends batch into one io_uring_enter and the
    // per-request sendmsg syscall disappears.
    int wr = 0;
    if (use_zc) {
      // Zero-copy: the kernel DMAs from the source pages (no copy into skbs) and posts a
      // second IORING_CQE_F_NOTIF CQE once the pages are free (typically after the peer
      // ACKs). The send-result CQE (IORING_CQE_F_MORE set) does NOT mean the pages are free,
      // so the anchors are held and the consume is deferred until the notification drains.
      Metrics::Counter::increment(write_zc_stat);
      if (fixed_ok) {
        UringFixedBufArena::instance().ensure_registered(); // idempotent: register the arena on this ring
        Metrics::Counter::increment(write_zc_fixed_stat);
      }
      ts::iouring::UringMultishotOp op([&](io_uring_sqe *sqe) {
        if (fixed_ok) {
          // Arena-backed contiguous run: DMA from the pre-registered, pre-pinned region (no
          // per-send get_user_pages / IOMMU map). reg_idx selects the registered region;
          // try_to_write is the merged length of the contiguous blocks.
          io_uring_prep_send_zc_fixed(sqe, fd, tiovec[0].iov_base, try_to_write, MSG_NOSIGNAL, IORING_SEND_ZC_REPORT_USAGE,
                                      reg_idx);
        } else if (msg.msg_iovlen == 1) {
          io_uring_prep_send_zc(sqe, fd, msg.msg_iov[0].iov_base, msg.msg_iov[0].iov_len, MSG_NOSIGNAL,
                                IORING_SEND_ZC_REPORT_USAGE);
        } else {
          io_uring_prep_sendmsg_zc(sqe, fd, &msg, MSG_NOSIGNAL);
          sqe->ioprio |= IORING_SEND_ZC_REPORT_USAGE;
        }
      });
      _write_op = &op;
      wr        = co_await op; // send-result CQE (bytes sent)
      // Drain the notification (and any cancel terminal): F_MORE means another CQE follows.
      // The notification's res carries IORING_NOTIF_USAGE_ZC_COPIED if the kernel fell back
      // to copying (the fast path did not engage).
      while (op.more()) {
        int n = co_await op;
        if ((op.flags() & IORING_CQE_F_NOTIF) && (static_cast<unsigned>(n) & IORING_NOTIF_USAGE_ZC_COPIED)) {
          Metrics::Counter::increment(write_zc_copied_stat);
        }
      }
      _write_op = nullptr;
      for (auto &a : anchor) {
        a = nullptr; // kernel is done with the source pages
      }
    } else {
      ts::iouring::UringOp op([&](io_uring_sqe *sqe) {
        if (msg.msg_iovlen == 1) {
          io_uring_prep_send(sqe, fd, msg.msg_iov[0].iov_base, msg.msg_iov[0].iov_len, MSG_NOSIGNAL);
        } else {
          io_uring_prep_sendmsg(sqe, fd, &msg, 0);
        }
      });
      _write_op = &op;
      wr        = co_await op;
      _write_op = nullptr;
      for (auto &a : anchor) {
        a = nullptr; // non-ZC: the kernel copied the source at send time, so release the pins now
      }
    }

    if (_closing) {
      _complete_deferred_close();
      co_return;
    }
    if (_write_abandoned) {
      // do_io_write(null) stopped this write VIO while the send was in flight (a tunnel teardown
      // such as abort_tunnel); the source buffer may now be freed/recycled, so skip the stale
      // consume + signal. The send itself was safe (source blocks were pinned). Re-drive
      // net_write_io for whatever the VIO holds now (a fresh transfer, or a disable).
      _write_abandoned = false;
      writeReschedule(nh);
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
