/** @file

    A brief file description

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

#include "TCPNetVConnection.h"
#include "I_Continuation.h"
#include "I_Event.h"
#include "I_IOBuffer.h"
#include "I_Net.h"
#include "NetAIO.h"
#include "NetVCOptions.h"
#include "P_Net.h"
#include "P_UnixNet.h"
#include "tscore/ink_assert.h"
#include "tscore/ink_hrtime.h"
#include "tscore/ink_inet.h"
#include "tscore/ink_platform.h"
#include "tscore/InkErrno.h"

// Global
ClassAllocator<TCPNetVConnection> tcpNetVCAllocator("tcpNetVCAllocator");
static constexpr auto TAG = "TCPNetVConnection";

// A wrapper around struct msghdr that holds on to the IOVec as well
struct MsgHdr : public msghdr {
  MsgHdr() : msghdr()
  {
    ink_zero(*this);
    msg_iov = tiovec;
  }
  IOVec tiovec[NET_MAX_IOV];
};

//
// Reschedule a TCPNetVConnection by moving it
// onto or off of the ready_list
//
void
TCPNetVConnection::_read_reschedule()
{
  ink_release_assert(this_ethread() == thread);
  ink_assert(handler == &TCPNetVConnection::mainEvent);
  _read.state = op_state::TRY_ISSUE;
  thread->schedule_in_local(this, HRTIME_MSECONDS(net_retry_delay));
}

void
TCPNetVConnection::_write_reschedule()
{
  ink_release_assert(this_ethread() == thread);
  ink_assert(handler == &TCPNetVConnection::mainEvent);
  _write.state = op_state::TRY_ISSUE;
  thread->schedule_in_local(this, HRTIME_MSECONDS(net_retry_delay));
}

//
// Signal an event
//
int
TCPNetVConnection::_read_signal_and_update(int event)
{
  _recursion++;
  if (_read.vio.cont && _read.vio.mutex == _read.vio.cont->mutex) {
    Debug(TAG, "read signal event=%d", event);
    _read.vio.cont->handleEvent(event, &_read.vio);
  } else {
    if (_read.vio.cont) {
      Note("_read_signal_and_update: mutexes are different? this=%p, event=%d", this, event);
    }
    switch (event) {
    case VC_EVENT_EOS:
    case VC_EVENT_ERROR:
    case VC_EVENT_ACTIVE_TIMEOUT:
    case VC_EVENT_INACTIVITY_TIMEOUT:
      Debug("inactivity_cop", "event %d: null _read.vio cont, closing this %p", event, this);
      _con.close();
      break;
    default:
      Error("Unexpected event %d for this %p", event, this);
      ink_release_assert(0);
      break;
    }
  }
  if (!--_recursion && _con.is_closed()) {
    /* BZ  31932 */
    ink_assert(thread == this_ethread());
    return EVENT_DONE;
  } else {
    return EVENT_CONT;
  }
}

int
TCPNetVConnection::_write_signal_and_update(int event)
{
  _recursion++;
  if (_write.vio.cont && _write.vio.mutex == _write.vio.cont->mutex) {
    Debug(TAG, "write signal event=%d", event);
    _write.vio.cont->handleEvent(event, &_write.vio);
  } else {
    if (_write.vio.cont) {
      Note("_write_signal_and_update: mutexes are different? this=%p, event=%d", this, event);
    }
    switch (event) {
    case VC_EVENT_EOS:
    case VC_EVENT_ERROR:
    case VC_EVENT_ACTIVE_TIMEOUT:
    case VC_EVENT_INACTIVITY_TIMEOUT:
      Debug("inactivity_cop", "event %d: null _write.vio cont, closing this %p", event, this);
      _con.close();
      break;
    default:
      Error("Unexpected event %d for this %p", event, this);
      ink_release_assert(0);
      break;
    }
  }
  if (!--_recursion && _con.is_closed()) {
    /* BZ  31932 */
    ink_assert(thread == this_ethread());
    return EVENT_DONE;
  } else {
    return EVENT_CONT;
  }
}

int
TCPNetVConnection::_read_signal_done(int event)
{
  _read.vio.disable();
  if (_read_signal_and_update(event) == EVENT_DONE) {
    _read.state = op_state::IDLE;
    return EVENT_DONE;
  } else {
    _read_reschedule();
    return EVENT_CONT;
  }
}

int
TCPNetVConnection::_write_signal_done(int event)
{
  _write.vio.disable();
  if (_write_signal_and_update(event) == EVENT_DONE) {
    _write.state = op_state::IDLE;
    return EVENT_DONE;
  } else {
    _write_reschedule();
    return EVENT_CONT;
  }
}

int
TCPNetVConnection::_read_from_net(int event, Event *e)
{
  // Locking while accessing the buffer
  MUTEX_TRY_LOCK(lock, _read.vio.mutex, thread);

  if (!lock.is_locked()) {
    _read_reschedule();
    return EVENT_CONT;
  };

  if (_con.is_closed()) {
    return EVENT_DONE;
  }
  // if it is not enabled.
  if (_read.vio.op != VIO::READ || _read.vio.is_disabled()) {
    // TODO: cancel?
    return EVENT_DONE;
  }

  MIOBufferAccessor &buf = _read.vio.buffer;
  ink_assert(buf.writer());

  // if there is nothing to do, disable connection
  int64_t ntodo = _read.vio.ntodo();
  if (ntodo <= 0) {
    return EVENT_DONE;
  }

  int64_t toread = buf.writer()->write_avail();
  if (toread > ntodo) {
    toread = ntodo;
  }

  ink_assert(_read.state == op_state::TRY_ISSUE);

  // read data
  int64_t rattempted = 0;
  unsigned niov      = 0;

  auto msg = std::make_unique<struct MsgHdr>();
  ink_release_assert(msg);

  if (toread) {
    IOBufferBlock *b = buf.writer()->first_write_block();
    niov             = 0;
    rattempted       = 0;
    while (b && niov < NET_MAX_IOV) {
      int64_t a = b->write_avail();
      if (a > 0) {
        msg->tiovec[niov].iov_base = b->_end;
        int64_t togo               = toread - rattempted;
        if (a > togo) {
          a = togo;
        }
        msg->tiovec[niov].iov_len = a;
        rattempted                += a;
        niov++;
        if (a >= togo) {
          break;
        }
      }
      b = b->next.get();
    }

    ink_assert(niov > 0);
    ink_assert(niov <= countof(msg->tiovec));
    msg->msg_name    = const_cast<sockaddr *>(get_remote_addr());
    msg->msg_namelen = ats_ip_size(get_remote_addr());
    msg->msg_iovlen  = niov;

    ink_assert(remote_addr.isValid());

    _read.state = op_state::WAIT_FOR_COMPLETION;
    auto ret    = _con.recvmsg(std::move(msg), 0);
    if (!ret) {
      Error("recvmsg failed");
      _read.state = op_state::IDLE;
      // TODO: what to do here?
      return EVENT_ERROR;
    } else {
      NET_INCREMENT_DYN_STAT(net_calls_to_read_stat);
    }
  }

  // It's okay to let go of the lock while the recvmsg is happening, since the structure of MIOBuffer is not updated during the
  // write.

  return EVENT_CONT;
}

void
TCPNetVConnection::onRecvmsg(ssize_t bytes, std::unique_ptr<struct msghdr> msg, NetAIO::TCPConnection &c)
{
  ink_release_assert(&c == &_con);
  ink_release_assert(_read.vio.op == VIO::READ);
  ink_release_assert(!_read.vio.is_disabled());
  ink_release_assert(_read.state == op_state::WAIT_FOR_COMPLETION);

  _read.r     = bytes;
  _read.state = op_state::TRY_HANDLER;
  ink_assert(handler == &TCPNetVConnection::mainEvent);
  thread->schedule_imm_local(this);

  // let msg get freed here
}

void
TCPNetVConnection::onError(NetAIO::ErrorSource source, int err, NetAIO::TCPConnection &c)
{
  ink_release_assert(&c == &_con);

  Debug(TAG, "onError: %d %d", source, err);

  // Failed to connect
  if (_connect_state == connect_state::WAIT) {
    _connect_state = connect_state::FAILED;
    lerrno         = err;
    _handle_connect_error();
  }

  // Handle EOS
  if (source == NetAIO::ES_RECVMSG) {
    lerrno = err;
    _handle_read_error();
  }

  if (source == NetAIO::ES_SENDMSG) {
    lerrno = err;
    _handle_write_error();
    return;
  }

  // TODO: close this NetVConnection
  c.close();
}

// Handle the completion of an async read of the underlying connection.
// Errors should not be handled here.
void
TCPNetVConnection::_handle_read_done()
{
  MUTEX_TRY_LOCK(lock, _read.vio.mutex, thread);
  if (!lock.is_locked()) {
    thread->schedule_in_local(this, HRTIME_MSECONDS(net_retry_delay));
    return;
  }

  int r = _read.r;
  ink_release_assert(r > 0);

  NET_SUM_DYN_STAT(net_read_bytes_stat, r);

  // Add data to buffer and signal continuation.
  MIOBufferAccessor &buf = _read.vio.buffer;
  ink_assert(buf.writer());
  buf.writer()->fill(r);
#ifdef DEBUG
  if (buf.writer()->write_avail() <= 0) {
    Debug(TAG, "_read_from_net, read buffer full");
  }
#endif
  _read.vio.ndone += r;

  // Signal read ready, check if user is not done

  // If there are no more bytes to read, signal read complete
  if (_read.vio.ntodo() <= 0) {
    _read_signal_done(VC_EVENT_READ_COMPLETE);
    Debug("iocore_net", "read_from_net, read finished - signal done");
    return;
  } else {
    if (_read_signal_and_update(VC_EVENT_READ_READY) != EVENT_CONT) {
      _read.state = op_state::IDLE;
      return;
    }

    // change of lock... don't look at shared variables!
    if (lock.get_mutex() != _read.vio.mutex.get()) {
      _read_reschedule();
      return;
    }
  }

  // If here are is no more room, or nothing to do, disable the connection
  if (_read.vio.ntodo() <= 0 || _read.vio.is_disabled() || !buf.writer()->write_avail()) {
    _read.state = op_state::IDLE;
    return;
  } else {
    _read_reschedule();
    return;
  }
}

void
TCPNetVConnection::_handle_read_error()
{
  ink_assert(_read.state == op_state::ERROR);
  MUTEX_TRY_LOCK(lock, _read.vio.mutex, thread);

  if (!lock.is_locked() || lock.get_mutex() != _read.vio.mutex.get()) {
    thread->schedule_in_local(this, HRTIME_MSECONDS(net_retry_delay));
    return;
  }

  if (lerrno == ECONNRESET) {
    _read_signal_done(VC_EVENT_EOS);
  } else {
    _read_signal_done(VC_EVENT_ERROR);
  }
}

// Begin writing to the underlying connection.  Schedule retry if
// necessary.
int
TCPNetVConnection::_write_to_net(int event, Event *e)
{
  ProxyMutex *mutex = thread->mutex.get();

  NET_INCREMENT_DYN_STAT(net_calls_to_writetonet_stat);

  // Lock while accessing the buffer
  MUTEX_TRY_LOCK(lock, _write.vio.mutex, thread);

  if (!lock.is_locked() || lock.get_mutex() != _write.vio.mutex.get()) {
    _write_reschedule();
    return EVENT_CONT;
  }

  if (_con.is_connecting()) {
    _write_reschedule();
    return EVENT_CONT;
  }

  // If it is not enabled,add to WaitList.
  if (_write.vio.is_disabled() || _write.vio.op != VIO::WRITE) {
    return EVENT_DONE;
  }

  // If there is nothing to do, disable
  int64_t ntodo = _write.vio.ntodo();
  if (ntodo <= 0) {
    return EVENT_DONE;
  }

  MIOBufferAccessor &buf = _write.vio.buffer;
  ink_assert(buf.writer());

  // Calculate the amount to write.
  int64_t towrite = buf.reader()->read_avail();
  if (towrite > ntodo) {
    towrite = ntodo;
  }

  _write.signalled = 0;

  // signal write ready to allow user to fill the buffer
  if (towrite != ntodo && !buf.writer()->high_water()) {
    if (_write_signal_and_update(VC_EVENT_WRITE_READY) != EVENT_CONT) {
      return EVENT_DONE;
    }

    _write.signalled = 1;

    // Recalculate amount to write
    towrite = buf.reader()->read_avail();
    if (towrite > ntodo) {
      towrite = ntodo;
    }
  }

  // if there is nothing to do, disable
  ink_assert(towrite >= 0);
  if (towrite <= 0) {
    return EVENT_DONE;
  }

  int64_t try_to_write = 0;
  auto p               = buf.reader()->clone();
  auto deleter         = [](IOBufferReader *p) { p->dealloc(); };
  std::unique_ptr<IOBufferReader, decltype(deleter)> tmp_reader{p, deleter};

  auto msg = std::make_unique<struct MsgHdr>();
  ink_release_assert(msg);

  unsigned niov = 0;
  try_to_write  = 0;

  while (niov < NET_MAX_IOV) {
    int64_t wavail = towrite - try_to_write;
    int64_t len    = tmp_reader->block_read_avail();

    // Check if we have done this block.
    if (len <= 0) {
      break;
    }

    // Check if the amount to write exceeds that in this buffer.
    if (len > wavail) {
      len = wavail;
    }

    if (len == 0) {
      break;
    }

    // build an iov entry
    msg->tiovec[niov].iov_len  = len;
    msg->tiovec[niov].iov_base = tmp_reader->start();
    niov++;

    try_to_write += len;
    tmp_reader->consume(len);
  }

  ink_assert(niov > 0);
  ink_assert(niov <= countof(msg->tiovec));

  msg->msg_name    = const_cast<sockaddr *>(get_remote_addr());
  msg->msg_namelen = ats_ip_size(get_remote_addr());
  msg->msg_iovlen  = niov;
  int flags        = 0;

  _write.state = op_state::WAIT_FOR_COMPLETION;
  auto ret     = _con.sendmsg(std::move(msg), flags);
  if (!ret) {
    _write.state = op_state::WAIT_FOR_COMPLETION;
    Error("sendmsg failed");
    // TODO: what to do here?
    return EVENT_ERROR;
  }

  NET_INCREMENT_DYN_STAT(net_calls_to_write_stat);

  return EVENT_DONE;
}

void
TCPNetVConnection::onSendmsg(ssize_t bytes, std::unique_ptr<struct msghdr> msg, NetAIO::TCPConnection &c)
{
  ink_release_assert(&c == &_con);
  ink_release_assert(_write.vio.op == VIO::WRITE);
  ink_release_assert(!_write.vio.is_disabled());
  ink_release_assert(_write.state == op_state::WAIT_FOR_COMPLETION);

  _write.r     = bytes;
  _write.state = op_state::TRY_HANDLER;
  ink_assert(handler == &TCPNetVConnection::mainEvent);
  thread->schedule_imm_local(this);

  // let msg get freed here
}

void
TCPNetVConnection::_handle_write_done()
{
  ink_release_assert(_write.state == op_state::TRY_HANDLER);

  MUTEX_TRY_LOCK(lock, _write.vio.mutex, thread);
  if (!lock.is_locked()) {
    thread->schedule_in(this, HRTIME_MSECONDS(net_retry_delay));
    return;
  }

  auto r = _write.r;
  // A write of 0 makes no sense since we tried to write more than 0.
  ink_release_assert(r > 0);

  MIOBufferAccessor &buf = _write.vio.buffer;
  if (r > 0) {
    buf.reader()->consume(r);
    NET_SUM_DYN_STAT(net_write_bytes_stat, r);
    _write.vio.ndone += r;
  }

  // Either we wrote something or got an error.
  // check for errors
  int wbe_event = write_buffer_empty_event; // save so we can clear if needed.

  // If the empty write buffer trap is set, clear it.
  if (!(buf.reader()->is_read_avail_more_than(0))) {
    write_buffer_empty_event = 0;
  }

  // If there are no more bytes to write, signal write complete,
  ink_assert(_write.vio.ntodo() >= 0);
  if (_write.vio.ntodo() <= 0) {
    _write_signal_done(VC_EVENT_WRITE_COMPLETE);
    return;
  }

  int event_out = 0;
  if (!_write.signalled || (_write.vio.ntodo() > 0 && !buf.writer()->high_water())) {
    event_out = VC_EVENT_WRITE_READY;
  } else if (wbe_event != write_buffer_empty_event) {
    // @a signalled means we won't send an event, and the event values differing means we
    // had a write buffer trap and cleared it, so we need to send it now.
    event_out = wbe_event;
  }

  if (event_out) {
    if (_write_signal_and_update(event_out) != EVENT_CONT) {
      _write.state = op_state::IDLE;
      return;
    }

    // change of lock... don't look at shared variables!
    if (lock.get_mutex() != _write.vio.mutex.get()) {
      _write_reschedule();
      return;
    }
  }

  if (!(buf.reader()->is_read_avail_more_than(0))) {
    return;
  } else {
    _write_reschedule();
    return;
  }
}

void
TCPNetVConnection::_handle_write_error()
{
  ink_assert(_write.state == op_state::ERROR);
  MUTEX_TRY_LOCK(lock, _write.vio.mutex, thread);

  if (!lock.is_locked() || lock.get_mutex() != _write.vio.mutex.get()) {
    thread->schedule_in_local(this, HRTIME_MSECONDS(net_retry_delay));
    return;
  }

  _write_signal_done(VC_EVENT_ERROR);
}

bool
TCPNetVConnection::get_data(int id, void *data)
{
  union {
    TSVIO *vio;
    void *data;
    int *n;
  } ptr;

  ptr.data = data;

  switch (id) {
  case TS_API_DATA_READ_VIO:
    *ptr.vio = reinterpret_cast<TSVIO>(&_read.vio);
    return true;
  case TS_API_DATA_WRITE_VIO:
    *ptr.vio = reinterpret_cast<TSVIO>(&_write.vio);
    return true;
  case TS_API_DATA_CLOSED:
    *ptr.n = _con.is_closed();
    return true;
  default:
    return false;
  }
}

VIO *
TCPNetVConnection::do_io_read(Continuation *c, int64_t nbytes, MIOBuffer *buf)
{
  if (_con.is_closed() && !(c == nullptr && nbytes == 0 && buf == nullptr)) {
    Error("do_io_read invoked on _closed this %p, cont %p, nbytes %" PRId64 ", buf %p", this, c, nbytes, buf);
    return nullptr;
  }
  _read.vio.op        = VIO::READ;
  _read.vio.mutex     = c ? c->mutex : mutex;
  _read.vio.cont      = c;
  _read.vio.nbytes    = nbytes;
  _read.vio.ndone     = 0;
  _read.vio.vc_server = this;
  if (buf) {
    _read.vio.buffer.writer_for(buf);
    if (_read.vio.is_disabled()) {
      _read.vio.reenable();
    }
  } else {
    _read.vio.buffer.clear();
    _read.vio.disable();
  }
  return &_read.vio;
}

VIO *
TCPNetVConnection::do_io_write(Continuation *c, int64_t nbytes, IOBufferReader *reader, bool owner)
{
  if (_con.is_closed() && !(c == nullptr && nbytes == 0 && reader == nullptr)) {
    Error("do_io_write invoked on _closed this %p, cont %p, nbytes %" PRId64 ", reader %p", this, c, nbytes, reader);
    return nullptr;
  }
  _write.vio.op        = VIO::WRITE;
  _write.vio.mutex     = c ? c->mutex : mutex;
  _write.vio.cont      = c;
  _write.vio.nbytes    = nbytes;
  _write.vio.ndone     = 0;
  _write.vio.vc_server = this;
  if (reader) {
    ink_assert(!owner);
    _write.vio.buffer.reader_for(reader);
    if (nbytes && _write.vio.is_disabled()) {
      _write.vio.reenable();
    }
  } else {
    _write.vio.disable();
  }
  return &_write.vio;
}

void
TCPNetVConnection::do_io_close(int alerrno /* = -1 */)
{
  // The vio continuations will be cleared in ::clear called from ::free
  _read.vio.disable();
  _write.vio.disable();
  _read.vio.nbytes = 0;
  _read.vio.op     = VIO::NONE;

  if (netvc_context == NET_VCONNECTION_OUT) {
    // do not clear the iobufs yet to guard
    // against race condition with session pool closing
    Debug("iocore_net", "delay vio buffer clear to protect against  race for this %p", this);
  } else {
    // may be okay to delay for all VCs?
    _read.vio.buffer.clear();
    _write.vio.buffer.clear();
  }

  _write.vio.nbytes = 0;
  _write.vio.op     = VIO::NONE;

  if (alerrno && alerrno != -1) {
    lerrno = alerrno;
  }

  // Must mark for _closed last in case this is a
  // cross thread migration scenario.
  _con.close();
}

void
TCPNetVConnection::do_io_shutdown(ShutdownHowTo_t howto)
{
  switch (howto) {
  case IO_SHUTDOWN_READ:
    _con.shutdown(SHUT_RD);
    _read.vio.disable();
    _read.vio.buffer.clear();
    _read.vio.nbytes = 0;
    _read.vio.cont   = nullptr;
    break;
  case IO_SHUTDOWN_WRITE:
    _con.shutdown(SHUT_WR);
    _write.vio.disable();
    _write.vio.buffer.clear();
    _write.vio.nbytes = 0;
    _write.vio.cont   = nullptr;
    break;
  case IO_SHUTDOWN_READWRITE:
    _con.shutdown(SHUT_RDWR);
    _read.vio.disable();
    _write.vio.disable();
    _read.vio.buffer.clear();
    _read.vio.nbytes = 0;
    _write.vio.buffer.clear();
    _write.vio.nbytes = 0;
    _read.vio.cont    = nullptr;
    _write.vio.cont   = nullptr;
    break;
  default:
    ink_assert(!"not reached");
  }
}

//
// Function used to reenable the VC for reading or
// writing.
//
void
TCPNetVConnection::reenable(VIO *vio)
{
  ink_release_assert(!vio->is_disabled());
  ink_release_assert(!_con.is_closed());
  if (!thread) {
    ink_assert(!"No thread?  How can this happen?");
    return;
  }
  EThread *t = vio->mutex->thread_holding;
  ink_assert(t == this_ethread());
  ink_release_assert(!_con.is_closed());

  if (vio == &_read.vio) {
    _read.state = op_state::TRY_ISSUE;
    _read_from_net();
  } else {
    _write.state = op_state::TRY_ISSUE;
    _write_to_net();
  }
}

void
TCPNetVConnection::reenable_re(VIO *vio)
{
  reenable(vio);
}

TCPNetVConnection::TCPNetVConnection(const IpEndpoint *remote, NetVCOptions *opt, EThread *t)
  : _connect_state(connect_state::WAIT), _con(*remote, opt, *get_PollDescriptor(t), *this)
{
  SET_HANDLER(&TCPNetVConnection::connectEvent);
  netvc_context   = NET_VCONNECTION_OUT;
  thread          = t;
  remote_addr     = *remote;
  got_remote_addr = true;

  _read.vio.disable();
  _write.vio.disable();

  // TODO: throttle
  // TODO: stats
}

// Private methods

void
TCPNetVConnection::onConnect(NetAIO::TCPConnection &c)
{
  NET_SUM_GLOBAL_DYN_STAT(net_connections_currently_open_stat, 1);

  _connect_state = connect_state::DONE;
  _handle_connect_done();
}

int
TCPNetVConnection::_handle_connect_done(int event, Event *e)
{
  MUTEX_TRY_LOCK(lock, action_.continuation->mutex, thread);
  if (!lock.is_locked()) {
    thread->schedule_in_local(this, HRTIME_MSECONDS(net_retry_delay));
    return EVENT_CONT;
  }

  SET_HANDLER(&TCPNetVConnection::mainEvent);
  return action_.continuation->handleEvent(NET_EVENT_OPEN, this);
}

int
TCPNetVConnection::_handle_connect_error(int event, Event *e)
{
  MUTEX_TRY_LOCK(lock, action_.continuation->mutex, thread);
  if (!lock.is_locked()) {
    ink_assert(handler == &TCPNetVConnection::connectEvent);
    thread->schedule_in_local(this, net_retry_delay);
    return EVENT_CONT;
  }

  return action_.continuation->handleEvent(NET_EVENT_OPEN_FAILED, reinterpret_cast<void *>(lerrno));
}

int
TCPNetVConnection::connectEvent(int event, void *edata)
{
  switch (_connect_state) {
  case connect_state::WAIT:
    Debug(TAG, "connectEvent: connect_state == WAIT");
    break;
  case connect_state::DONE:
    _handle_connect_done();
    return EVENT_DONE;
  case connect_state::FAILED:
    _handle_connect_error();
    return EVENT_ERROR;
  default:
    ink_release_assert(!"invalid connect state!");
  }

  return EVENT_ERROR;
}

int
TCPNetVConnection::acceptEvent(int event, void *edata)
{
  Event *e   = static_cast<Event *>(edata);
  EThread *t = (e == nullptr) ? this_ethread() : e->ethread;

  thread = t;

  // Switch mutex from NetHandler->mutex to new mutex
  mutex = new_ProxyMutex();
  SCOPED_MUTEX_LOCK(lock2, mutex, t);

  // Setup a timeout callback handler.
  SET_HANDLER(&TCPNetVConnection::mainEvent);

  if (action_.continuation->mutex != nullptr) {
    MUTEX_TRY_LOCK(lock3, action_.continuation->mutex, t);
    if (!lock3.is_locked()) {
      ink_release_assert(0);
    }
    action_.continuation->handleEvent(NET_EVENT_ACCEPT, this);
  } else {
    action_.continuation->handleEvent(NET_EVENT_ACCEPT, this);
  }
  return EVENT_DONE;
}

//
// The main event for TCPNetVConnections.
// This is called by the Event subsystem to initialize the TCPNetVConnection
// and for active and inactivity timeouts.
//
int
TCPNetVConnection::mainEvent(int event, void *edata)
{
  ink_assert(thread == this_ethread());
  Event *e = static_cast<Event *>(edata);

  MUTEX_TRY_LOCK(rlock, _read.vio.mutex ? _read.vio.mutex : e->ethread->mutex, e->ethread);
  MUTEX_TRY_LOCK(wlock, _write.vio.mutex ? _write.vio.mutex : e->ethread->mutex, e->ethread);

  if (!rlock.is_locked() || !wlock.is_locked() || (_read.vio.mutex && rlock.get_mutex() != _read.vio.mutex.get()) ||
      (_write.vio.mutex && wlock.get_mutex() != _write.vio.mutex.get())) {
    return EVENT_CONT;
  }

  if (e->cancelled) {
    return EVENT_DONE;
  }

  if (_con.is_closed()) {
    return EVENT_DONE;
  }

  switch (_read.state) {
  case op_state::IDLE:
  case op_state::WAIT_FOR_COMPLETION:
    break;
  case op_state::TRY_ISSUE:
    _read_from_net();
    break;
  case op_state::TRY_HANDLER:
    ink_assert(_read.vio.op == VIO::READ);
    _handle_read_done();
    break;
  case op_state::ERROR:
    _handle_read_error();
    break;
  default:
    ink_release_assert(!"Invalid read state");
  }

  switch (_write.state) {
  case op_state::IDLE:
  case op_state::WAIT_FOR_COMPLETION:
    break;
  case op_state::TRY_ISSUE:
    _write_to_net();
    break;
  case op_state::TRY_HANDLER:
    ink_assert(_write.vio.op == VIO::WRITE);
    _handle_write_done();
    break;
  case op_state::ERROR:
    _handle_write_error();
    break;
  default:
    ink_release_assert(!"Invalid read state");
  }

  return EVENT_DONE;
}

void
TCPNetVConnection::onClose(NetAIO::TCPConnection &c)
{
  NET_SUM_GLOBAL_DYN_STAT(net_connections_currently_open_stat, -1);
}

/*
void
TCPNetVConnection::clear()
{
  // clear variables for reuse
  mutex.clear();
  action_.mutex.clear();
  got_remote_addr = false;
  got_local_addr  = false;
  attributes      = 0;
  _read.vio.mutex.clear();
  _write.vio.mutex.clear();
  _read.vio.cont       = nullptr;
  _write.vio.cont      = nullptr;
  _read.vio.vc_server  = nullptr;
  _write.vio.vc_server = nullptr;
  options.reset();
  if (netvc_context == NET_VCONNECTION_OUT) {
    _read.vio.buffer.clear();
    _write.vio.buffer.clear();
  }
  netvc_context = NET_VCONNECTION_UNSET;
}

void
TCPNetVConnection::free(EThread *t)
{
  ink_release_assert(t == this_ethread());
  _con.close();

  clear();
  SET_CONTINUATION_HANDLER(this, &TCPNetVConnection::connectEvent);
  ink_assert(_con.is_closed());
  ink_assert(t == this_ethread());

  if (from_accept_thread) {
    tcpNetVCAllocator.free(this);
  } else {
    THREAD_FREE(this, tcpNetVCAllocator, t);
  }
}
*/

void
TCPNetVConnection::apply_options()
{
  _con.apply_options(&options);
}

void
TCPNetVConnection::add_to_keep_alive_queue()
{
  // TODO
}

void
TCPNetVConnection::remove_from_keep_alive_queue()
{
  // TODO
}

bool
TCPNetVConnection::add_to_active_queue()
{
  // TODO
  return true;
}

void
TCPNetVConnection::remove_from_active_queue()
{
  // TODO
}

int
TCPNetVConnection::populate_protocol(std::string_view *results, int n) const
{
  int retval = 0;
  if (n > retval) {
    if (!(results[retval] = options.get_proto_string()).empty()) {
      ++retval;
    }
    if (n > retval) {
      if (!(results[retval] = options.get_family_string()).empty()) {
        ++retval;
      }
    }
  }
  return retval;
}

const char *
TCPNetVConnection::protocol_contains(std::string_view tag) const
{
  std::string_view retval = options.get_proto_string();
  if (!IsNoCasePrefixOf(tag, retval)) { // didn't match IP level, check TCP level
    retval = options.get_family_string();
    if (!IsNoCasePrefixOf(tag, retval)) { // no match here either, return empty.
      ink_zero(retval);
    }
  }
  return retval.data();
}

int
TCPNetVConnection::set_tcp_congestion_control(tcp_congestion_control_t side)
{
#ifdef TCP_CONGESTION
  std::string_view ccp;

  if (side == CLIENT_SIDE) {
    ccp = net_ccp_in;
  } else {
    ccp = net_ccp_out;
  }

  if (!ccp.empty()) {
    int rv = setsockopt(con.fd, IPPROTO_TCP, TCP_CONGESTION, reinterpret_cast<const void *>(ccp.data()), ccp.size());

    if (rv < 0) {
      Error("Unable to set TCP congestion control on socket %d to \"%s\", errno=%d (%s)", con.fd, ccp.data(), errno,
            strerror(errno));
    } else {
      Debug("socket", "Setting TCP congestion control on socket [%d] to \"%s\" -> %d", con.fd, ccp.data(), rv);
    }
    return 0;
  }
  return -1;
#else
  Debug("socket", "Setting TCP congestion control is not supported on this platform.");
  return -1;
#endif
}

void
TCPNetVConnection::set_local_addr()
{
  int local_sa_size = sizeof(local_addr);
  // This call will fail if fd is closed already. That is ok, because the
  // `local_addr` is checked within get_local_addr() and the `got_local_addr`
  // is set only with a valid `local_addr`.
  ATS_UNUSED_RETURN(safe_getsockname(_con.get_fd(), &local_addr.sa, &local_sa_size));
}

// Update the internal VC state variable for MPTCP
void
TCPNetVConnection::set_mptcp_state()
{
  int mptcp_enabled      = -1;
  int mptcp_enabled_size = sizeof(mptcp_enabled);

  if (0 ==
      safe_getsockopt(_con.get_fd(), IPPROTO_TCP, MPTCP_ENABLED, reinterpret_cast<char *>(&mptcp_enabled), &mptcp_enabled_size)) {
    Debug("socket_mptcp", "MPTCP socket state: %d", mptcp_enabled);
    mptcp_state = mptcp_enabled > 0 ? true : false;
  } else {
    Debug("socket_mptcp", "MPTCP failed getsockopt(): %s", strerror(errno));
  }
}

ink_hrtime
TCPNetVConnection::get_active_timeout()
{
  // TODO
  return 0;
}

ink_hrtime
TCPNetVConnection::get_inactivity_timeout()
{
  // TODO
  return 0;
}

void
TCPNetVConnection::set_active_timeout(ink_hrtime timeout_in)
{
  // TODO
}

void
TCPNetVConnection::set_inactivity_timeout(ink_hrtime timeout_in)
{
  // TODO
}

void
TCPNetVConnection::set_default_inactivity_timeout(ink_hrtime timeout_in)
{
  // TODO
}

bool
TCPNetVConnection::is_default_inactivity_timeout()
{
  // TODO
  return false;
}

void
TCPNetVConnection::cancel_inactivity_timeout()
{
  // TODO
}

void
TCPNetVConnection::cancel_active_timeout()
{
  // TODO
}

TCPNetVConnection::~TCPNetVConnection() {}

SOCKET
TCPNetVConnection::get_socket()
{
  return _con.get_fd();
}

void
TCPNetVConnection::set_action(Continuation *c)
{
  action_ = c;
}

const Action *
TCPNetVConnection::get_action() const
{
  return &action_;
}

void
TCPNetVConnection::set_remote_addr()
{
  ink_release_assert(!"not implemented");
}

void
TCPNetVConnection::set_remote_addr(const sockaddr *new_sa)
{
  ink_release_assert(!"not implemented");
}
