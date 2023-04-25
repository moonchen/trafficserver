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
#include "NetAIO.h"
#include "NetVCOptions.h"
#include "P_Net.h"
#include "P_UnixNet.h"
#include "tscore/ink_assert.h"
#include "tscore/ink_inet.h"
#include "tscore/ink_platform.h"
#include "tscore/InkErrno.h"

// Global
ClassAllocator<TCPNetVConnection> tcpNetVCAllocator("tcpNetVCAllocator");
static constexpr auto TAG = "TCPNetVConnection";

//
// Reschedule a TCPNetVConnection by moving it
// onto or off of the ready_list
//
void
TCPNetVConnection::_read_reschedule()
{
  ink_release_assert(this_ethread() == thread);
  SET_HANDLER(&TCPNetVConnection::_read_from_net);
  thread->schedule_imm_local(this);
}

void
TCPNetVConnection::_write_reschedule()
{
  ink_release_assert(this_ethread() == thread);
  SET_HANDLER(&TCPNetVConnection::_write_to_net);
  thread->schedule_imm_local(this);
}

//
// Signal an event
//
int
TCPNetVConnection::_read_signal_and_update(int event)
{
  _recursion++;
  if (_read_vio.cont && _read_vio.mutex == _read_vio.cont->mutex) {
    _read_vio.cont->handleEvent(event, &_read_vio);
  } else {
    if (_read_vio.cont) {
      Note("_read_signal_and_update: mutexes are different? this=%p, event=%d", this, event);
    }
    switch (event) {
    case VC_EVENT_EOS:
    case VC_EVENT_ERROR:
    case VC_EVENT_ACTIVE_TIMEOUT:
    case VC_EVENT_INACTIVITY_TIMEOUT:
      Debug("inactivity_cop", "event %d: null _read_vio cont, closing this %p", event, this);
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
  if (_write_vio.cont && _write_vio.mutex == _write_vio.cont->mutex) {
    _write_vio.cont->handleEvent(event, &_write_vio);
  } else {
    if (_write_vio.cont) {
      Note("_write_signal_and_update: mutexes are different? this=%p, event=%d", this, event);
    }
    switch (event) {
    case VC_EVENT_EOS:
    case VC_EVENT_ERROR:
    case VC_EVENT_ACTIVE_TIMEOUT:
    case VC_EVENT_INACTIVITY_TIMEOUT:
      Debug("inactivity_cop", "event %d: null _write_vio cont, closing this %p", event, this);
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
  _read_vio.disable();
  if (_read_signal_and_update(event) == EVENT_DONE) {
    return EVENT_DONE;
  } else {
    _read_reschedule();
    return EVENT_CONT;
  }
}

int
TCPNetVConnection::_write_signal_done(int event)
{
  _write_vio.disable();
  if (_write_signal_and_update(event) == EVENT_DONE) {
    return EVENT_DONE;
  } else {
    _write_reschedule();
    return EVENT_CONT;
  }
}

int
TCPNetVConnection::_read_signal_error(int lerrno)
{
  this->lerrno = lerrno;
  return _read_signal_done(VC_EVENT_ERROR);
}

int
TCPNetVConnection::_write_signal_error(int lerrno)
{
  this->lerrno = lerrno;
  return _write_signal_done(VC_EVENT_ERROR);
}

int
TCPNetVConnection::_read_from_net(int event, Event *e)
{
  // We need to hold this mutex until the read finishes
  MUTEX_TRY_LOCK(lock, _read_vio.mutex, thread);

  if (!lock.is_locked()) {
    _read_reschedule();
    return EVENT_CONT;
  };

  if (_con.is_closed()) {
    return EVENT_DONE;
  }
  // if it is not enabled.
  if (_read_vio.op != VIO::READ || _read_vio.is_disabled()) {
    // TODO: cancel?
    return EVENT_DONE;
  }

  MIOBufferAccessor &buf = _read_vio.buffer;
  ink_assert(buf.writer());

  // if there is nothing to do, disable connection
  int64_t ntodo = _read_vio.ntodo();
  if (ntodo <= 0) {
    return EVENT_DONE;
  }

  int64_t toread = buf.writer()->write_avail();
  if (toread > ntodo) {
    toread = ntodo;
  }

  // read data
  int64_t rattempted = 0;
  unsigned niov      = 0;
  IOVec tiovec[NET_MAX_IOV];
  if (toread) {
    IOBufferBlock *b = buf.writer()->first_write_block();
    niov             = 0;
    rattempted       = 0;
    while (b && niov < NET_MAX_IOV) {
      int64_t a = b->write_avail();
      if (a > 0) {
        tiovec[niov].iov_base = b->_end;
        int64_t togo          = toread - rattempted;
        if (a > togo) {
          a = togo;
        }
        tiovec[niov].iov_len = a;
        rattempted           += a;
        niov++;
        if (a >= togo) {
          break;
        }
      }
      b = b->next.get();
    }

    ink_assert(niov > 0);
    ink_assert(niov <= countof(tiovec));
    auto msg = std::make_unique<struct msghdr>();

    ink_zero(msg);
    msg->msg_name    = const_cast<sockaddr *>(get_remote_addr());
    msg->msg_namelen = ats_ip_size(get_remote_addr());
    msg->msg_iov     = &tiovec[0];
    msg->msg_iovlen  = niov;
    auto ret         = _con.recvmsg(std::move(msg), 0);
    if (!ret) {
      Error("recvmsg failed");
      return EVENT_ERROR;
    } else {
      NET_INCREMENT_DYN_STAT(net_calls_to_read_stat);
      _read_state.lock = std::move(lock);
    }
  }

  return EVENT_CONT;
}

void
TCPNetVConnection::onRecvmsg(ssize_t bytes, std::unique_ptr<struct msghdr> msg, NetAIO::TCPConnection &c)
{
  ink_release_assert(&c == &_con);
  ink_release_assert(_read_state.lock && _read_state.lock->is_locked());
  ink_release_assert(_read_vio.mutex->thread_holding == this_ethread());
  ink_release_assert(_read_vio.op == VIO::READ);
  ink_release_assert(!_read_vio.is_disabled());

  _read_state.r        = bytes;
  _read_state.finished = true;
  SET_HANDLER(&TCPNetVConnection::mainEvent);
  thread->schedule_imm_local(this);

  // let msg get freed here
}

void
TCPNetVConnection::onError(NetAIO::ErrorSource source, int err, NetAIO::TCPConnection &c)
{
  ink_release_assert(&c == &_con);

  // Failed connection
  if (source == NetAIO::ES_CONNECT || source == NetAIO::ES_SOCKET || source == NetAIO::ES_BIND) {
    action_.continuation->handleEvent(NET_EVENT_OPEN_FAILED, reinterpret_cast<void *>(err));
    return;
  }

  // Handle EOS
  if (source == NetAIO::ES_RECVMSG && err == ECONNRESET) {
    _read_signal_done(VC_EVENT_EOS);
    return;
  }

  if (source == NetAIO::ES_SENDMSG) {
    _write_signal_error(err);
    return;
  }

  // TODO: close this NetVConnection
  c.close();
}

// Handle the completion of an async read of the underlying connection.
// Errors should not be handled here.
int
TCPNetVConnection::_handle_read_done(int event, Event *e)
{
  ink_release_assert(_read_state.lock);
  auto lock = std::move(_read_state.lock.value());
  int r     = _read_state.r;

  ink_release_assert(lock.is_locked());
  ink_release_assert(lock.get_mutex()->thread_holding == this_ethread());
  ink_release_assert(r > 0);

  NET_SUM_DYN_STAT(net_read_bytes_stat, r);

  // Add data to buffer and signal continuation.
  MIOBufferAccessor &buf = _read_vio.buffer;
  ink_assert(buf.writer());
  buf.writer()->fill(r);
#ifdef DEBUG
  if (buf.writer()->write_avail() <= 0) {
    Debug(TAG, "_read_from_net, read buffer full");
  }
#endif
  _read_vio.ndone += r;

  // Signal read ready, check if user is not done

  // If there are no more bytes to read, signal read complete
  if (_read_vio.ntodo() <= 0) {
    _read_signal_done(VC_EVENT_READ_COMPLETE);
    Debug("iocore_net", "read_from_net, read finished - signal done");
    return EVENT_DONE;
  } else {
    if (_read_signal_and_update(VC_EVENT_READ_READY) != EVENT_CONT) {
      return EVENT_DONE;
    }

    // change of lock... don't look at shared variables!
    if (lock.get_mutex() != _read_vio.mutex.get()) {
      _read_reschedule();
      return EVENT_CONT;
    }
  }

  // If here are is no more room, or nothing to do, disable the connection
  if (_read_vio.ntodo() <= 0 || _read_vio.is_disabled() || !buf.writer()->write_avail()) {
    return EVENT_DONE;
  } else {
    _read_reschedule();
    return EVENT_CONT;
  }
}

// Begin writing to the underlying connection.  Schedule retry if
// necessary.
int
TCPNetVConnection::_write_to_net(int event, Event *e)
{
  ProxyMutex *mutex = thread->mutex.get();

  NET_INCREMENT_DYN_STAT(net_calls_to_writetonet_stat);

  MUTEX_TRY_LOCK(lock, _write_vio.mutex, thread);

  if (!lock.is_locked() || lock.get_mutex() != _write_vio.mutex.get()) {
    _write_reschedule();
    return EVENT_CONT;
  }

  if (_con.is_connecting()) {
    _write_reschedule();
    return EVENT_CONT;
  }

  // If it is not enabled,add to WaitList.
  if (_write_vio.is_disabled() || _write_vio.op != VIO::WRITE) {
    return EVENT_DONE;
  }

  // If there is nothing to do, disable
  int64_t ntodo = _write_vio.ntodo();
  if (ntodo <= 0) {
    return EVENT_DONE;
  }

  MIOBufferAccessor &buf = _write_vio.buffer;
  ink_assert(buf.writer());

  // Calculate the amount to write.
  int64_t towrite = buf.reader()->read_avail();
  if (towrite > ntodo) {
    towrite = ntodo;
  }

  _write_state.signalled = 0;

  // signal write ready to allow user to fill the buffer
  if (towrite != ntodo && !buf.writer()->high_water()) {
    if (_write_signal_and_update(VC_EVENT_WRITE_READY) != EVENT_CONT) {
      return EVENT_DONE;
    }

    _write_state.signalled = 1;

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

  IOVec tiovec[NET_MAX_IOV];
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
    tiovec[niov].iov_len  = len;
    tiovec[niov].iov_base = tmp_reader->start();
    niov++;

    try_to_write += len;
    tmp_reader->consume(len);
  }

  ink_assert(niov > 0);
  ink_assert(niov <= countof(tiovec));

  auto msg = std::make_unique<struct msghdr>();
  ink_zero(msg);
  msg->msg_name    = const_cast<sockaddr *>(get_remote_addr());
  msg->msg_namelen = ats_ip_size(get_remote_addr());
  msg->msg_iov     = &tiovec[0];
  msg->msg_iovlen  = niov;
  int flags        = 0;

  auto ret = _con.sendmsg(std::move(msg), flags);
  if (!ret) {
    Error("sendmsg failed");
    return EVENT_ERROR;
  }
  _write_state.lock = std::move(lock);

  NET_INCREMENT_DYN_STAT(net_calls_to_write_stat);

  return EVENT_DONE;
}

void
TCPNetVConnection::onSendmsg(ssize_t bytes, std::unique_ptr<struct msghdr> msg, NetAIO::TCPConnection &c)
{
  ink_release_assert(&c == &_con);
  ink_release_assert(_write_state.lock && _write_state.lock->is_locked());
  ink_release_assert(_write_vio.mutex->thread_holding == this_ethread());
  ink_release_assert(_write_vio.op == VIO::WRITE);
  ink_release_assert(!_write_vio.is_disabled());

  _write_state.r        = bytes;
  _write_state.finished = true;
  SET_HANDLER(&TCPNetVConnection::mainEvent);
  thread->schedule_imm_local(this);

  // let msg get freed here
}

int
TCPNetVConnection::_handle_write_done(int event, Event *e)
{
  ink_release_assert(_write_state.lock);
  auto lock              = std::move(_write_state.lock.value());
  auto r                 = _write_state.r;
  MIOBufferAccessor &buf = _write_vio.buffer;

  // A write of 0 makes no sense since we tried to write more than 0.
  ink_assert(r > 0);

  if (r > 0) {
    buf.reader()->consume(r);
    NET_SUM_DYN_STAT(net_write_bytes_stat, r);
    _write_vio.ndone += r;
  }

  // Either we wrote something or got an error.
  // check for errors
  int wbe_event = write_buffer_empty_event; // save so we can clear if needed.

  // If the empty write buffer trap is set, clear it.
  if (!(buf.reader()->is_read_avail_more_than(0))) {
    write_buffer_empty_event = 0;
  }

  // If there are no more bytes to write, signal write complete,
  ink_assert(_write_vio.ntodo() >= 0);
  if (_write_vio.ntodo() <= 0) {
    _write_signal_done(VC_EVENT_WRITE_COMPLETE);
    return EVENT_DONE;
  }

  int event_out = 0;
  if (!_write_state.signalled || (_write_vio.ntodo() > 0 && !buf.writer()->high_water())) {
    event_out = VC_EVENT_WRITE_READY;
  } else if (wbe_event != write_buffer_empty_event) {
    // @a signalled means we won't send an event, and the event values differing means we
    // had a write buffer trap and cleared it, so we need to send it now.
    event_out = wbe_event;
  }

  if (event_out) {
    if (_write_signal_and_update(event_out) != EVENT_CONT) {
      return EVENT_DONE;
    }

    // change of lock... don't look at shared variables!
    if (lock.get_mutex() != _write_vio.mutex.get()) {
      _write_reschedule();
      return EVENT_CONT;
    }
  }

  if (!(buf.reader()->is_read_avail_more_than(0))) {
    return EVENT_DONE;
  } else {
    _write_reschedule();
    return EVENT_DONE;
  }
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
    *ptr.vio = reinterpret_cast<TSVIO>(&_read_vio);
    return true;
  case TS_API_DATA_WRITE_VIO:
    *ptr.vio = reinterpret_cast<TSVIO>(&_write_vio);
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
  _read_vio.op        = VIO::READ;
  _read_vio.mutex     = c ? c->mutex : mutex;
  _read_vio.cont      = c;
  _read_vio.nbytes    = nbytes;
  _read_vio.ndone     = 0;
  _read_vio.vc_server = this;
  if (buf) {
    _read_vio.buffer.writer_for(buf);
    if (_read_vio.is_disabled()) {
      _read_vio.reenable();
    }
  } else {
    _read_vio.buffer.clear();
    _read_vio.disable();
  }
  return &_read_vio;
}

VIO *
TCPNetVConnection::do_io_write(Continuation *c, int64_t nbytes, IOBufferReader *reader, bool owner)
{
  if (_con.is_closed() && !(c == nullptr && nbytes == 0 && reader == nullptr)) {
    Error("do_io_write invoked on _closed this %p, cont %p, nbytes %" PRId64 ", reader %p", this, c, nbytes, reader);
    return nullptr;
  }
  _write_vio.op        = VIO::WRITE;
  _write_vio.mutex     = c ? c->mutex : mutex;
  _write_vio.cont      = c;
  _write_vio.nbytes    = nbytes;
  _write_vio.ndone     = 0;
  _write_vio.vc_server = this;
  if (reader) {
    ink_assert(!owner);
    _write_vio.buffer.reader_for(reader);
    if (nbytes && _write_vio.is_disabled()) {
      _write_vio.reenable();
    }
  } else {
    _write_vio.disable();
  }
  return &_write_vio;
}

void
TCPNetVConnection::do_io_close(int alerrno /* = -1 */)
{
  // The vio continuations will be cleared in ::clear called from ::free
  _read_vio.disable();
  _write_vio.disable();
  _read_vio.nbytes = 0;
  _read_vio.op     = VIO::NONE;

  if (netvc_context == NET_VCONNECTION_OUT) {
    // do not clear the iobufs yet to guard
    // against race condition with session pool closing
    Debug("iocore_net", "delay vio buffer clear to protect against  race for this %p", this);
  } else {
    // may be okay to delay for all VCs?
    _read_vio.buffer.clear();
    _write_vio.buffer.clear();
  }

  _write_vio.nbytes = 0;
  _write_vio.op     = VIO::NONE;

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
    _read_vio.disable();
    _read_vio.buffer.clear();
    _read_vio.nbytes = 0;
    _read_vio.cont   = nullptr;
    break;
  case IO_SHUTDOWN_WRITE:
    _con.shutdown(SHUT_WR);
    _write_vio.disable();
    _write_vio.buffer.clear();
    _write_vio.nbytes = 0;
    _write_vio.cont   = nullptr;
    break;
  case IO_SHUTDOWN_READWRITE:
    _con.shutdown(SHUT_RDWR);
    _read_vio.disable();
    _write_vio.disable();
    _read_vio.buffer.clear();
    _read_vio.nbytes = 0;
    _write_vio.buffer.clear();
    _write_vio.nbytes = 0;
    _read_vio.cont    = nullptr;
    _write_vio.cont   = nullptr;
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

  if (vio == &_read_vio) {
    _read_from_net();
  } else {
    _write_to_net();
  }
}

void
TCPNetVConnection::reenable_re(VIO *vio)
{
  reenable(vio);
}

TCPNetVConnection::TCPNetVConnection(const IpEndpoint *target, NetVCOptions *opt, EThread *t)
  : _con(*target, opt, *get_PollDescriptor(t), *this)
{
  SET_HANDLER(&TCPNetVConnection::startEvent);
  netvc_context = NET_VCONNECTION_OUT;
}

// Private methods

void
TCPNetVConnection::onConnect(NetAIO::TCPConnection &c)
{
  SET_HANDLER(&TCPNetVConnection::mainEvent);
  NET_SUM_GLOBAL_DYN_STAT(net_connections_currently_open_stat, 1);
  action_.continuation->handleEvent(NET_EVENT_OPEN, this);
}

int
TCPNetVConnection::acceptEvent(int event, Event *e)
{
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
TCPNetVConnection::mainEvent(int event, Event *e)
{
  ink_assert(event == VC_EVENT_ACTIVE_TIMEOUT || event == VC_EVENT_INACTIVITY_TIMEOUT);
  ink_assert(thread == this_ethread());

  ink_release_assert(_read_vio.mutex != _write_vio.mutex);
  MUTEX_TRY_LOCK(rlock, _read_vio.mutex ? _read_vio.mutex : e->ethread->mutex, e->ethread);
  MUTEX_TRY_LOCK(wlock, _write_vio.mutex ? _write_vio.mutex : e->ethread->mutex, e->ethread);

  if (!rlock.is_locked() || !wlock.is_locked() || (_read_vio.mutex && rlock.get_mutex() != _read_vio.mutex.get()) ||
      (_write_vio.mutex && wlock.get_mutex() != _write_vio.mutex.get())) {
    return EVENT_CONT;
  }

  if (e->cancelled) {
    return EVENT_DONE;
  }

  if (_con.is_closed()) {
    return EVENT_DONE;
  }

  if (_read_state.finished) {
    ink_assert(_read_vio.op == VIO::READ);
    _read_state.finished = false;
    _handle_read_done();
  }

  if (_write_state.finished) {
    ink_assert(_read_vio.op == VIO::WRITE);
    _write_state.finished = false;
    _handle_write_done();
  }
  return EVENT_DONE;
}

int
TCPNetVConnection::startEvent(int event, Event *e)
{
  return EVENT_CONT;
}

void
TCPNetVConnection::clear()
{
  // clear variables for reuse
  mutex.clear();
  action_.mutex.clear();
  got_remote_addr = false;
  got_local_addr  = false;
  attributes      = 0;
  _read_vio.mutex.clear();
  _write_vio.mutex.clear();
  _read_vio.cont       = nullptr;
  _write_vio.cont      = nullptr;
  _read_vio.vc_server  = nullptr;
  _write_vio.vc_server = nullptr;
  options.reset();
  if (netvc_context == NET_VCONNECTION_OUT) {
    _read_vio.buffer.clear();
    _write_vio.buffer.clear();
  }
  netvc_context = NET_VCONNECTION_UNSET;
}

void
TCPNetVConnection::onClose(NetAIO::TCPConnection &c)
{
  NET_SUM_GLOBAL_DYN_STAT(net_connections_currently_open_stat, -1);
}

void
TCPNetVConnection::free(EThread *t)
{
  ink_release_assert(t == this_ethread());
  _con.close();

  clear();
  SET_CONTINUATION_HANDLER(this, &TCPNetVConnection::startEvent);
  ink_assert(_con.is_closed());
  ink_assert(t == this_ethread());

  if (from_accept_thread) {
    tcpNetVCAllocator.free(this);
  } else {
    THREAD_FREE(this, tcpNetVCAllocator, t);
  }
}

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
TCPNetVConnection::set_tcp_congestion_control(int side)
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
