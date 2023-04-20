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
#include "I_IOBuffer.h"
#include "NetAIO.h"
#include "P_Net.h"
#include "tscore/ink_assert.h"
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
  ink_release_assert(_read_state.lock.is_locked());
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
  // Handle EOS
  if (source == NetAIO::ES_RECVMSG && err == ECONNRESET) {
    _read_signal_done(VC_EVENT_EOS);
    return;
  }

  if (source == NetAIO::ES_SENDMSG) {
    _write_signal_error(err);
  }
  // TODO: close this NetVConnection
}

// Handle the completion of an async read of the underlying connection.
// Errors should not be handled here.
int
TCPNetVConnection::_handle_read_done(int event, Event *e)
{
  auto lock = std::move(_read_state.lock);
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

int
TCPNetVConnection::_handle_write_done(int event, Event *e)
{
  auto lock              = std::move(_write_state.lock);
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
  _read_vio.vc_server = (VConnection *)this;
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
  _write_vio.vc_server = (VConnection *)this;
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

TCPNetVConnection::TCPNetVConnection()
{
  SET_HANDLER(&TCPNetVConnection::startEvent);
}

// Private methods

int
TCPNetVConnection::startEvent(int /* event ATS_UNUSED */, Event *e)
{
  if (!action_.cancelled) {
    connectUp(e->ethread, NO_FD);
  }
  return EVENT_DONE;
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

  int signal_event;
  Continuation *reader_cont = nullptr;
  Continuation *writer_cont = nullptr;

  writer_cont = _write_vio.cont;

  if (_con.is_closed()) {
    return EVENT_DONE;
  }

  if (_read_state.finished) {
    ink_assert(_read_vio.op == VIO::READ);
    reader_cont = _read_vio.cont;
    _handle_read_done();
    if (_read_signal_and_update(signal_event) == EVENT_DONE) {
      return EVENT_DONE;
    }
  }

  if (_write_vio.op == VIO::WRITE && !_con.is_shutdown_write() && reader_cont != _write_vio.cont &&
      writer_cont == _write_vio.cont) {
    if (_write_signal_and_update(signal_event) == EVENT_DONE) {
      return EVENT_DONE;
    }
  }
  return EVENT_DONE;
}

int
TCPNetVConnection::connectUp(EThread *t, int fd)
{
  int res;

  thread = t;
  /*
  // TODO: check throttle
  if (check_net_throttle(CONNECT)) {
    check_throttle_warning(CONNECT);
    res = -ENET_THROTTLING;
    NET_INCREMENT_DYN_STAT(net_connections_throttled_out_stat);
    goto fail;
  }
  */

  //
  // Initialize this TCPNetVConnection
  //
  if (is_debug_tag_set("iocore_net")) {
    char addrbuf[INET6_ADDRSTRLEN];
    Debug("iocore_net", "connectUp:: local_addr=%s:%d [%s]",
          options.local_ip.isValid() ? options.local_ip.toString(addrbuf, sizeof(addrbuf)) : "*", options.local_port,
          NetVCOptions::toString(options.addr_binding));
  }

  // If this is getting called from the TS API, then we are wiring up a file descriptor
  // provided by the caller. In that case, we know that the socket is already connected.
  if (fd == NO_FD) {
    // Due to multi-threads system, the fd returned from con.open() may exceed the limitation of check_net_throttle().
    _con = std::move(NetAIO::TCPConnection{remote, opt, pd, observer});
    res  = con._open(options);
    if (res != 0) {
      goto fail;
    }
  } else {
    int len = sizeof(con.sock_type);

    // This call will fail if fd is not a socket (e.g. it is a
    // eventfd or a regular file fd.  That is ok, because sock_type
    // is only used when setting up the socket.
    safe_getsockopt(fd, SOL_SOCKET, SO_TYPE, reinterpret_cast<char *>(&con.sock_type), &len);
    safe_nonblocking(fd);
    con.fd           = fd;
    con.is_connected = true;
    con.is_bound     = true;
  }

  // Must connect after EventIO::Start() to avoid a race condition
  // when edge triggering is used.
  if ((res = get_NetHandler(t)->startIO(this)) < 0) {
    goto fail;
  }

  if (fd == NO_FD) {
    res = con._connect(nullptr, options);
    if (res != 0) {
      // fast stopIO
      goto fail;
    }
  }

  // Did not fail, increment connection count
  NET_SUM_GLOBAL_DYN_STAT(net_connections_currently_open_stat, 1);
  ink_release_assert(con.fd != NO_FD);

  // Setup a timeout callback handler.
  SET_HANDLER(&TCPNetVConnection::mainEvent);
  // Send this netvc to InactivityCop.
  nh->startCop(this);

  set_inactivity_timeout(0);
  ink_assert(!active_timeout_in);
  set_local_addr();
  action_.continuation->handleEvent(NET_EVENT_OPEN, this);
  return CONNECT_SUCCESS;

fail:
  lerrno = -res;
  action_.continuation->handleEvent(NET_EVENT_OPEN_FAILED, (void *)static_cast<intptr_t>(res));
  if (fd != NO_FD) {
    con.fd = NO_FD;
  }
  if (nullptr != nh) {
    nh->free_netevent(this);
  } else {
    free(t);
  }
  return CONNECT_FAILURE;
}

void
TCPNetVConnection::clear()
{
  // clear timeout variables
  next_inactivity_timeout_at = 0;
  next_activity_timeout_at   = 0;
  inactivity_timeout_in      = 0;
  active_timeout_in          = 0;

  // clear variables for reuse
  mutex.clear();
  action_.mutex.clear();
  got_remote_addr = false;
  got_local_addr  = false;
  attributes      = 0;
  _read_vio.mutex.clear();
  _write_vio.mutex.clear();
  flags                = 0;
  nh                   = nullptr;
  read.triggered       = 0;
  write.triggered      = 0;
  read.enabled         = 0;
  write.enabled        = 0;
  _read_vio.cont       = nullptr;
  _write_vio.cont      = nullptr;
  _read_vio.vc_server  = nullptr;
  _write_vio.vc_server = nullptr;
  options.reset();
  if (netvc_context == NET_VCONNECTION_OUT) {
    _read_vio.buffer.clear();
    _write_vio.buffer.clear();
  }
  _closed       = 0;
  netvc_context = NET_VCONNECTION_UNSET;
  ink_assert(!read.ready_link.prev && !read.ready_link.next);
  ink_assert(!read.enable_link.next);
  ink_assert(!write.ready_link.prev && !write.ready_link.next);
  ink_assert(!write.enable_link.next);
  ink_assert(!link.next && !link.prev);
}

void
TCPNetVConnection::free(EThread *t)
{
  ink_release_assert(t == this_ethread());

  // close socket fd
  if (con.fd != NO_FD) {
    NET_SUM_GLOBAL_DYN_STAT(net_connections_currently_open_stat, -1);
  }
  con._close();

  clear();
  SET_CONTINUATION_HANDLER(this, &TCPNetVConnection::startEvent);
  ink_assert(con.fd == NO_FD);
  ink_assert(t == this_ethread());

  if (from_accept_thread) {
    netVCAllocator.free(this);
  } else {
    THREAD_FREE(this, netVCAllocator, t);
  }
}

void
TCPNetVConnection::apply_options()
{
  con._apply_options(options);
}

TS_INLINE void
TCPNetVConnection::set_inactivity_timeout(ink_hrtime timeout_in)
{
  Debug("socket", "Set inactive timeout=%" PRId64 ", for NetVC=%p", timeout_in, this);
  inactivity_timeout_in      = timeout_in;
  next_inactivity_timeout_at = (timeout_in > 0) ? Thread::get_hrtime() + inactivity_timeout_in : 0;
}

TS_INLINE void
TCPNetVConnection::set_default_inactivity_timeout(ink_hrtime timeout_in)
{
  Debug("socket", "Set default inactive timeout=%" PRId64 ", for NetVC=%p", timeout_in, this);
  default_inactivity_timeout_in = timeout_in;
}

TS_INLINE bool
TCPNetVConnection::is_default_inactivity_timeout()
{
  return (use_default_inactivity_timeout && inactivity_timeout_in == 0);
}

/*
 * Close down the current netVC.  Save aside the socket and SSL information
 * and create new netVC in the current thread/netVC
 */
TCPNetVConnection *
TCPNetVConnection::migrateToCurrentThread(Continuation *cont, EThread *t)
{
  // TODO
  ink_release_assert(false);
  return nullptr;
}

NetProcessor *
TCPNetVConnection::_getNetProcessor()
{
  return &netProcessor;
}

void
TCPNetVConnection::add_to_keep_alive_queue()
{
  MUTEX_TRY_LOCK(lock, nh->mutex, this_ethread());
  if (lock.is_locked()) {
    nh->add_to_keep_alive_queue(this);
  } else {
    ink_release_assert(!"BUG: It must have acquired the NetHandler's lock before doing anything on keep_alive_queue.");
  }
}

void
TCPNetVConnection::remove_from_keep_alive_queue()
{
  MUTEX_TRY_LOCK(lock, nh->mutex, this_ethread());
  if (lock.is_locked()) {
    nh->remove_from_keep_alive_queue(this);
  } else {
    ink_release_assert(!"BUG: It must have acquired the NetHandler's lock before doing anything on keep_alive_queue.");
  }
}

bool
TCPNetVConnection::add_to_active_queue()
{
  bool result = false;

  MUTEX_TRY_LOCK(lock, nh->mutex, this_ethread());
  if (lock.is_locked()) {
    result = nh->add_to_active_queue(this);
  } else {
    ink_release_assert(!"BUG: It must have acquired the NetHandler's lock before doing anything on active_queue.");
  }
  return result;
}

void
TCPNetVConnection::remove_from_active_queue()
{
  MUTEX_TRY_LOCK(lock, nh->mutex, this_ethread());
  if (lock.is_locked()) {
    nh->remove_from_active_queue(this);
  } else {
    ink_release_assert(!"BUG: It must have acquired the NetHandler's lock before doing anything on active_queue.");
  }
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
TCPNetVConnection::set_remote_addr()
{
  ats_ip_copy(&remote_addr, &con.addr);
  this->control_flags.set_flag(ContFlags::DEBUG_OVERRIDE, diags()->test_override_ip(remote_addr));
  set_cont_flags(get_control_flags());
}

void
TCPNetVConnection::set_remote_addr(const sockaddr *new_sa)
{
  ats_ip_copy(&remote_addr, new_sa);
  this->control_flags.set_flag(ContFlags::DEBUG_OVERRIDE, diags()->test_override_ip(remote_addr));
  set_cont_flags(get_control_flags());
}

void
TCPNetVConnection::set_local_addr()
{
  int local_sa_size = sizeof(local_addr);
  // This call will fail if fd is closed already. That is ok, because the
  // `local_addr` is checked within get_local_addr() and the `got_local_addr`
  // is set only with a valid `local_addr`.
  ATS_UNUSED_RETURN(safe_getsockname(con.fd, &local_addr.sa, &local_sa_size));
}

// Update the internal VC state variable for MPTCP
void
TCPNetVConnection::set_mptcp_state()
{
  int mptcp_enabled      = -1;
  int mptcp_enabled_size = sizeof(mptcp_enabled);

  if (0 == safe_getsockopt(con.fd, IPPROTO_TCP, MPTCP_ENABLED, (char *)&mptcp_enabled, &mptcp_enabled_size)) {
    Debug("socket_mptcp", "MPTCP socket state: %d", mptcp_enabled);
    mptcp_state = mptcp_enabled > 0 ? true : false;
  } else {
    Debug("socket_mptcp", "MPTCP failed getsockopt(): %s", strerror(errno));
  }
}

ink_hrtime
TCPNetVConnection::get_active_timeout()
{
  return active_timeout_in;
}

ink_hrtime
TCPNetVConnection::get_inactivity_timeout()
{
  return inactivity_timeout_in;
}

void
TCPNetVConnection::set_active_timeout(ink_hrtime timeout_in)
{
  Debug("socket", "Set active timeout=%" PRId64 ", NetVC=%p", timeout_in, this);
  active_timeout_in        = timeout_in;
  next_activity_timeout_at = (active_timeout_in > 0) ? Thread::get_hrtime() + timeout_in : 0;
}

void
TCPNetVConnection::cancel_inactivity_timeout()
{
  Debug("socket", "Cancel inactive timeout for NetVC=%p", this);
  inactivity_timeout_in      = 0;
  next_inactivity_timeout_at = 0;
}

void
TCPNetVConnection::cancel_active_timeout()
{
  Debug("socket", "Cancel active timeout for NetVC=%p", this);
  active_timeout_in        = 0;
  next_activity_timeout_at = 0;
}

TCPNetVConnection::~TCPNetVConnection() {}

SOCKET
TCPNetVConnection::get_socket()
{
  return con.fd;
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
