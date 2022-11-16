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

#include "I_Continuation.h"
#include "I_IO_URING.h"
#include "I_NetVConnection.h"
#include "P_IOUringNet.h"
#include "P_IOUringNetVConnection.h"
#include "liburing.h"
#include "tscore/ink_assert.h"
#include "tscore/InkErrno.h"
#include <liburing/io_uring.h>

constexpr auto TAG = "io_uring";
static int
get_next_connection_id()
{
  static std::atomic<int> next_connection_id{0};
  return next_connection_id++;
}

IOUringNetVConnection::IOUringNetVConnection() : id(get_next_connection_id()), closed(false)
{
  SET_HANDLER(&IOUringNetVConnection::startEvent);
}

IOUringNetVConnection::~IOUringNetVConnection() {}

void
IOUringNetVConnection::prep_read()
{
  ink_assert(thread == this_ethread());
  if (!read.enabled) {
    return;
  }

  /*
  // TODO: is it necessary to hold the read.vio.mutex here?
  // TODO(mo): If so, we need to figure out a way to reschedule this.
  MUTEX_TRY_LOCK(lock, read.vio.mutex, thread);
  if (!lock.is_locked()) {
    // Reschedule
    SET_HANDLER(&IOUringNetVConnection::prep_read);
    this_ethread()->schedule_imm(this);
    return EVENT_DONE;
  }
  */

  MIOBufferAccessor &buf = read.vio.buffer;
  ink_assert(buf.writer());
  /*
  if (buf.high_water()) {
  }
  */

  // if there is nothing to do, do nothing
  int64_t ntodo = read.vio.ntodo();
  if (ntodo <= 0) {
    return;
  }

  int64_t toread = buf.writer()->write_avail();
  if (toread > ntodo) {
    toread = ntodo;
  }

  io_uring_sqe *sqe = IOUringContext::local_context()->next_sqe(&read);
  ink_assert(sqe != nullptr);

  // prepare an sqe to read data
  int64_t rattempted = 0, total_read = 0;
  unsigned niov = 0;
  IOVec tiovec[NET_MAX_IOV];
  if (toread) {
    IOBufferBlock *b = buf.writer()->first_write_block();
    niov             = 0;
    rattempted       = 0;
    while (b && niov < NET_MAX_IOV) {
      int64_t a = b->write_avail();
      if (a > 0) {
        tiovec[niov].iov_base = b->_end;
        int64_t togo          = toread - total_read - rattempted;
        if (a > togo) {
          a = togo;
        }
        tiovec[niov].iov_len = a;
        rattempted += a;
        niov++;
        if (a >= togo) {
          break;
        }
      }
      b = b->next.get();
    }

    ink_assert(niov > 0);
    ink_assert(niov <= countof(tiovec));
    struct msghdr msg;

    ink_zero(msg);
    msg.msg_name    = const_cast<sockaddr *>(get_remote_addr());
    msg.msg_namelen = ats_ip_size(get_remote_addr());
    msg.msg_iov     = &tiovec[0];
    msg.msg_iovlen  = niov;

    // TODO(mo): retain buffer blocks

    io_uring_prep_recvmsg(sqe, con.fd, &msg, 0);
    Debug(TAG, "prep_recvmsg, op = %p", &read);

    NET_INCREMENT_DYN_STAT(net_calls_to_read_stat);

    total_read += rattempted;
  }
}

int
IOUringNetVConnection::write_signal_and_update(int event)
{
  recursion++;
  if (write.vio.cont && write.vio.mutex == write.vio.cont->mutex) {
    write.vio.cont->handleEvent(event, &write.vio);
  } else {
    if (write.vio.cont) {
      Note("write_signal_and_update: mutexes are different? vc=%p, event=%d", this, event);
    }
    switch (event) {
    case VC_EVENT_EOS:
    case VC_EVENT_ERROR:
    case VC_EVENT_ACTIVE_TIMEOUT:
    case VC_EVENT_INACTIVITY_TIMEOUT:
      Debug("inactivity_cop", "event %d: null write.vio cont, closing vc %p", event, this);
      closed = true;
      break;
    default:
      Error("Unexpected event %d for vc %p", event, this);
      ink_release_assert(0);
      break;
    }
  }
  if (!--recursion && closed) {
    /* BZ  31932 */
    ink_assert(thread == this_ethread());
    return EVENT_DONE;
  } else {
    return EVENT_CONT;
  }
}

void
IOUringNetVConnection::load_buffer_and_write(int64_t towrite, MIOBufferAccessor &buf)
{
  int64_t try_to_write       = 0;
  IOBufferReader *tmp_reader = buf.reader()->clone();

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

  // If the platform doesn't support TCP Fast Open, verify that we
  // correctly disabled support in the socket option configuration.
  ink_assert(MSG_FASTOPEN != 0 || this->options.f_tcp_fastopen == false);
  struct msghdr msg;

  ink_zero(msg);
  msg.msg_name    = const_cast<sockaddr *>(this->get_remote_addr());
  msg.msg_namelen = ats_ip_size(this->get_remote_addr());
  msg.msg_iov     = &tiovec[0];
  msg.msg_iovlen  = niov;
  int flags       = 0;

  if (!this->con.is_connected && this->options.f_tcp_fastopen) {
    NET_INCREMENT_DYN_STAT(net_fastopen_attempts_stat);
    flags = MSG_FASTOPEN;
  }
  // r = SocketManager::sendmsg(con.fd, &msg, flags);
  io_uring_sqe *sqe = IOUringContext::local_context()->next_sqe(&write);
  ink_assert(sqe != nullptr);
  io_uring_prep_sendmsg(sqe, con.fd, &msg, flags);
  Debug(TAG, "prep_sendmsg, op = %p", &write);

  tmp_reader->dealloc();
}

// Either prep an SQE for more writing, or stop if writing is done.
void
IOUringNetVConnection::prep_write()
{
  if (!write.enabled) {
    return;
  }

  // TODO(mo): do we need to hold the vio mutex?

  // TODO: handle SSL handshake

  // If there is nothing to do, disable
  int64_t ntodo = write.vio.ntodo();
  if (ntodo <= 0) {
    write.enabled = false;
    return;
  }

  MIOBufferAccessor &buf = write.vio.buffer;
  ink_assert(buf.writer());

  // Calculate the amount to write.
  int64_t towrite = buf.reader()->read_avail();
  if (towrite > ntodo) {
    towrite = ntodo;
  }

  // signal write ready to allow user to fill the buffer
  if (towrite != ntodo && !buf.writer()->high_water()) {
    if (write_signal_and_update(VC_EVENT_WRITE_READY) != EVENT_CONT) {
      return;
    }

    ntodo = write.vio.ntodo();
    if (ntodo <= 0) {
      write.enabled = false;
      return;
    }

    // Recalculate amount to write
    towrite = buf.reader()->read_avail();
    if (towrite > ntodo) {
      towrite = ntodo;
    }
  }

  // if there is nothing to do, disable
  ink_assert(towrite >= 0);
  if (towrite <= 0) {
    write.enabled = false;
    return;
  }

  load_buffer_and_write(towrite, buf);
}

VIO *
IOUringNetVConnection::do_io_read(Continuation *c, int64_t nbytes, MIOBuffer *buf)
{
  Debug(TAG, "%s(%p, %" PRId64 ", %p)", __FUNCTION__, c, nbytes, buf);
  ink_assert(thread == this_ethread());

  read.vio.op        = VIO::READ;
  read.vio.mutex     = c ? c->mutex : this->mutex;
  read.vio.cont      = c;
  read.vio.nbytes    = nbytes;
  read.vio.ndone     = 0;
  read.vio.vc_server = this;
  read.vc            = this;

  if (buf) {
    read.vio.buffer.writer_for(buf);
    if (!read.enabled) {
      read.vio.reenable();
    }
  } else {
    // TODO: caller wants to cancel, but read might still be in progress
    read.vio.buffer.clear();
    read.enabled = false;
  }

  return &read.vio;
}

VIO *
IOUringNetVConnection::do_io_write(Continuation *c, int64_t nbytes, IOBufferReader *reader, bool owner)
{
  Debug(TAG, "%s(%p, %" PRId64 ", %p, %d)", __FUNCTION__, c, nbytes, reader, owner);
  if (closed && !(c == nullptr && nbytes == 0 && reader == nullptr)) {
    Error("do_io_write invoked on closed vc %p, cont %p, nbytes %" PRId64 ", reader %p", this, c, nbytes, reader);
    return nullptr;
  }
  write.vio.op        = VIO::WRITE;
  write.vio.mutex     = c ? c->mutex : this->mutex;
  write.vio.cont      = c;
  write.vio.nbytes    = nbytes;
  write.vio.ndone     = 0;
  write.vio.vc_server = this;
  write.vc            = this;

  if (reader) {
    ink_assert(!owner);
    write.vio.buffer.reader_for(reader);
    if (nbytes && !write.enabled) {
      write.vio.reenable();
    }
  } else {
    write.enabled = false;
  }
  return &write.vio;
}

void
IOUringNetVConnection::do_io_close(int lerrno)
{
  Debug(TAG, "%s", __FUNCTION__);
}

void
IOUringNetVConnection::do_io_shutdown(ShutdownHowTo_t howto)
{
  Debug(TAG, "%s", __FUNCTION__);
}

void
IOUringNetVConnection::set_active_timeout(ink_hrtime timeout_in)
{
  Debug(TAG, "%s", __FUNCTION__);
}

void
IOUringNetVConnection::set_inactivity_timeout(ink_hrtime timeout_in)
{
  Debug(TAG, "%s", __FUNCTION__);
}

void
IOUringNetVConnection::set_default_inactivity_timeout(ink_hrtime timeout_in)
{
  Debug(TAG, "%s", __FUNCTION__);
}

bool
IOUringNetVConnection::is_default_inactivity_timeout()
{
  Debug(TAG, "%s", __FUNCTION__);
  return false;
}

void
IOUringNetVConnection::cancel_active_timeout()
{
  Debug(TAG, "%s", __FUNCTION__);
}

void
IOUringNetVConnection::cancel_inactivity_timeout()
{
  Debug(TAG, "%s", __FUNCTION__);
}

void
IOUringNetVConnection::add_to_keep_alive_queue()
{
  Debug(TAG, "%s", __FUNCTION__);
}

void
IOUringNetVConnection::remove_from_keep_alive_queue()
{
  Debug(TAG, "%s", __FUNCTION__);
}

bool
IOUringNetVConnection::add_to_active_queue()
{
  Debug(TAG, "%s", __FUNCTION__);
  return true;
}

ink_hrtime
IOUringNetVConnection::get_active_timeout()
{
  Debug(TAG, "%s", __FUNCTION__);
  return 0;
}

ink_hrtime
IOUringNetVConnection::get_inactivity_timeout()
{
  Debug(TAG, "%s", __FUNCTION__);
  return 0;
}

void
IOUringNetVConnection::apply_options()
{
  Debug(TAG, "%s", __FUNCTION__);
}

void
IOUringNetVConnection::reenable(VIO *vio)
{
  if (vio == &read.vio && !read.enabled) {
    Debug(TAG, "reenable read");
    read.enabled = true;
    prep_read();
  } else if (vio == &write.vio && !write.enabled) {
    Debug(TAG, "reenable write");
    write.enabled = true;
    prep_write();
  }
}

void
IOUringNetVConnection::reenable_re(VIO *vio)
{
  Debug(TAG, "%s", __FUNCTION__);
}

SOCKET
IOUringNetVConnection::get_socket()
{
  Debug(TAG, "%s", __FUNCTION__);
  return 0;
}

int
IOUringNetVConnection::set_tcp_congestion_control(int side)
{
  Debug(TAG, "%s", __FUNCTION__);
  return 0;
}

void
IOUringNetVConnection::set_local_addr()
{
  Debug(TAG, "%s", __FUNCTION__);
  int local_sa_size = sizeof(local_addr);
  // This call will fail if fd is closed already. That is ok, because the
  // `local_addr` is checked within get_local_addr() and the `got_local_addr`
  // is set only with a valid `local_addr`.
  ATS_UNUSED_RETURN(safe_getsockname(con.fd, &local_addr.sa, &local_sa_size));
}

void
IOUringNetVConnection::set_remote_addr()
{
  Debug(TAG, "%s", __FUNCTION__);
  ats_ip_copy(&remote_addr, &con.addr);
  this->control_flags.set_flag(ContFlags::DEBUG_OVERRIDE, diags()->test_override_ip(remote_addr));
  set_cont_flags(this->control_flags);
}

void
IOUringNetVConnection::set_remote_addr(const sockaddr *new_sa)
{
  ats_ip_copy(&remote_addr, new_sa);
  this->control_flags.set_flag(ContFlags::DEBUG_OVERRIDE, diags()->test_override_ip(remote_addr));
  set_cont_flags(this->control_flags);
}

void
IOUringNetVConnection::set_mptcp_state()
{
  Debug(TAG, "%s", __FUNCTION__);
}

int
IOUringNetVConnection::acceptEvent(int event, Event *e)
{
  Debug(TAG, "%s", __FUNCTION__);
  EThread *t = (e == nullptr) ? this_ethread() : e->ethread;
  thread     = t;

  // Should only be called from the local thread
  ink_assert(this_ethread()->is_event_type(ET_NET));
  mutex = new_ProxyMutex();

  // Setup a timeout callback handler.
  SET_HANDLER(&IOUringNetVConnection::mainEvent);

  ink_release_assert(action_.continuation);
  if (action_.continuation->mutex != nullptr) {
    MUTEX_TRY_LOCK(lock, action_.continuation->mutex, t);
    if (!lock.is_locked()) {
      // TODO: can this happen?
      ink_release_assert(0);
    }
    action_.continuation->handleEvent(NET_EVENT_ACCEPT, this);
  } else {
    action_.continuation->handleEvent(NET_EVENT_ACCEPT, this);
  }
  return EVENT_DONE;
}

int
IOUringNetVConnection::startEvent(int event, Event *e)
{
  Debug(TAG, "startEvent");
  // TODO: continue to open a connection

  return EVENT_DONE;
}

int
IOUringNetVConnection::mainEvent(int event, Event *e)
{
  Debug(TAG, "mainEvent");
  return EVENT_DONE;
}

void
IOUringReader::handle_complete(io_uring_cqe *cqe)
{
  int r = cqe->res;

  Debug(TAG, "read.handle_complete r = %d", r);

  SCOPED_MUTEX_LOCK(lock, vio.mutex, this_ethread());

  if (r <= 0) {
    Debug(TAG, "read error vio: %d %s", r, strerror(-r));
    if (!r || r == -ECONNRESET) {
      vio.cont->handleEvent(VC_EVENT_EOS, &vio);
    } else {
      vio.vc_server->lerrno = -r;
      vio.cont->handleEvent(VC_EVENT_ERROR, &vio);
    }
  } else {
    vio.ndone += r;
    Debug(TAG, "vio complete: %d %ld/%ld", r, vio.ndone, vio.nbytes);
    ink_assert(vio.op == VIO::READ);
    vio.buffer.writer()->fill(r);

    if (vio.ntodo() <= 0) { // why <0?
      vio.cont->handleEvent(VC_EVENT_READ_COMPLETE, &vio);
    } else {
      vio.cont->handleEvent(VC_EVENT_READ_READY, &vio);
      vc->prep_read();
    }
  }

  auto mutex = vio.mutex;
  NET_SUM_DYN_STAT(net_read_bytes_stat, r);
}

void
IOUringWriter::handle_complete(io_uring_cqe *cqe)
{
  auto r = cqe->res;

  Debug(TAG, "write.handle_complete r = %d", r);

  auto mutex = vio.mutex;
  SCOPED_MUTEX_LOCK(lock, vio.mutex, this_ethread());

  if (!vc->con.is_connected && vc->options.f_tcp_fastopen) {
    if (r < 0) {
      if (r == -EINPROGRESS || r == -EWOULDBLOCK) {
        vc->con.is_connected = true;
      }
    } else {
      // For NET_INCREMENT_DYN_STAT
      NET_INCREMENT_DYN_STAT(net_fastopen_successes_stat);
      vc->con.is_connected = true;
    }
  }

  if (r <= 0) {
    Debug(TAG, "write error vio: %d %s", r, strerror(-r));
    if (!r || r == -ECONNRESET) {
      vio.cont->handleEvent(VC_EVENT_EOS, &vio);
    } else {
      vio.vc_server->lerrno = -r;
      vio.cont->handleEvent(VC_EVENT_ERROR, &vio);
    }
  } else {
    vio.buffer.reader()->consume(r);
    NET_SUM_DYN_STAT(net_write_bytes_stat, r);
    vio.ndone += r;
    // TODO: net_activity to prevent inactivity

    if (vio.ntodo() <= 0) {
      vio.cont->handleEvent(VC_EVENT_WRITE_COMPLETE, &vio);
    } else {
      vio.cont->handleEvent(VC_EVENT_WRITE_READY, &vio);
      vc->prep_write();
    }
  }

  NET_INCREMENT_DYN_STAT(net_calls_to_write_stat);
}

void
IOUringNetVConnection::_close()
{
  // TODO: cancel in-flight ops
}

int
IOUringNetVConnection::connectUp(EThread *t, int fd)
{
  Debug(TAG, "%s", __FUNCTION__);
  int res;

  auto fail = [this, fd](int res) {
    lerrno = -res;
    action_.continuation->handleEvent(NET_EVENT_OPEN_FAILED, reinterpret_cast<void *>(res));
    if (fd != NO_FD) {
      con.fd = NO_FD;
    }
  };

  thread = t;
  if (check_net_throttle(CONNECT)) {
    check_throttle_warning(CONNECT);
    res = -ENET_THROTTLING;
    NET_INCREMENT_DYN_STAT(net_connections_throttled_out_stat);
    fail(res);
    return CONNECT_FAILURE;
  }

  // Force family to agree with remote (server) address.
  options.ip_family = con.addr.sa.sa_family;

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
    con.open(options, [this, fail](int res) {
      if (res < 0) {
        Debug(TAG, "connectUp failed with %s", strerror(-res));
        fail(res);
        return;
      }

      con.connect(nullptr, options, [this, fail](int res) {
        if (res < 0) {
          fail(res);
          return;
        }

        // Did not fail, increment connection count
        NET_SUM_GLOBAL_DYN_STAT(net_connections_currently_open_stat, 1);
        ink_release_assert(con.fd != NO_FD);

        // Setup a timeout callback handler.
        SET_HANDLER(&UnixNetVConnection::mainEvent);

        set_inactivity_timeout(0);
        this->set_local_addr();
        action_.continuation->handleEvent(NET_EVENT_OPEN, this);
      });
    });
  } else {
    // TODO
    ink_assert(false);
  }

  return CONNECT_SUCCESS;
}
