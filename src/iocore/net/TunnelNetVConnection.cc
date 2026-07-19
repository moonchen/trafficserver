/** @file

  TunnelNetVConnection: raw byte-forwarding NetVConnection for TLS blind tunnels.

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

#include "P_TunnelNetVConnection.h"
#include "P_Net.h"

#include "iocore/eventsystem/EventSystem.h"
#include "tscore/Diags.h"
#include "tscore/ink_assert.h"

#include <algorithm>

ClassAllocator<TunnelNetVConnection> tunnelNetVCAllocator("tunnelNetVCAllocator");

namespace
{
DbgCtl dbg_ctl_ssl_tunnel{"ssl_tunnel"};
}

TunnelNetVConnection::TunnelNetVConnection()
{
  // Advertise the tunnel route to the HTTP layer via get_service<TLSTunnelSupport>().
  this->_set_service(static_cast<TLSTunnelSupport *>(this));
  SET_HANDLER(&TunnelNetVConnection::mainEvent);
}

TunnelNetVConnection::~TunnelNetVConnection()
{
  // Cancel any pending out-of-line read drive so it does not fire on freed memory.
  if (_read_drive_event != nullptr) {
    _read_drive_event->cancel();
    _read_drive_event = nullptr;
  }

  if (_is_tunnel_endpoint) {
    // This VC only ever serves an inbound pure-blind (SNIRoutingType::BLIND) tunnel.
    Metrics::Gauge::decrement(net_rsb.tunnel_current_client_connections_tls_tunnel);
  }

  // Stop the transport before freeing the buffer it reads into.
  if (_unvc != nullptr) {
    _unvc->do_io_close();
    _unvc = nullptr;
  }

  if (_buffered_reader != nullptr) {
    _buffered_reader->dealloc();
    _buffered_reader = nullptr;
  }
  // _read_buf is freed by its unique_ptr deleter (free_MIOBuffer).

  this->mutex.clear();
  _user_read_vio.mutex.clear();
  _user_read_vio.cont = nullptr;
  _user_write_vio.mutex.clear();
  _user_write_vio.cont = nullptr;
}

void
TunnelNetVConnection::free_thread(EThread *)
{
  // Blind tunnels are infrequent, so free straight through the global allocator (which
  // runs the destructor and is thread-safe) rather than wiring a per-thread proxy
  // allocator member onto EThread.
  tunnelNetVCAllocator.free(this);
}

void
TunnelNetVConnection::adopt(UnixNetVConnection *unvc, MIOBuffer *read_buf, IOBufferReader *buffered_reader)
{
  ink_release_assert(unvc != nullptr);
  _unvc = unvc;
  _read_buf.reset(read_buf);
  _buffered_reader = buffered_reader;

  // Re-point the transport read VIO at us, continuing to read raw bytes into _read_buf.
  // Bytes already buffered (the ClientHello plus anything pipelined behind it) stay in
  // _read_buf and remain visible through _buffered_reader.
  _transport_read_vio = _unvc->do_io_read(this, INT64_MAX, _read_buf.get());

  // The donor's write VIO still names the donor (about to be freed) as its continuation
  // and used the donor's write buffer. Cancel it so a stale transport write event does
  // not signal freed memory; our own do_io_write installs a fresh one when the HTTP layer
  // writes the origin->client direction.
  _unvc->do_io_write(nullptr, 0, nullptr);
}

void
TunnelNetVConnection::hand_off_to(Continuation *accept_cont)
{
  ink_release_assert(accept_cont != nullptr);
  Dbg(dbg_ctl_ssl_tunnel, "TunnelNetVConnection %p: handing off to accept continuation %p", this, accept_cont);

  // Present a completed read to the acceptor (the SSLNextProtocolTrampoline). Because
  // this VC is not an SSLNetVConnection, the trampoline routes it to the default HTTP
  // endpoint via NET_EVENT_ACCEPT; the BLIND_TUNNEL attribute then drives CONNECT tunnel
  // setup, and the buffered ClientHello is delivered when the HTTP layer issues its read.
  _user_read_vio.op        = VIO::READ;
  _user_read_vio.vc_server = this;
  _user_read_vio.cont      = accept_cont;
  _user_read_vio.mutex     = accept_cont->mutex;
  accept_cont->handleEvent(VC_EVENT_READ_COMPLETE, &_user_read_vio);
}

//
// Deliver `event` to the consumer on `side`. handleEvent may free this VC (the consumer can
// call do_io_close from within its handler); the recursion guard defers the actual free until
// the outermost signal unwinds. This fuses in one body what SSLNetVConnection splits into
// _signal_user + _signalAndReclaim. EVENT_DONE means this VC was freed: the caller must touch
// nothing afterward.
//
int
TunnelNetVConnection::_signal_user(SignalSide side, int event)
{
  VIO &vio = side == SignalSide::READ ? _user_read_vio : _user_write_vio;

  _recursion++;
  if (vio.cont != nullptr && vio.mutex == vio.cont->mutex) {
    vio.cont->handleEvent(event, &vio);
  }
  if (!--_recursion && _closed) {
    ink_assert(thread == this_ethread());
    this->free_thread(this_ethread());
    return EVENT_DONE;
  }
  return EVENT_CONT;
}

// Which side has a consumer attached to take a connection-level event (error/timeout):
// read-first, mirroring SSLNetVConnection::_handshake_fail_side. Empty when both sides are
// severed -- the event has nobody to go to and is dropped.
std::optional<TunnelNetVConnection::SignalSide>
TunnelNetVConnection::_active_user_side() const
{
  if (_user_read_vio.cont != nullptr) {
    return SignalSide::READ;
  }
  if (_user_write_vio.cont != nullptr) {
    return SignalSide::WRITE;
  }
  return std::nullopt;
}

void
TunnelNetVConnection::_schedule_read_drive()
{
  if (_read_drive_event == nullptr) {
    _read_drive_event = this_ethread()->schedule_imm(this);
  }
}

//
// Pump raw bytes from the transport buffer (_read_buf via _buffered_reader) into the
// consumer's read buffer. Used both for the scheduled initial delivery of the buffered
// ClientHello and for steady-state reads driven by transport read-ready events.
//
void
TunnelNetVConnection::_drive_read()
{
  if (_closed) {
    return;
  }

  // Consumer is not actively reading: quiesce the transport and wait.
  // buffer.writer() is null in the window between hand_off_to() (which points _user_read_vio at the
  // trampoline with no buffer) and the HTTP layer's first do_io_read(buf); quiesce the transport
  // until then -- the consumer's do_io_read re-drives via _schedule_read_drive.
  if (_user_read_vio.op != VIO::READ || _user_read_vio.is_disabled() || _user_read_vio.cont == nullptr ||
      _user_read_vio.buffer.writer() == nullptr) {
    if (_transport_read_vio != nullptr) {
      _transport_read_vio->disable();
    }
    return;
  }

  int64_t navail = _buffered_reader != nullptr ? _buffered_reader->read_avail() : 0;
  int64_t ntodo  = _user_read_vio.ntodo();
  // HttpTunnel throttles the producer only by withholding the consumer reenable, so bound
  // the copy by the destination buffer's write_avail() (which honors its high-water mark)
  // the way UnixNetVConnection::net_read_io does; otherwise a slow consumer lets the buffer
  // grow without bound. Any bytes left behind stay in _buffered_reader for the next drive.
  int64_t nspace = _user_read_vio.buffer.writer()->write_avail();
  int64_t nmove  = std::min({navail, ntodo, nspace});

  if (nmove > 0) {
    int64_t moved = _user_read_vio.buffer.writer()->write(_buffered_reader, nmove);
    _buffered_reader->consume(moved);
    _user_read_vio.ndone += moved;
    Dbg(dbg_ctl_ssl_tunnel, "TunnelNetVConnection %p: forwarded %" PRId64 " raw bytes to consumer", this, moved);
    int ev = _user_read_vio.ntodo() <= 0 ? VC_EVENT_READ_COMPLETE : VC_EVENT_READ_READY;
    if (_signal_user(SignalSide::READ, ev) == EVENT_DONE) {
      return; // freed during signal
    }
  }

  if (_transport_read_eos) {
    // Surface EOS only once everything buffered has been handed to the consumer; if the
    // consumer could not take it all, reenable() reschedules a drive to continue.
    if (_buffered_reader == nullptr || _buffered_reader->read_avail() == 0) {
      _signal_user(SignalSide::READ, VC_EVENT_EOS);
    }
    return;
  }

  // Keep the transport reading more raw bytes, but only while the consumer buffer has room.
  // At high water we leave the transport quiesced; the consumer's reenable() re-drives once
  // it drains space, matching net_read_io's disable-when-full behavior.
  if (_transport_read_vio != nullptr && _user_read_vio.op == VIO::READ && !_user_read_vio.is_disabled() &&
      _user_read_vio.buffer.writer()->write_avail() > 0) {
    _transport_read_vio->reenable();
  }
}

int
TunnelNetVConnection::_handle_transport_write(int event)
{
  if (_closed) {
    return EVENT_DONE;
  }
  if (_user_write_vio.op != VIO::WRITE || _user_write_vio.cont == nullptr) {
    return EVENT_CONT;
  }
  // The transport write VIO consumes the same reader the consumer handed us, so its
  // progress is the consumer's progress; mirror it and relay the event unchanged.
  if (_transport_write_vio != nullptr) {
    _user_write_vio.ndone = _transport_write_vio->ndone;
  }
  return _signal_user(SignalSide::WRITE, event);
}

int
TunnelNetVConnection::mainEvent(int event, void *data)
{
  // A scheduled out-of-line read drive arrives with an Event*, not a transport VIO.
  if (data != _transport_read_vio && data != _transport_write_vio) {
    _read_drive_event = nullptr;
    if (_closed) {
      this->free_thread(this_ethread());
      return EVENT_DONE;
    }
    _drive_read();
    return EVENT_DONE;
  }

  if (_closed) {
    return EVENT_DONE;
  }

  Dbg(dbg_ctl_ssl_tunnel, "TunnelNetVConnection %p: transport event %d", this, event);

  switch (event) {
  case VC_EVENT_READ_READY:
  case VC_EVENT_READ_COMPLETE:
    _drive_read();
    return EVENT_CONT;
  case VC_EVENT_WRITE_READY:
  case VC_EVENT_WRITE_COMPLETE:
    return _handle_transport_write(event);
  case VC_EVENT_EOS:
    _transport_read_eos = true;
    _drive_read();
    return EVENT_DONE;
  case VC_EVENT_ERROR:
    if (_unvc != nullptr) {
      this->lerrno = _unvc->lerrno;
    }
    if (auto side = _active_user_side(); side.has_value()) {
      _signal_user(*side, VC_EVENT_ERROR);
    }
    return EVENT_DONE;
  case VC_EVENT_ACTIVE_TIMEOUT:
  case VC_EVENT_INACTIVITY_TIMEOUT:
    if (auto side = _active_user_side(); side.has_value()) {
      _signal_user(*side, event);
    }
    return EVENT_DONE;
  default:
    Warning("TunnelNetVConnection %p: unexpected event %d", this, event);
    return EVENT_CONT;
  }
}

VIO *
TunnelNetVConnection::do_io_read(Continuation *c, int64_t nbytes, MIOBuffer *buf)
{
  if (_closed) {
    return nullptr;
  }

  _user_read_vio.op        = VIO::READ;
  _user_read_vio.mutex     = c ? c->mutex : this->mutex;
  _user_read_vio.cont      = c;
  _user_read_vio.nbytes    = nbytes;
  _user_read_vio.ndone     = 0;
  _user_read_vio.vc_server = this;

  if (buf) {
    _user_read_vio.set_writer(buf);
    // Deliver whatever is already buffered (and surface a pending EOS) out of line so we
    // do not re-enter the caller; also keep the transport reading more raw bytes.
    _schedule_read_drive();
  } else {
    _user_read_vio.disable();
    _user_read_vio.buffer.clear();
    if (_transport_read_vio != nullptr) {
      _transport_read_vio->disable();
    }
  }
  return &_user_read_vio;
}

VIO *
TunnelNetVConnection::do_io_write(Continuation *c, int64_t nbytes, IOBufferReader *reader, bool owner)
{
  if (_closed) {
    return nullptr;
  }

  _user_write_vio.op        = VIO::WRITE;
  _user_write_vio.mutex     = c ? c->mutex : this->mutex;
  _user_write_vio.cont      = c;
  _user_write_vio.nbytes    = nbytes;
  _user_write_vio.ndone     = 0;
  _user_write_vio.vc_server = this;

  if (reader) {
    ink_assert(!owner);
    _user_write_vio.set_reader(reader);
    // Hand the consumer's reader straight to the transport: the socket drains it directly,
    // with no copy and no encryption.
    _transport_write_vio = _unvc->do_io_write(this, nbytes, reader, false);
  } else {
    _user_write_vio.disable();
    if (_transport_write_vio != nullptr) {
      _transport_write_vio->disable();
    }
  }
  return &_user_write_vio;
}

void
TunnelNetVConnection::do_io_close(int alerrno)
{
  if (_closed) {
    return;
  }
  Dbg(dbg_ctl_ssl_tunnel, "TunnelNetVConnection %p: do_io_close (errno %d)", this, alerrno);
  _closed      = true;
  this->lerrno = alerrno;

  // If we are inside a signal callout (the consumer closed us from its handler), defer the
  // free to the signal unwind; otherwise free now if we hold the connection mutex.
  bool close_inline = !_recursion && this->mutex && this->mutex->thread_holding == this_ethread();
  if (close_inline) {
    this->free_thread(this_ethread());
  } else if (!_recursion) {
    // Off-mutex, non-nested close (e.g. a plugin TSVConnClose from its own continuation):
    // nothing else will free us, so defer to a clean stack. The scheduled mainEvent dispatch
    // frees on _closed; the destructor cancels the event if a signal unwind frees us first.
    _schedule_read_drive();
  }
}

void
TunnelNetVConnection::do_io_shutdown(ShutdownHowTo_t howto)
{
  if (_unvc != nullptr) {
    _unvc->do_io_shutdown(howto);
  }
}

void
TunnelNetVConnection::reenable(VIO *vio)
{
  if (_closed) {
    return;
  }
  if (vio == &_user_read_vio) {
    // If bytes remain buffered, or the transport already closed, deliver out of line;
    // otherwise wait for the transport to read more.
    if (_transport_read_eos || (_buffered_reader != nullptr && _buffered_reader->read_avail() > 0)) {
      _schedule_read_drive();
    } else if (_transport_read_vio != nullptr) {
      _transport_read_vio->reenable();
    }
  } else if (vio == &_user_write_vio) {
    if (_transport_write_vio != nullptr) {
      // HttpTunnel signals "no more data, finish" by setting the final byte count on the
      // consumer VIO and reenabling. Mirror it onto the transport write VIO so the inner
      // transport completes (and we relay WRITE_COMPLETE) instead of waiting forever.
      _transport_write_vio->nbytes = _user_write_vio.nbytes;
      _transport_write_vio->reenable();
    }
  }
}

void
TunnelNetVConnection::reenable_re(VIO *vio)
{
  // No caller exists today (HttpTunnel/HttpSM drive this VC via reenable()), but this is a
  // pure-virtual override that must be provided. Delegate to reenable(), which performs the
  // correct user->transport VIO translation, rather than forwarding the user VIO straight to the
  // inner transport (which would misclassify a forwarded read VIO as a write).
  reenable(vio);
}

void
TunnelNetVConnection::mark_as_tunnel_endpoint()
{
  ink_assert(!_is_tunnel_endpoint);
  ink_assert(get_context() == NET_VCONNECTION_IN);

  _is_tunnel_endpoint = true;
  Metrics::Counter::increment(net_rsb.tunnel_total_client_connections_tls_tunnel);
  Metrics::Gauge::increment(net_rsb.tunnel_current_client_connections_tls_tunnel);
}

//
// Control-operation delegations to the inner transport.
//
void
TunnelNetVConnection::set_active_timeout(ink_hrtime timeout_in)
{
  if (_unvc != nullptr) {
    _unvc->set_active_timeout(timeout_in);
  }
}

void
TunnelNetVConnection::set_inactivity_timeout(ink_hrtime timeout_in)
{
  if (_unvc != nullptr) {
    _unvc->set_inactivity_timeout(timeout_in);
  }
}

void
TunnelNetVConnection::set_default_inactivity_timeout(ink_hrtime timeout_in)
{
  if (_unvc != nullptr) {
    _unvc->set_default_inactivity_timeout(timeout_in);
  }
}

bool
TunnelNetVConnection::is_default_inactivity_timeout()
{
  return _unvc != nullptr && _unvc->is_default_inactivity_timeout();
}

void
TunnelNetVConnection::cancel_active_timeout()
{
  if (_unvc != nullptr) {
    _unvc->cancel_active_timeout();
  }
}

void
TunnelNetVConnection::cancel_inactivity_timeout()
{
  if (_unvc != nullptr) {
    _unvc->cancel_inactivity_timeout();
  }
}

void
TunnelNetVConnection::add_to_keep_alive_queue()
{
  if (_unvc != nullptr) {
    _unvc->add_to_keep_alive_queue();
  }
}

void
TunnelNetVConnection::remove_from_keep_alive_queue()
{
  if (_unvc != nullptr) {
    _unvc->remove_from_keep_alive_queue();
  }
}

bool
TunnelNetVConnection::add_to_active_queue()
{
  return _unvc != nullptr && _unvc->add_to_active_queue();
}

ink_hrtime
TunnelNetVConnection::get_active_timeout()
{
  return _unvc != nullptr ? _unvc->get_active_timeout() : 0;
}

ink_hrtime
TunnelNetVConnection::get_inactivity_timeout()
{
  return _unvc != nullptr ? _unvc->get_inactivity_timeout() : 0;
}

void
TunnelNetVConnection::apply_options()
{
  if (_unvc != nullptr) {
    _unvc->options = this->options;
    _unvc->apply_options();
  }
}

SOCKET
TunnelNetVConnection::get_socket()
{
  return _unvc != nullptr ? _unvc->get_socket() : NO_FD;
}

int
TunnelNetVConnection::set_tcp_congestion_control(tcp_congestion_control_side side)
{
  return _unvc != nullptr ? _unvc->set_tcp_congestion_control(side) : -1;
}

void
TunnelNetVConnection::trapWriteBufferEmpty(int event)
{
  // The inner transport does the actual writing, so the trap must live on it:
  // its write path reads its own write_buffer_empty_event.
  if (_unvc != nullptr) {
    _unvc->trapWriteBufferEmpty(event);
  }
}

void
TunnelNetVConnection::set_local_addr()
{
  if (_unvc != nullptr) {
    _unvc->set_local_addr();
    ats_ip_copy(&local_addr, _unvc->get_local_addr());
  }
}

void
TunnelNetVConnection::set_remote_addr()
{
  if (_unvc != nullptr) {
    _unvc->set_remote_addr();
    ats_ip_copy(&remote_addr, _unvc->get_remote_addr());
  }
}

void
TunnelNetVConnection::set_remote_addr(const sockaddr *addr)
{
  ats_ip_copy(&remote_addr, addr);
}

void
TunnelNetVConnection::set_mptcp_state()
{
  if (_unvc != nullptr) {
    _unvc->set_mptcp_state();
  }
}
