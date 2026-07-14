/** @file

  TunnelNetVConnection: a raw byte-forwarding NetVConnection for TLS blind
  tunnels in the layered (has-a UnixNetVConnection) model.

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

#include "iocore/eventsystem/Continuation.h"
#include "iocore/eventsystem/IOBuffer.h"
#include "iocore/net/NetVConnection.h"
#include "iocore/net/TLSTunnelSupport.h"

#include "P_UnixNetVConnection.h"

#include <memory>

/** A NetVConnection that forwards raw bytes between an inner transport
 *  (a UnixNetVConnection) and its consumer, performing no TLS.
 *
 *  This is the layered-model equivalent of master ATS's blind-tunnel behavior,
 *  where the terminating SSLNetVConnection (which is-a UnixNetVConnection)
 *  simply reverts to plain socket reads/writes once the SNI callback selects a
 *  blind tunnel_route. Here, SSLNetVConnection only has-a transport, so instead
 *  of reverting in place we hand the transport off to this dedicated VC.
 *
 *  It owns:
 *    - the inner @c UnixNetVConnection (@a _unvc), the real TCP socket,
 *    - the @c MIOBuffer (@a _read_buf) the handshake bytes were read into, into
 *      which @a _unvc keeps reading raw bytes,
 *    - a reader (@a _buffered_reader, the old handShakeHolder) positioned at the
 *      start of the buffered ClientHello.
 *
 *  It also is-a TLSTunnelSupport so the HTTP layer can recover the tunnel route
 *  via get_service<TLSTunnelSupport>(); the route is copied across at handoff.
 *
 *  Byte flow has no crypto: reads copy raw bytes from @a _read_buf into the
 *  consumer's buffer (delivering the buffered ClientHello first); writes hand
 *  the consumer's reader straight to @a _unvc. All control operations (timeouts,
 *  addresses, options, shutdown, close) delegate to @a _unvc.
 */
class TunnelNetVConnection : public NetVConnection, public TLSTunnelSupport
{
public:
  TunnelNetVConnection();
  ~TunnelNetVConnection() override;

  TunnelNetVConnection(const TunnelNetVConnection &)            = delete;
  TunnelNetVConnection &operator=(const TunnelNetVConnection &) = delete;

  /** Take ownership of the transport and buffered handshake bytes from a
   *  terminating connection, and (re)point the transport's read VIO at us so we
   *  receive its events. After this call the donor must release ownership of
   *  @a unvc, @a read_buf and @a buffered_reader (not free them). */
  void adopt(UnixNetVConnection *unvc, MIOBuffer *read_buf, IOBufferReader *buffered_reader);

  /** Hand this VC up the accept chain by signalling READ_COMPLETE to the
   *  acceptor continuation (the SSLNextProtocolTrampoline). Because this VC is
   *  not an SSLNetVConnection, the trampoline routes it to the default HTTP
   *  endpoint, where the BLIND_TUNNEL attribute drives CONNECT tunnel setup. */
  void hand_off_to(Continuation *accept_cont);

  // VConnection / NetVConnection
  VIO       *do_io_read(Continuation *c, int64_t nbytes, MIOBuffer *buf) override;
  VIO       *do_io_write(Continuation *c, int64_t nbytes, IOBufferReader *reader, bool owner) override;
  void       do_io_close(int lerrno = -1) override;
  void       do_io_shutdown(ShutdownHowTo_t howto) override;
  void       reenable(VIO *vio) override;
  void       reenable_re(VIO *vio) override;
  void       set_active_timeout(ink_hrtime timeout_in) override;
  void       set_inactivity_timeout(ink_hrtime timeout_in) override;
  void       set_default_inactivity_timeout(ink_hrtime timeout_in) override;
  bool       is_default_inactivity_timeout() override;
  void       cancel_active_timeout() override;
  void       cancel_inactivity_timeout() override;
  void       add_to_keep_alive_queue() override;
  void       remove_from_keep_alive_queue() override;
  bool       add_to_active_queue() override;
  ink_hrtime get_active_timeout() override;
  ink_hrtime get_inactivity_timeout() override;
  void       apply_options() override;
  SOCKET     get_socket() override;
  int        set_tcp_congestion_control(tcp_congestion_control_side side) override;
  void       set_local_addr() override;
  void       set_remote_addr() override;
  void       set_remote_addr(const sockaddr *addr) override;
  void       set_mptcp_state() override;
  void       mark_as_tunnel_endpoint() override;
  void       trapWriteBufferEmpty(int event = VC_EVENT_WRITE_READY) override;

  // Event handler for relayed transport events and scheduled read drives.
  int mainEvent(int event, void *data);

  void free_thread(EThread *t);

private:
  void _drive_read();
  int  _handle_transport_write(int event);
  int  _signal_read(int event);
  int  _signal_write(int event);
  void _schedule_read_drive();

  UnixNetVConnection *_unvc = nullptr;

  // The MIOBuffer the inner transport reads raw bytes into; _buffered_reader is
  // a reader on it positioned at the start of the buffered ClientHello.
  std::unique_ptr<MIOBuffer, decltype(&free_MIOBuffer)> _read_buf{nullptr, &free_MIOBuffer};
  IOBufferReader                                       *_buffered_reader = nullptr;

  // VIOs we hand to our consumer.
  VIO _user_read_vio;
  VIO _user_write_vio;

  // VIOs the inner transport gives us.
  VIO *_transport_read_vio  = nullptr;
  VIO *_transport_write_vio = nullptr;

  bool _closed             = false;
  bool _transport_read_eos = false; // inner transport hit EOS; drain buffer then signal EOS
  bool _is_tunnel_endpoint = false;
  int  _recursion          = 0;

  // An out-of-line read drive (schedule_imm) is pending; never queue more than one.
  bool   _read_drive_scheduled = false;
  Event *_read_drive_event     = nullptr;
};

extern ClassAllocator<TunnelNetVConnection> tunnelNetVCAllocator;
