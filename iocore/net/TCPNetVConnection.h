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

/****************************************************************************


  This file implements an I/O Processor for network I/O on Unix.


 ****************************************************************************/

#pragma once

#include "I_Lock.h"
#include "NetVCOptions.h"
#include "tscore/ink_hrtime.h"
#include "tscore/ink_sock.h"
#include "I_NetVConnection.h"
#include "NetEvent.h"
#include "NetAIO.h"

enum class op_state { IDLE, TRY_ISSUE, WAIT_FOR_COMPLETION, TRY_HANDLER, ERROR };
enum class connect_state { NONE, WAIT, FAILED, DONE };

class TCPNetVConnection : public NetVConnection, public NetAIO::TCPConnectionObserver
{
public:
  VIO *do_io_read(Continuation *c, int64_t nbytes, MIOBuffer *buf) override;
  VIO *do_io_write(Continuation *c, int64_t nbytes, IOBufferReader *buf, bool owner = false) override;

  bool get_data(int id, void *data) override;

  const char *
  get_server_name() const override
  {
    return nullptr;
  }

  void do_io_close(int lerrno = -1) override;
  void do_io_shutdown(ShutdownHowTo_t howto) override;

  ////////////////////////////////////////////////////////////
  // Set the timeouts associated with this connection.      //
  // active_timeout is for the total elapsed time of        //
  // the connection.                                        //
  // inactivity_timeout is the elapsed time from the time   //
  // a read or a write was scheduled during which the       //
  // connection  was unable to sink/provide data.           //
  // calling these functions repeatedly resets the timeout. //
  // These functions are NOT THREAD-SAFE, and may only be   //
  // called when handing an  event from this NetVConnection,//
  // or the NetVConnection creation callback.               //
  ////////////////////////////////////////////////////////////
  void set_active_timeout(ink_hrtime timeout_in) override;
  void set_inactivity_timeout(ink_hrtime timeout_in) override;
  void set_default_inactivity_timeout(ink_hrtime timeout_in) override;
  bool is_default_inactivity_timeout() override;
  void cancel_active_timeout() override;
  void cancel_inactivity_timeout() override;
  void set_action(Continuation *c) override;
  const Action *get_action() const;
  void add_to_keep_alive_queue() override;
  void remove_from_keep_alive_queue() override;
  bool add_to_active_queue() override;
  virtual void remove_from_active_queue();

  // The public interface is VIO::reenable()
  void reenable(VIO *vio) override;
  void reenable_re(VIO *vio) override;

  SOCKET get_socket() override;

  ~TCPNetVConnection() override;

  /////////////////////////////////////////////////////////////////
  // instances of TCPNetVConnection should be allocated         //
  // only from the free list using TCPNetVConnection::alloc().  //
  // The constructor is public just to avoid compile errors.      //
  /////////////////////////////////////////////////////////////////
  TCPNetVConnection(const IpEndpoint *remote, NetVCOptions *opt, EThread *t);
  // void free(EThread *t);

  int populate_protocol(std::string_view *results, int n) const override;
  const char *protocol_contains(std::string_view tag) const override;

  // noncopyable
  TCPNetVConnection(const NetVConnection &)            = delete;
  TCPNetVConnection &operator=(const NetVConnection &) = delete;

  /////////////////////////
  // UNIX implementation //
  /////////////////////////
  void set_enabled(VIO *vio);

  void get_local_sa();

  // TCPConnectionObserver
  void onConnect(NetAIO::TCPConnection &c) override;
  void onRecvmsg(ssize_t bytes, std::unique_ptr<struct msghdr> msg, NetAIO::TCPConnection &c) override;
  void onSendmsg(ssize_t bytes, std::unique_ptr<struct msghdr> msg, NetAIO::TCPConnection &c) override;
  void onError(NetAIO::ErrorSource source, int err, NetAIO::TCPConnection &c) override;
  void onClose(NetAIO::TCPConnection &c) override;

  Action action_;

  unsigned int id = 0;

  int connectEvent(int event, void *edata);
  int acceptEvent(int event, void *edata);
  int mainEvent(int event, void *edata);

  /**
   * Populate the current object based on the socket information in the
   * con parameter.
   * This is logic is invoked when the NetVC object is created in a new thread context
   */
  // virtual void clear();

  ink_hrtime get_inactivity_timeout() override;
  ink_hrtime get_active_timeout() override;

  void set_local_addr() override;
  void set_mptcp_state() override;
  int set_tcp_congestion_control(tcp_congestion_control_t side) override;
  void set_remote_addr() override;
  void set_remote_addr(const sockaddr *) override;
  void apply_options() override;

private:
  connect_state _connect_state = connect_state::NONE;
  int _handle_connect_done(int event = 0, Event *e = nullptr);
  int _handle_connect_error(int event = 0, Event *e = nullptr);

  int _read_from_net(int event = 0, Event *e = nullptr);
  void _handle_read_done();
  void _handle_read_error();
  void _read_reschedule();
  int _read_signal_and_update(int event);
  int _read_signal_done(int event);
  int _read_signal_error(int lerrno);

  struct read_info {
    int r;
    op_state state = op_state::IDLE;
    VIO vio{VIO::READ};
  } _read;

  int _write_to_net(int event = 0, Event *e = nullptr);
  void _handle_write_done();
  void _handle_write_error();
  void _write_reschedule();
  int _write_signal_and_update(int event);
  int _write_signal_done(int event);
  struct write_info {
    int r;
    op_state state = op_state::IDLE;
    int signalled;
    VIO vio{VIO::WRITE};
  } _write;

  int _recursion = 0;
  NetAIO::TCPConnection _con;
};

extern ClassAllocator<TCPNetVConnection> tcpNetVCAllocator;
