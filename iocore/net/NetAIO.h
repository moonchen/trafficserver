/** @file

  Asynchronous networking API

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

#include <sys/socket.h>
#include <memory>
#include <thread>

#include "NetVCOptions.h"
#include "I_Net.h"
#include "I_IOBuffer.h"
#include "EventIO.h"
#include "P_UnixPollDescriptor.h"
#include "AcceptOptions.h"
#include "tscore/ink_inet.h"

namespace NetAIO
{
enum ErrorSource {
  ES_SOCKET,
  ES_REGISTER,
  ES_CONNECT,
  ES_BIND,
  ES_SENDMSG,
  ES_RECVMSG,
  ES_CLOSE,
  ES_SETSOCKOPT,
  ES_FCNTL,
  ES_LISTEN
};

class TCPConnection;

class TCPConnectionEventIO : public EventIO
{
public:
  TCPConnectionEventIO(TCPConnection &tcpcon) : EventIO(), _tcpcon(tcpcon) {}
  int start(EventLoop l, int fd, int events);
  void process_event(int flags) override;

private:
  TCPConnection &_tcpcon;
};
class TCPConnectionObserver
{
public:
  virtual void onConnect(TCPConnection &c)                                                    = 0;
  virtual void onRecvmsg(ssize_t bytes, std::unique_ptr<struct msghdr> msg, TCPConnection &c) = 0;
  virtual void onSendmsg(ssize_t bytes, std::unique_ptr<struct msghdr> msg, TCPConnection &c) = 0;
  virtual void onError(ErrorSource source, int err, TCPConnection &c)                         = 0;
};

class TCPConnection
{
public:
  enum state {
    TCP_CLOSED,
    TCP_CONNECTING,
    TCP_CONNECTED,
    TCP_HALF_SHUTDOWN,
    TCP_SHUTDOWN
    // There is no TCP_CLOSING state because we support destruction
  };

  // Constructor for a TCPConnection based on an existing fd that is connected.
  // If fd is NO_FD, then a new socket will be created and connected to target.
  TCPConnection(const IpEndpoint &remote, const NetVCOptions &opt, PollDescriptor &pd, TCPConnectionObserver &observer,
                int fd = NO_FD);

  TCPConnection(const TCPConnection &other)           = delete;
  TCPConnection operator=(const TCPConnection &other) = delete;

  // Destructor.  If the connection is open, it will be closed.
  virtual ~TCPConnection() { _close(); }

  // Attempt to read nbytes from the connection.  The format of msg is the same as for recvmsg.  onRecvmsg will be called when the
  // read makes progress.
  //
  // Ownership of msg is transferred to the TCPConnection.  The TCPConnection will transfer ownership back when the read
  // completes. You should either use std::move to pass msg, or construct a temporary std::unique_ptr<struct msghdr> and pass
  // that.
  //
  // Returns true if the read can proceed.  False if the read cannot proceed because the connection is not open, or another read
  // is outstanding.
  bool recvmsg(std::unique_ptr<struct msghdr> msg, int flags);

  // Attempt to write.  The format of msg is the same as for sendmsg.  onSendmsg be called when the write makes progress.
  //
  // Ownership of msg is transferred to the TCPConnection.  The TCPConnection will transfer ownership back when the read
  // completes. You should either use std::move to pass msg, or construct a temporary std::unique_ptr<struct msghdr> and pass
  // that.
  //
  // Returns true if the write can proceed.  False if the write cannot proceed because the connection is not open, or another
  // write is outstanding.
  bool sendmsg(std::unique_ptr<struct msghdr> msg, int flags);

  void poll(int flags);

private:
  int _fd;
  enum state _state { TCP_CLOSED };
  bool _recvmsg_in_progress{false};
  bool _sendmsg_in_progress{false};
  const IpEndpoint _remote;
  const NetVCOptions &_opt;
  PollDescriptor &_pd;
  TCPConnectionObserver &_observer;

  // Ensure that the TCPConnection is only used from the thread that created it.
  const std::thread::id _thread_id;

  std::unique_ptr<struct msghdr> _recvmsg_msg;
  int _recvmsg_flags;

  std::unique_ptr<struct msghdr> _sendmsg_msg;
  int _sendmsg_flags;

  TCPConnectionEventIO _ep{*this};
  bool _read_ready{true};
  bool _write_ready{true};

  bool _open();
  void _connect();
  void _close();
  void _apply_options();
  void _poll_connected(int flags);
  bool _register_poll();

  void
  _rearm_read()
  {
    _ep.modify(EVENTIO_READ);
    _ep.refresh(EVENTIO_READ);
  };

  void
  _rearm_write()
  {
    _ep.modify(EVENTIO_WRITE);
    _ep.refresh(EVENTIO_WRITE);
  }

  // Unix-specific state
};

class TCPListener;
class TCPListenerEventIO : public EventIO
{
public:
  TCPListenerEventIO(TCPListener &listener) : EventIO(), _listener(listener) {}
  int start(EventLoop l, int fd, int events);
  void process_event(int flags) override;

private:
  TCPListener &_listener;
};
class TCPListenerObserver
{
public:
  virtual void onAccept(int fd, IpEndpoint _remote) = 0;
  virtual void onError(ErrorSource source, int err) = 0;
};

class TCPListener
{
public:
  explicit TCPListener(const IpEndpoint &local, const AcceptOptions &opt, int accept_mss, int backlog, PollDescriptor &pd,
                       TCPListenerObserver &observer);
  virtual ~TCPListener();

  TCPListener(const TCPListener &other)            = delete;
  TCPListener &operator=(const TCPListener &other) = delete;

  /* Call this to make progress. */
  void poll(int flags);

private:
  int _listen();
  int _setup_fd_for_listen();
  int _setup_fd_after_listen();
  int _accept();
  int _close();
  int _get_listen_backlog();

  int _fd{NO_FD};
  bool _ready{true};
  const int _accept_mss;
  const int _backlog;
  const IpEndpoint _local;
  const AcceptOptions &_opt;
  PollDescriptor &_pd;
  TCPListenerObserver &_observer;
  TCPListenerEventIO _ep{*this};
};

extern const NetVCOptions DEFAULT_OPTIONS;
}; // namespace NetAIO
