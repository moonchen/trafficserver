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
#include "EventIO.h"
#include "NetAIO.h"
#include "ScopeGuard.h"
#include "I_SocketManager.h"

#include "tscore/ink_assert.h"
#include "tscore/ink_sock.h"
#include "tscore/ink_assert.h"

#include <sys/socket.h>

const NetVCOptions NetAIO::DEFAULT_OPTIONS{};
static constexpr auto TAG{"TCPConnection"};

NetAIO::TCPConnection::TCPConnection(const IpEndpoint &target, const NetVCOptions &opt, PollDescriptor &pd,
                                     TCPConnectionObserver &observer, int fd)
  : _fd{fd}, _remote{target}, _opt{opt}, _pd(pd), _observer{observer}, _thread_id{std::this_thread::get_id()}
{
  if (_fd == NO_FD) {
    if (_open()) {
      _connect();
    }
    _state = TCP_CONNECTING;
  } else {
    _ep.start(&_pd, _fd, EVENTIO_READ | EVENTIO_WRITE);
    _state = TCP_CONNECTED;
  }
}

bool
NetAIO::TCPConnection::_open()
{
  ink_assert(_fd == NO_FD);
  int enable_reuseaddr = 1; // used for sockopt setting
  int res              = 0; // temp result
  IpEndpoint local_addr;
  int family;

  bool is_any_address = false;
  if (NetVCOptions::FOREIGN_ADDR == _opt.addr_binding || NetVCOptions::INTF_ADDR == _opt.addr_binding) {
    // Same for now, transparency for foreign addresses must be handled
    // *after* the socket is created, and we need to do this calculation
    // before the socket to get the IP family correct.
    ink_release_assert(_opt.local_ip.isValid());
    local_addr.assign(_opt.local_ip, htons(_opt.local_port));
    family = _opt.local_ip.family();
  } else {
    // No local address specified, so use family option if possible.
    family = ats_is_ip(_opt.ip_family) ? _opt.ip_family : AF_INET;
    local_addr.setToAnyAddr(family);
    is_any_address                  = true;
    local_addr.network_order_port() = htons(_opt.local_port);
  }

  res = SocketManager::socket(family, SOCK_STREAM, 0);
  if (-1 == res) {
    _observer.onError(ES_SOCKET, errno, *this);
    return false;
  }

  _fd = res;
  // mark _fd for close until we succeed.
  ScopeGuard cleanup{[this]() { _close(); }};

  // Try setting the various socket options, if requested.

  if (-1 == safe_setsockopt(_fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char *>(&enable_reuseaddr), sizeof(enable_reuseaddr))) {
    _observer.onError(ES_SETSOCKOPT, errno, *this);
    return false;
  }

  if (NetVCOptions::FOREIGN_ADDR == _opt.addr_binding) {
    static char const *const DEBUG_TEXT = "::open setsockopt() IP_TRANSPARENT";
#if TS_USE_TPROXY
    int value = 1;
    if (-1 == safe_setsockopt(_fd, SOL_IP, TS_IP_TRANSPARENT, reinterpret_cast<char *>(&value), sizeof(value))) {
      Debug(TAG, "%s - fail %d:%s", DEBUG_TEXT, errno, strerror(errno));
      return -errno;
    } else {
      Debug(TAG, "%s set", DEBUG_TEXT);
    }
#else
    Debug(TAG, "%s - requested but TPROXY not configured", DEBUG_TEXT);
#endif
  }

  if (-1 == safe_nonblocking(_fd)) {
    _observer.onError(ES_FCNTL, errno, *this);
    return false;
  }

  if (_opt.socket_recv_bufsize > 0) {
    if (SocketManager::set_rcvbuf_size(_fd, _opt.socket_recv_bufsize)) {
      // Round down until success
      int rbufsz = ROUNDUP(_opt.socket_recv_bufsize, 1024);
      while (rbufsz && !SocketManager::set_rcvbuf_size(_fd, rbufsz)) {
        rbufsz -= 1024;
      }
      Debug(TAG, "::open: recv_bufsize = %d of %d", rbufsz, _opt.socket_recv_bufsize);
    }
  }
  if (_opt.socket_send_bufsize > 0) {
    if (SocketManager::set_sndbuf_size(_fd, _opt.socket_send_bufsize)) {
      // Round down until success
      int sbufsz = ROUNDUP(_opt.socket_send_bufsize, 1024);
      while (sbufsz && !SocketManager::set_sndbuf_size(_fd, sbufsz)) {
        sbufsz -= 1024;
      }
      Debug(TAG, "::open: send_bufsize = %d of %d", sbufsz, _opt.socket_send_bufsize);
    }
  }

  // apply dynamic options
  _apply_options();

  if (local_addr.network_order_port() || !is_any_address) {
    if (-1 == SocketManager::ink_bind(_fd, &local_addr.sa, ats_ip_size(&local_addr.sa))) {
      _observer.onError(ES_BIND, errno, *this);
      return false;
    }
  }

  cleanup.reset();
  return true;
}

void
NetAIO::TCPConnection::_connect()
{
  ink_assert(_fd != NO_FD);

  int res;

  // apply dynamic options with this.addr initialized
  _apply_options();

  ScopeGuard cleanup{[this]() { _close(); }}; // mark for close until we succeed.

  if (!_register_poll()) {
    _observer.onError(ES_REGISTER, errno, *this);
    return;
  }

  if (_opt.f_tcp_fastopen) {
    // TCP Fast Open is (effectively) a non-blocking connect, so set the
    // return value we would see in that case.
    errno = EINPROGRESS;
    res   = -1;
  } else {
    res = ::connect(_fd, &_remote.sa, ats_ip_size(&this->_remote.sa));
  }

  // It's only really an error if either the connect was blocking
  // or it wasn't blocking and the error was other than EINPROGRESS.
  // (Is EWOULDBLOCK ok? Does that start the connect?)
  // We also want to handle the cases where the connect blocking
  // and IO blocking differ, by turning it on or off as needed.
  if (-1 == res && !(EINPROGRESS == errno || EWOULDBLOCK == errno)) {
    _observer.onError(ES_CONNECT, errno, *this);
    return;
  }

  cleanup.reset();
  _state = TCP_CONNECTING;
  // Wait for the connect to complete.
  _ep.start(&_pd, _fd, EVENTIO_WRITE);
}

void
NetAIO::TCPConnection::_apply_options()
{
  // Set options which can be changed after a connection is established
  // ignore other changes
  if (_opt.sockopt_flags & NetVCOptions::SOCK_OPT_NO_DELAY) {
    safe_setsockopt(_fd, IPPROTO_TCP, TCP_NODELAY, SOCKOPT_ON, sizeof(int));
    Debug(TAG, "::open: setsockopt() TCP_NODELAY on socket");
  }
  if (_opt.sockopt_flags & NetVCOptions::SOCK_OPT_KEEP_ALIVE) {
    safe_setsockopt(_fd, SOL_SOCKET, SO_KEEPALIVE, SOCKOPT_ON, sizeof(int));
    Debug(TAG, "::open: setsockopt() SO_KEEPALIVE on socket");
  }
  if (_opt.sockopt_flags & NetVCOptions::SOCK_OPT_LINGER_ON) {
    struct linger l;
    l.l_onoff  = 1;
    l.l_linger = 0;
    safe_setsockopt(_fd, SOL_SOCKET, SO_LINGER, reinterpret_cast<char *>(&l), sizeof(l));
    Debug(TAG, "::open:: setsockopt() turn on SO_LINGER on socket");
  }
#ifdef TCP_NOTSENT_LOWAT
  if (_opt.sockopt_flags & NetVCOptions::SOCK_OPT_TCP_NOTSENT_LOWAT) {
    uint32_t lowat = _opt.packet_notsent_lowat;
    safe_setsockopt(_fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, reinterpret_cast<char *>(&lowat), sizeof(lowat));
    Debug(TAG, "::open:: setsockopt() set TCP_NOTSENT_LOWAT to %d", lowat);
  }
#endif

#if TS_HAS_SO_MARK
  if (_opt.sockopt_flags & NetVCOptions::SOCK_OPT_PACKET_MARK) {
    uint32_t mark = _opt.packet_mark;
    safe_setsockopt(_fd, SOL_SOCKET, SO_MARK, reinterpret_cast<char *>(&mark), sizeof(uint32_t));
  }
#endif

#if TS_HAS_IP_TOS
  if (_opt.sockopt_flags & NetVCOptions::SOCK_OPT_PACKET_TOS) {
    uint32_t tos = _opt.packet_tos;
    if (_remote.isIp4()) {
      safe_setsockopt(_fd, IPPROTO_IP, IP_TOS, reinterpret_cast<char *>(&tos), sizeof(uint32_t));
    } else if (_remote.isIp6()) {
      safe_setsockopt(_fd, IPPROTO_IPV6, IPV6_TCLASS, reinterpret_cast<char *>(&tos), sizeof(uint32_t));
    }
  }
#endif
}

void
NetAIO::TCPConnection::_close()
{
  // don't close any of the standards
  if (_fd >= 2 && _fd != NO_FD) {
    int fd_save = _fd;
    _fd         = NO_FD;
    SocketManager::close(fd_save);
  } else {
    Error("TCPConnection should not be managing fd %d", _fd);
    ink_assert(!"Wrong fd in TCPConnection::close()");
    _fd = NO_FD;
  }
}

bool
NetAIO::TCPConnection::recvmsg(std::unique_ptr<struct msghdr> msg, int flags)
{
  ink_release_assert(std::this_thread::get_id() == _thread_id);
  ink_release_assert(_fd != NO_FD);
  ink_release_assert(msg);

  if (_recvmsg_in_progress) {
    ink_release_assert(_recvmsg_msg);
    return false;
  }

  ink_release_assert(!_recvmsg_msg);

  if (_state != TCP_CONNECTED) {
    _observer.onError(ES_RECVMSG, ENOTCONN, *this);
    return false;
  }

  if (_read_ready) {
    int res = ::recvmsg(_fd, msg.get(), flags);
    if (res == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        _read_ready = false;
      } else {
        _observer.onError(ES_RECVMSG, errno, *this);
      }
    } else {
      _observer.onRecvmsg(res, std::move(msg), *this);
    }
    // TODO: if less than the full amount is read, consider the fd not ready for read.
  }

  if (!_read_ready) {
    _rearm_read();
    _recvmsg_in_progress = true;
    _recvmsg_msg         = std::move(msg);
    _recvmsg_flags       = flags;
  }

  return true;
}

bool
NetAIO::TCPConnection::sendmsg(std::unique_ptr<struct msghdr> msg, int flags)
{
  ink_release_assert(std::this_thread::get_id() == _thread_id);
  ink_release_assert(_fd != NO_FD);

  if (_sendmsg_in_progress) {
    ink_release_assert(_sendmsg_msg);
    return false;
  }

  if (_state == TCP_CONNECTED || (_state == TCP_CONNECTING && _opt.f_tcp_fastopen)) {
    ink_release_assert(!_sendmsg_msg);

    if (_write_ready) {
      int res = ::sendmsg(_fd, msg.get(), flags);
      if (res == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
          _write_ready = false;
        } else {
          _observer.onError(ES_SENDMSG, errno, *this);
        }
      } else {
        _observer.onSendmsg(res, std::move(_sendmsg_msg), *this);
      }
      // TODO: if less than the full amount is written, consider the fd not ready for write.
    }

    if (!_write_ready) {
      _rearm_write();
      _sendmsg_in_progress = true;
      _sendmsg_msg         = std::move(msg);
      _sendmsg_flags       = flags;
    }
  } else {
    _observer.onError(ES_SENDMSG, ENOTCONN, *this);
    return false;
  }

  return true;
}

void
NetAIO::TCPConnection::_poll_connected(int flags)
{
  if (_recvmsg_in_progress && _read_ready) {
    int res = ::recvmsg(_fd, _recvmsg_msg.get(), _recvmsg_flags);
    if (res == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        _read_ready = false;
        _rearm_read();
        return;
      } else {
        _observer.onError(ES_RECVMSG, errno, *this);
      }
    } else {
      _recvmsg_in_progress = false;
      _observer.onRecvmsg(res, std::move(_recvmsg_msg), *this);
    }
  }

  if (_sendmsg_in_progress && _write_ready) {
    int res = ::sendmsg(_fd, _sendmsg_msg.get(), _sendmsg_flags);
    if (res == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        _write_ready = false;
        _rearm_write();
        return;
      } else {
        _observer.onError(ES_SENDMSG, errno, *this);
      }
    } else {
      _sendmsg_in_progress = false;
      _observer.onSendmsg(res, std::move(_sendmsg_msg), *this);
    }
  }
}

void
NetAIO::TCPConnection::poll(int flags)
{
  // Edge-triggered epoll: update states
  if (flags & EVENTIO_READ) {
    _read_ready = true;
  }

  if (flags & EVENTIO_WRITE) {
    _write_ready = true;
  }

  if (_state == TCP_CONNECTING) {
    if (_write_ready) {
      _state = TCP_CONNECTED;
      _observer.onConnect(*this);
    }
  }

  // Fall through since we may have data to read/write.
  if (_state == TCP_CONNECTED) {
    _poll_connected(flags);
  }
}

bool
NetAIO::TCPConnection::_register_poll()
{
  return (_ep.start(&_pd, _fd, EVENTIO_READ | EVENTIO_WRITE) == 0);
}

int
NetAIO::TCPConnectionEventIO::start(EventLoop l, int fd, int events)
{
  return start_common(l, fd, events);
}

void
NetAIO::TCPConnectionEventIO::process_event(int flags)
{
  _tcpcon.poll(flags);
}
