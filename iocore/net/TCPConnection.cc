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
#include "I_SocketManager.h"
#include "NetAIO.h"
#include "NetVCOptions.h"
#include "ScopeGuard.h"

#include "tscore/ink_assert.h"
#include "tscore/ink_sock.h"

#include <optional>
#include <sys/socket.h>

const NetVCOptions NetAIO::DEFAULT_OPTIONS{};
static constexpr auto TAG{"TCPConnection"};

NetAIO::TCPConnection::TCPConnection(const IpEndpoint &target, const NetVCOptions *opt, PollDescriptor &pd,
                                     TCPConnectionObserver &observer, int fd)
  : _fd{fd}, _remote{target}, _opt{opt}, _pd(pd), _observer{observer}, _thread_id{std::this_thread::get_id()}
{
  if (_fd == NO_FD) {
    if (_open()) {
      _connect();
    }
    _state = State::TCP_CONNECTING;
  } else {
    if (_register_poll()) {
      _state = State::TCP_CONNECTED;
    } else {
      _observer.onError(ErrorSource::ES_REGISTER, errno, *this);
      _state = State::TCP_CLOSED;
    }
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
  if (NetVCOptions::FOREIGN_ADDR == _opt->addr_binding || NetVCOptions::INTF_ADDR == _opt->addr_binding) {
    // Same for now, transparency for foreign addresses must be handled
    // *after* the socket is created, and we need to do this calculation
    // before the socket to get the IP family correct.
    ink_release_assert(_opt->local_ip.isValid());
    local_addr.assign(_opt->local_ip, htons(_opt->local_port));
    family = _opt->local_ip.family();
  } else {
    // No local address specified, so use family option if possible.
    family = ats_is_ip(_opt->ip_family) ? _opt->ip_family : AF_INET;
    local_addr.setToAnyAddr(family);
    is_any_address                  = true;
    local_addr.network_order_port() = htons(_opt->local_port);
  }

  res = SocketManager::socket(family, SOCK_STREAM, 0);
  if (-1 == res) {
    _observer.onError(ErrorSource::ES_SOCKET, errno, *this);
    return false;
  }

  _fd = res;
  // mark _fd for close until we succeed.
  ScopeGuard cleanup{[this]() { close(); }};

  // Try setting the various socket options, if requested.

  if (-1 == safe_setsockopt(_fd, SOL_SOCKET, SO_REUSEADDR, reinterpret_cast<char *>(&enable_reuseaddr), sizeof(enable_reuseaddr))) {
    _observer.onError(ErrorSource::ES_SETSOCKOPT, errno, *this);
    return false;
  }

  if (NetVCOptions::FOREIGN_ADDR == _opt->addr_binding) {
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
    _observer.onError(ErrorSource::ES_FCNTL, errno, *this);
    return false;
  }

  if (_opt->socket_recv_bufsize > 0) {
    if (SocketManager::set_rcvbuf_size(_fd, _opt->socket_recv_bufsize)) {
      // Round down until success
      int rbufsz = ROUNDUP(_opt->socket_recv_bufsize, 1024);
      while (rbufsz && !SocketManager::set_rcvbuf_size(_fd, rbufsz)) {
        rbufsz -= 1024;
      }
      Debug(TAG, "::open: recv_bufsize = %d of %d", rbufsz, _opt->socket_recv_bufsize);
    }
  }
  if (_opt->socket_send_bufsize > 0) {
    if (SocketManager::set_sndbuf_size(_fd, _opt->socket_send_bufsize)) {
      // Round down until success
      int sbufsz = ROUNDUP(_opt->socket_send_bufsize, 1024);
      while (sbufsz && !SocketManager::set_sndbuf_size(_fd, sbufsz)) {
        sbufsz -= 1024;
      }
      Debug(TAG, "::open: send_bufsize = %d of %d", sbufsz, _opt->socket_send_bufsize);
    }
  }

  // apply dynamic options
  apply_options(_opt);

  if (local_addr.network_order_port() || !is_any_address) {
    if (-1 == SocketManager::ink_bind(_fd, &local_addr.sa, ats_ip_size(&local_addr.sa))) {
      _observer.onError(ErrorSource::ES_BIND, errno, *this);
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
  apply_options(_opt);

  ScopeGuard cleanup{[this]() { close(); }}; // mark for close until we succeed.

  if (!_register_poll()) {
    _observer.onError(ErrorSource::ES_REGISTER, errno, *this);
    return;
  }

  if (_opt->f_tcp_fastopen) {
    // TCP Fast Open is (effectively) a non-blocking connect, so set the
    // return value we would see in that case.
    errno        = EINPROGRESS;
    res          = -1;
    _write_ready = true;
  } else {
    _write_ready = false;
    res          = ::connect(_fd, &_remote.sa, ats_ip_size(&this->_remote.sa));
  }

  if (-1 == res && !(EINPROGRESS == errno || EWOULDBLOCK == errno)) {
    _state = State::TCP_CLOSED;
    _observer.onError(ErrorSource::ES_CONNECT, errno, *this);
    return;
  } else if (-1 == res && (EINPROGRESS == errno || EWOULDBLOCK == errno)) {
    _state = State::TCP_CONNECTING;
    Debug(TAG, "%d: connecting", _fd);
    _read_ready  = false;
    _write_ready = false;
  } else if (res == 0) {
    _state = State::TCP_CONNECTED;
  } else {
    ink_release_assert(!"Unexpected return value from connect()");
  }

  cleanup.reset();
}

void
NetAIO::TCPConnection::apply_options(const NetVCOptions *options)
{
  _opt = options;

  // Set options which can be changed after a connection is established
  // ignore other changes
  if (_opt->sockopt_flags & NetVCOptions::SOCK_OPT_NO_DELAY) {
    safe_setsockopt(_fd, IPPROTO_TCP, TCP_NODELAY, SOCKOPT_ON, sizeof(int));
    Debug(TAG, "::open: setsockopt() state::TCP_NODELAY on socket");
  }
  if (_opt->sockopt_flags & NetVCOptions::SOCK_OPT_KEEP_ALIVE) {
    safe_setsockopt(_fd, SOL_SOCKET, SO_KEEPALIVE, SOCKOPT_ON, sizeof(int));
    Debug(TAG, "::open: setsockopt() SO_KEEPALIVE on socket");
  }
  if (_opt->sockopt_flags & NetVCOptions::SOCK_OPT_LINGER_ON) {
    struct linger l;
    l.l_onoff  = 1;
    l.l_linger = 0;
    safe_setsockopt(_fd, SOL_SOCKET, SO_LINGER, reinterpret_cast<char *>(&l), sizeof(l));
    Debug(TAG, "::open:: setsockopt() turn on SO_LINGER on socket");
  }
#ifdef TCP_NOTSENT_LOWAT
  if (_opt->sockopt_flags & NetVCOptions::SOCK_OPT_TCP_NOTSENT_LOWAT) {
    uint32_t lowat = _opt->packet_notsent_lowat;
    safe_setsockopt(_fd, IPPROTO_TCP, TCP_NOTSENT_LOWAT, reinterpret_cast<char *>(&lowat), sizeof(lowat));
    Debug(TAG, "::open:: setsockopt() set state::TCP_NOTSENT_LOWAT to %d", lowat);
  }
#endif

#if TS_HAS_SO_MARK
  if (_opt->sockopt_flags & NetVCOptions::SOCK_OPT_PACKET_MARK) {
    uint32_t mark = _opt->packet_mark;
    safe_setsockopt(_fd, SOL_SOCKET, SO_MARK, reinterpret_cast<char *>(&mark), sizeof(uint32_t));
  }
#endif

#if TS_HAS_IP_TOS
  if (_opt->sockopt_flags & NetVCOptions::SOCK_OPT_PACKET_TOS) {
    uint32_t tos = _opt->packet_tos;
    if (_remote.isIp4()) {
      safe_setsockopt(_fd, IPPROTO_IP, IP_TOS, reinterpret_cast<char *>(&tos), sizeof(uint32_t));
    } else if (_remote.isIp6()) {
      safe_setsockopt(_fd, IPPROTO_IPV6, IPV6_TCLASS, reinterpret_cast<char *>(&tos), sizeof(uint32_t));
    }
  }
#endif
}

void
NetAIO::TCPConnection::close()
{
  // don't close any of the standards
  if (_fd >= 2 && _fd != NO_FD) {
    int fd_save = _fd;
    _fd         = NO_FD;
    int res     = SocketManager::close(fd_save);
    Debug(TAG, "close(%d) -> %d", fd_save, res);
    _observer.onClose(*this);
  } else if (_fd == NO_FD) {
    // Do nothing
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

  if (_read_ready) {
    int res = ::recvmsg(_fd, msg.get(), flags);
    Debug(TAG, "recvmsg(%d, %p, %d) -> res=%d, errno = %d", _fd, msg.get(), flags, res, errno);
    if (res == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        Debug(TAG, "poll: %d read not ready", _fd);
        _read_ready = false;
      } else {
        _observer.onError(ErrorSource::ES_RECVMSG, errno, *this);
      }
    } else {
      ink_assert(res >= 0);
      _observer.onRecvmsg(res, std::move(msg), *this);
    }
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

  ink_assert(_state == State::TCP_CONNECTED || _state == State::TCP_CONNECTING);
  ink_release_assert(!_sendmsg_msg);

  if (_write_ready) {
    int res = ::sendmsg(_fd, msg.get(), flags);
    Debug(TAG, "sendmsg(%d, %p, %d) -> res=%d, errno=%d", _fd, msg.get(), flags, res, errno);
    if (res == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK || (errno == EINPROGRESS && _opt->f_tcp_fastopen)) {
        Debug(TAG, "poll: %d write not ready", _fd);
        _write_ready = false;
      } else {
        _observer.onError(ErrorSource::ES_SENDMSG, errno, *this);
      }
    } else {
      _observer.onSendmsg(res, std::move(_sendmsg_msg), *this);
    }
  }

  if (!_write_ready) {
    _rearm_write();
    _sendmsg_in_progress = true;
    _sendmsg_msg         = std::move(msg);
    _sendmsg_flags       = flags;
  }

  return true;
}

bool
NetAIO::TCPConnection::shutdown(int how)
{
  int res = SocketManager::shutdown(_fd, how);
  if (res == 0) {
    if (how == SHUT_RD) {
      _state = State::TCP_SHUTDOWN_RD;
    } else if (how == SHUT_WR) {
      _state = State::TCP_SHUTDOWN_WR;
    } else if (how == SHUT_RDWR) {
      _state = State::TCP_SHUTDOWN_RDWR;
    }
  } else {
    _observer.onError(ErrorSource::ES_SHUTDOWN, errno, *this);
  }
  return true;
}

void
NetAIO::TCPConnection::_poll_connected(int flags)
{
  if (_recvmsg_in_progress && _read_ready) {
    int res = ::recvmsg(_fd, _recvmsg_msg.get(), _recvmsg_flags);
    Debug(TAG, "recvmsg(%d, %p, %d) -> res=%d, errno = %d", _fd, _recvmsg_msg.get(), _recvmsg_flags, res, errno);
    if (res == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        Debug(TAG, "poll: %d read not ready", _fd);
        _read_ready = false;
        _rearm_read();
        return;
      } else {
        _observer.onError(ErrorSource::ES_RECVMSG, errno, *this);
      }
    } else {
      _recvmsg_in_progress = false;
      _observer.onRecvmsg(res, std::move(_recvmsg_msg), *this);
    }
  }

  if (_sendmsg_in_progress && _write_ready) {
    int res = ::sendmsg(_fd, _sendmsg_msg.get(), _sendmsg_flags);
    Debug(TAG, "sendmsg(%d, %p, %d) -> res=%d, errno=%d", _fd, _sendmsg_msg.get(), _sendmsg_flags, res, errno);
    if (res == -1) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        Debug(TAG, "poll: %d write not ready", _fd);
        _write_ready = false;
        _rearm_write();
        return;
      } else {
        _observer.onError(ErrorSource::ES_SENDMSG, errno, *this);
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
    Debug(TAG, "poll: %d read ready", _fd);
    _read_ready = true;
  }

  if (flags & EVENTIO_WRITE) {
    Debug(TAG, "poll: %d write ready", _fd);
    _write_ready = true;
  }

  if (flags & EVENTIO_ERROR) {
    int error;
    socklen_t errlen = sizeof error;
    getsockopt(_fd, SOL_SOCKET, SO_ERROR, &error, &errlen);
    _observer.onError(ErrorSource::ES_POLL, error, *this);
    return;
  }

  if (_state == State::TCP_CONNECTING) {
    if (_write_ready) {
      _state = State::TCP_CONNECTED;
      _observer.onConnect(*this);
    }
  }

  // Fall through since we may have data to read/write.
  if (_state == State::TCP_CONNECTED) {
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
