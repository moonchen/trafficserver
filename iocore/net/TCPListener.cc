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

#include "AcceptOptions.h"
#include "NetAIO.h"
#include "I_SocketManager.h"

#include "tscore/ink_assert.h"
#include "tscore/ink_inet.h"
#include "tscore/ink_sock.h"

using namespace NetAIO;
constexpr auto TAG = "TCPListener";

TCPListener::TCPListener(const IpEndpoint &local, const AcceptOptions &_opt, int accept_mss, int backlog, PollDescriptor &pd,
                         TCPListenerObserver &observer)
  : _accept_mss(accept_mss), _backlog(backlog), _local(local), _opt(_opt), _pd(pd), _observer(observer)
{
  if (_listen() == 0) {
    // Empty the accept queue now so that epoll will wake us up when new connections arrive.
    _accept();
  } else {
    _observer.onError(ErrorSource::ES_LISTEN, errno);
  }
}

TCPListener::~TCPListener()
{
  _close();
}

int
TCPListener::_setup_fd_for_listen()
{
  int res = 0;

  ink_assert(_fd != NO_FD);

#ifdef SEND_BUF_SIZE
  {
    int send_buf_size = SEND_BUF_SIZE;
    if ((res = safe_setsockopt(_fd, SOL_SOCKET, SO_SNDBUF, (char *)&send_buf_size, sizeof(int)) < 0)) {
      goto Lerror;
    }
  }
#endif

#ifdef RECV_BUF_SIZE
  {
    int recv_buf_size = RECV_BUF_SIZE;
    if ((res = safe_setsockopt(_fd, SOL_SOCKET, SO_RCVBUF, (char *)&recv_buf_size, sizeof(int))) < 0) {
      goto Lerror;
    }
  }
#endif

  if (_opt.recv_bufsize) {
    if (SocketManager::set_rcvbuf_size(_fd, _opt.recv_bufsize)) {
      // Round down until success
      int rbufsz = ROUNDUP(_opt.recv_bufsize, 1024);
      while (rbufsz) {
        if (SocketManager::set_rcvbuf_size(_fd, rbufsz)) {
          rbufsz -= 1024;
        } else {
          break;
        }
      }
    }
  }

  if (_opt.send_bufsize) {
    if (SocketManager::set_sndbuf_size(_fd, _opt.send_bufsize)) {
      // Round down until success
      int sbufsz = ROUNDUP(_opt.send_bufsize, 1024);
      while (sbufsz) {
        if (SocketManager::set_sndbuf_size(_fd, sbufsz)) {
          sbufsz -= 1024;
        } else {
          break;
        }
      }
    }
  }

  if (safe_fcntl(_fd, F_SETFD, FD_CLOEXEC) < 0) {
    goto Lerror;
  }

  {
    struct linger l;
    l.l_onoff  = 0;
    l.l_linger = 0;
    if ((_opt.sockopt_flags & NetVCOptions::SOCK_OPT_LINGER_ON) && safe_setsockopt(_fd, SOL_SOCKET, SO_LINGER, &l, sizeof l) < 0) {
      goto Lerror;
    }
  }

  if (ats_is_ip6(&_local) && safe_setsockopt(_fd, IPPROTO_IPV6, IPV6_V6ONLY, SOCKOPT_ON, sizeof(int)) < 0) {
    goto Lerror;
  }

  if (safe_setsockopt(_fd, SOL_SOCKET, SO_REUSEADDR, SOCKOPT_ON, sizeof(int)) < 0) {
    goto Lerror;
  }

  if (safe_setsockopt(_fd, SOL_SOCKET, SO_REUSEPORT, SOCKOPT_ON, sizeof(int)) < 0) {
    goto Lerror;
  }
#ifdef SO_REUSEPORT_LB
  if (safe_setsockopt(_fd, SOL_SOCKET, SO_REUSEPORT_LB, SOCKOPT_ON, sizeof(int)) < 0) {
    goto Lerror;
  }
#endif

  if ((_opt.sockopt_flags & NetVCOptions::SOCK_OPT_NO_DELAY) &&
      safe_setsockopt(_fd, IPPROTO_TCP, TCP_NODELAY, SOCKOPT_ON, sizeof(int)) < 0) {
    goto Lerror;
  }

  // enables 2 hour inactivity probes, also may fix IRIX FIN_WAIT_2 leak
  if ((_opt.sockopt_flags & NetVCOptions::SOCK_OPT_KEEP_ALIVE) &&
      safe_setsockopt(_fd, SOL_SOCKET, SO_KEEPALIVE, SOCKOPT_ON, sizeof(int)) < 0) {
    goto Lerror;
  }

#ifdef TCP_FASTOPEN
  if ((_opt.sockopt_flags & NetVCOptions::SOCK_OPT_TCP_FAST_OPEN) &&
      safe_setsockopt(_fd, IPPROTO_TCP, TCP_FASTOPEN, SOCKOPT_ON, sizeof(int)) < 0) {
    // safe_setsockopt(_fd, IPPROTO_TCP, TCP_FASTOPEN, &_opt.tfo_queue_length, sizeof(int)) < 0) {
    goto Lerror;
  }
#endif

  if (_opt.f_inbound_transparent) {
#if TS_USE_TPROXY
    Debug("http_tproxy", "Listen port inbound transparency enabled.");
    if (safe_setsockopt(_fd, SOL_IP, TS_IP_TRANSPARENT, SOCKOPT_ON, sizeof(int)) < 0) {
      Fatal("[TCPListener::listen] Unable to set transparent socket option [%d] %s\n", errno, strerror(errno));
    }
#else
    Error("[TCPListener::listen] Transparency requested but TPROXY not configured\n");
#endif
  }

  if (_opt.f_proxy_protocol) {
    Debug("proxyprotocol", "Proxy Protocol enabled.");
  }

#if defined(TCP_MAXSEG)
  if (_accept_mss > 0) {
    if (safe_setsockopt(_fd, IPPROTO_TCP, TCP_MAXSEG, reinterpret_cast<const char *>(&_accept_mss), sizeof _accept_mss) < 0) {
      goto Lerror;
    }
  }
#endif

  if (_opt.f_mptcp) {
#if MPTCP_ENABLED
    if (safe_setsockopt(_fd, IPPROTO_TCP, MPTCP_ENABLED, SOCKOPT_ON, sizeof(int)) < 0) {
      Error("[TCPListener::listen] Unable to enable MPTCP socket-option [%d] %s\n", errno, strerror(errno));
      goto Lerror;
    }
#else
    Error("[TCPListener::listen] Multipath TCP requested but not configured on this host\n");
#endif
  }

#ifdef TCP_DEFER_ACCEPT
  // set tcp defer accept timeout if it is configured, this will not trigger an accept until there is
  // data on the socket ready to be read
  if (_opt.defer_accept > 0 && setsockopt(_fd, IPPROTO_TCP, TCP_DEFER_ACCEPT, &_opt.defer_accept, sizeof(int)) < 0) {
    // FIXME: should we go to the error
    // goto error;
    Error("[TCPListener::listen] Defer accept is configured but set failed: %d", errno);
  }
#endif

  if (safe_nonblocking(_fd) < 0) {
    goto Lerror;
  }

  return 0;

Lerror:
  res = -errno;

  // coverity[check_after_sink]
  if (_fd != NO_FD) {
    _close();
  }

  return res;
}

int
TCPListener::_setup_fd_after_listen()
{
#ifdef SO_ACCEPTFILTER
  // SO_ACCEPTFILTER needs to be set **after** listen
  if (_opt.defer_accept > 0) {
    int file_id = kldfind("accf_data");

    struct kld_file_stat stat;
    stat.version = sizeof(stat);

    if (kldstat(file_id, &stat) < 0) {
      Error("[TCPListener::listen] Ignored defer_accept config. Because accf_data module is not loaded errno=%d", errno);
    } else {
      struct accept_filter_arg afa;

      bzero(&afa, sizeof(afa));
      strcpy(afa.af_name, "dataready");

      if (setsockopt(this->_fd, SOL_SOCKET, SO_ACCEPTFILTER, &afa, sizeof(afa)) < 0) {
        Error("[TCPListener::listen] Defer accept is configured but set failed: %d", errno);
        return -errno;
      }
    }
  }
#endif

  return 0;
}

int
TCPListener::_listen()
{
  ink_assert(_fd == NO_FD);
  int res = 0;

  ink_release_assert(ats_is_ip(_local));

  _fd = res = SocketManager::socket(_local.sa.sa_family, SOCK_STREAM, IPPROTO_TCP);
  if (res < 0) {
    goto Lerror;
  }

  res = _setup_fd_for_listen();
  if (res < 0) {
    goto Lerror;
  }

  if ((res = SocketManager::ink_bind(_fd, &_local.sa, ats_ip_size(&_local.sa), IPPROTO_TCP)) < 0) {
    goto Lerror;
  }

  res = _ep.start(&_pd, _fd, EVENTIO_READ);
  if (res < 0) {
    goto Lerror;
  }

  if ((res = safe_listen(_fd, _backlog)) < 0) {
    goto Lerror;
  }

  res = _setup_fd_after_listen();
  if (res < 0) {
    goto Lerror;
  }

  return 0;

Lerror:
  if (_fd != NO_FD) {
    _close();
  }

  Debug(TAG, "Could not bind or listen to port %d (error: %d)", ats_ip_port_host_order(&_local), res);
  return res;
}

int
TCPListener::_accept()
{
  int res = 0;
  struct sockaddr sa;
  socklen_t sz = sizeof sa;

  while (res >= 0 && _ready) {
    res = SocketManager::accept4(_fd, &sa, &sz, SOCK_NONBLOCK | SOCK_CLOEXEC);
    if (res < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        _ready = false;
        _ep.modify(EVENTIO_READ);
        _ep.refresh(EVENTIO_READ);
      }
    } else {
      if (is_debug_tag_set("iocore_net_server")) {
        ip_port_text_buffer ipb1, ipb2;
        Debug("iocore_net_server", "Connection accepted [TCPListener]. %s -> %s", ats_ip_nptop(&sa, ipb2, sizeof(ipb2)),
              ats_ip_nptop(&_local, ipb1, sizeof(ipb1)));
      }

#ifdef SEND_BUF_SIZE
      SocketManager::set_sndbuf_size(c->_fd, SEND_BUF_SIZE);
#endif
      _observer.onAccept(res, {sa});
    }
  }

  return res;
}

int
TCPListener::_close()
{
  // don't close any of the standards
  if (_fd >= 2 && _fd != NO_FD) {
    int fd_save = _fd;
    _fd         = NO_FD;
    return SocketManager::close(fd_save);
  } else {
    Error("TCPListener should not be managing fd %d", _fd);
    ink_assert(!"Wrong fd in TCPListener::close()");
    _fd = NO_FD;
    return -EINVAL;
  }
}

void
TCPListener::poll(int flags)
{
  _ready = true;
  _accept();
}

int
TCPListenerEventIO::start(EventLoop l, int fd, int events)
{
  return start_common(l, fd, events);
}

void
TCPListenerEventIO::process_event(int flags)
{
  _listener.poll(flags);
}
