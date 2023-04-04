/** @file

  Catch based unit tests for PROXY Protocol

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

#include "I_SocketManager.h"
#include "NetVCOptions.h"
#include "P_UnixPollDescriptor.h"
#include "EventIO.h"
#include "NetAIO.h"
#include "tscore/ink_inet.h"
#include <memory>
#include <string_view>

#define CATCH_CONFIG_MAIN
#include "catch.hpp"

#include <optional>

static constexpr std::string_view MESSAGE = "Hello World";

static void
do_poll(PollDescriptor *pd, int poll_timeout)
{
#if TS_USE_EPOLL
  pd->result = epoll_wait(pd->epoll_fd, pd->ePoll_Triggered_Events, POLL_DESCRIPTOR_SIZE, poll_timeout);
#elif TS_USE_KQUEUE
  struct timespec tv;
  tv.tv_sec  = poll_timeout / 1000;
  tv.tv_nsec = 1000000 * (poll_timeout % 1000);
  pd->result = kevent(pd->kqueue_fd, nullptr, 0, pd->kq_Triggered_Events, POLL_DESCRIPTOR_SIZE, &tv);
#endif

  // Get & Process polling result
  for (int x = 0; x < pd->result; x++) {
    NetAIO::TCPConnectionEventIO *epd = static_cast<NetAIO::TCPConnectionEventIO *> get_ev_data(pd, x);
    int flags                         = get_ev_events(pd, x);
    epd->process_event(flags);
    ev_next_event(pd, x);
  }
}

class Echoer : public NetAIO::TCPConnectionObserver
{
public:
  explicit Echoer(int fd, IpEndpoint remote, NetVCOptions &opt, PollDescriptor &pd)
    : _remote(remote), _con(remote, opt, pd, *this, fd)
  {
    _receive(_con);
  }
  virtual ~Echoer() {}

public:
  void
  onConnect(NetAIO::TCPConnection &c) override
  {
    FAIL("Shouldn't get here");
  }

  void
  onRecvmsg(ssize_t bytes, std::unique_ptr<msghdr> msg, NetAIO::TCPConnection &c) override
  {
    REQUIRE(bytes > 0);
    REQUIRE(static_cast<size_t>(bytes) <= sizeof _buf);
    INFO("Echoer::onRecvmsg: got " << bytes << " bytes");

    auto out_msg         = std::make_unique<msghdr>();
    _iov[0].iov_base     = _buf;
    _iov[0].iov_len      = static_cast<size_t>(bytes);
    out_msg->msg_name    = &_remote.sa;
    out_msg->msg_namelen = ats_ip_size(_remote);
    out_msg->msg_iov     = &_iov[0];
    out_msg->msg_iovlen  = 1;
    c.sendmsg(std::move(out_msg), 0);
  }

  void
  onSendmsg(ssize_t bytes, std::unique_ptr<struct msghdr> msg, NetAIO::TCPConnection &c) override
  {
    INFO("Echoer::onSendmsg: sent " << bytes << " bytes");
    _receive(c);
  }

  void
  onError(NetAIO::ErrorSource source, int err, NetAIO::TCPConnection &c) override
  {
    FAIL("Echoer::onError: source = " << source << ", err = " << err << " (" << strerror(err) << ")");
  }

private:
  IpEndpoint _remote;
  NetAIO::TCPConnection _con;
  struct iovec _iov[1];
  char _buf[1024];

  void
  _receive(NetAIO::TCPConnection &c)
  {
    auto in_msg         = std::make_unique<msghdr>();
    _iov[0].iov_base    = _buf;
    _iov[0].iov_len     = sizeof _buf;
    in_msg->msg_name    = &_remote.sa;
    in_msg->msg_namelen = ats_ip_size(_remote);
    in_msg->msg_iov     = &_iov[0];
    in_msg->msg_iovlen  = 1;

    c.recvmsg(std::move(in_msg), 0);
  }
};

class Listener : public NetAIO::TCPListenerObserver
{
public:
  explicit Listener(bool &done, NetVCOptions &opt, PollDescriptor &pd) : _opt(opt), _pd(pd) {}
  void
  onAccept(int fd, IpEndpoint remote) override
  {
    REQUIRE(fd > 0);
    INFO("_remote: " << remote);
    _echoer.emplace(fd, remote, _opt, _pd);
  }
  virtual ~Listener() {}

  void
  onError(NetAIO::ErrorSource source, int err) override
  {
    FAIL("Listener::onError: source = " << source << ", err = " << err << " (" << strerror(err) << ")");
  }

private:
  NetVCOptions &_opt;
  PollDescriptor &_pd;
  std::optional<Echoer> _echoer;
};

class Connector : public NetAIO::TCPConnectionObserver
{
public:
  explicit Connector(bool fastopen, bool &done, const IpEndpoint &remote) : _fastopen(fastopen), _done(done), _remote(remote) {}
  virtual ~Connector() {}

  void
  onConnect(NetAIO::TCPConnection &c) override
  {
    SUCCEED("Connector: connected");

    if (!_fastopen) {
      send(c);
    }
  }

  void
  onRecvmsg(ssize_t bytes, std::unique_ptr<struct msghdr> msg, NetAIO::TCPConnection &c) override
  {
    INFO("Connector::onRecvmsg: got " << bytes << " bytes");
    REQUIRE(bytes > 0);
    REQUIRE(static_cast<size_t>(bytes) <= sizeof _buf);

    // Accumulate the echo and check if we're done.
    std::string_view received_message(_buf, bytes);
    _full_echo.append(received_message);
    if (_full_echo == MESSAGE) {
      _done = true;
    } else {
      _receive(c);
    }
  }

  void
  onSendmsg(ssize_t bytes, std::unique_ptr<struct msghdr> msg, NetAIO::TCPConnection &c) override
  {
    INFO("Connector::onSendmsg: sent " << bytes << " bytes");
    REQUIRE(bytes > 0);
    _bytes_sent += bytes;
    if (_bytes_sent < MESSAGE.size()) {
      send(c);
    } else {
      _receive(c);
    }
  }

  void
  onError(NetAIO::ErrorSource source, int err, NetAIO::TCPConnection &c) override
  {
    FAIL("Connector::onError: source = " << source << ", err = " << err << " (" << strerror(err) << ")");
  }

  void
  send(NetAIO::TCPConnection &c)
  {
    memcpy(_buf, MESSAGE);
    auto out_msg         = std::make_unique<msghdr>();
    _iov[0].iov_base     = _buf;
    _iov[0].iov_len      = MESSAGE.size();
    out_msg->msg_name    = &_remote.sa;
    out_msg->msg_namelen = ats_ip_size(_remote);
    out_msg->msg_iov     = &_iov[0];
    out_msg->msg_iovlen  = 1;
    int flags            = 0;
    if (_fastopen) {
      REQUIRE(MSG_FASTOPEN > 0);
      flags |= MSG_FASTOPEN;
    }
    c.sendmsg(std::move(out_msg), flags);
  }

private:
  const bool _fastopen;
  bool &_done;
  IpEndpoint _remote;
  struct iovec _iov[1];
  char _buf[1024];
  std::string _full_echo;
  size_t _bytes_sent = 0;

  void
  _receive(NetAIO::TCPConnection &c)
  {
    auto in_msg         = std::make_unique<msghdr>();
    _iov[0].iov_base    = _buf;
    _iov[0].iov_len     = sizeof _buf;
    in_msg->msg_name    = &_remote.sa;
    in_msg->msg_namelen = ats_ip_size(_remote);
    in_msg->msg_iov     = &_iov[0];
    in_msg->msg_iovlen  = 1;

    c.recvmsg(std::move(in_msg), 0);
  }
};

TEST_CASE("Listen and Connect", "[listen][connect]")
{
  bool done                      = false;
  constexpr uint16_t LISTEN_PORT = 51525;
  PollDescriptor pd;

  NetVCOptions topt;

  // Set up listener
  IpEndpoint local;
  ats_ip4_set(&local, htonl(INADDR_LOOPBACK), htons(LISTEN_PORT));
  AcceptOptions aopt;
  aopt.local_port = LISTEN_PORT;
  auto l          = std::make_unique<Listener>(done, topt, pd);
  NetAIO::TCPListener listener{local, aopt, 0, 5, pd, *l};

  // Set up connector
  IpEndpoint localhost;
  ats_ip4_set(&localhost, htonl(INADDR_LOOPBACK), htons(LISTEN_PORT));
  auto connector = std::make_unique<Connector>(false, done, localhost);
  NetAIO::TCPConnection conn{localhost, topt, pd, *connector};

  while (!done) {
    do_poll(&pd, 1);
  }
}

TEST_CASE("TCP Fast Open", "[listen][connect][fastopen]")
{
  if (!SocketManager::fastopen_supported()) {
    SUCCEED();
  }

  for (int i = 0; i < 2; i++) {
    bool done                      = false;
    constexpr uint16_t LISTEN_PORT = 51524;
    PollDescriptor pd;

    NetVCOptions topt;
    topt.f_tcp_fastopen = true;

    // Set up listener
    IpEndpoint local;
    ats_ip4_set(&local, htonl(INADDR_LOOPBACK), htons(LISTEN_PORT));
    AcceptOptions aopt;
    aopt.sockopt_flags |= NetVCOptions::SOCK_OPT_TCP_FAST_OPEN;
    auto l             = std::make_unique<Listener>(done, topt, pd);
    NetAIO::TCPListener listener{local, aopt, 0, 5, pd, *l};

    // Set up connector
    IpEndpoint localhost;
    ats_ip4_set(&localhost, htonl(INADDR_LOOPBACK), htons(LISTEN_PORT));
    auto connector = std::make_unique<Connector>(true, done, localhost);
    NetAIO::TCPConnection conn{localhost, topt, pd, *connector};
    connector->send(conn);

    while (!done) {
      do_poll(&pd, 1);
    }
  }
}
