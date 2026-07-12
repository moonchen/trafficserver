/** @file

  Catch based unit test harness for SSLNetVConnection ("reducer")

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

#include "../P_SSLNetVConnection.h"
#include "../P_UnixNetVConnection.h"
#include "iocore/eventsystem/VIO.h"
#include "iocore/eventsystem/IOBuffer.h"

#include <openssl/ssl.h>
#include <string>
#include <vector>

void reducer_make_self_signed(std::string &cert_pem, std::string &key_pem);

// Publishes a self-signed server cert as the default TLS context so an inbound
// SUT can complete SSL_accept. Writes files into `dir` (use a scratch dir).
void reducer_install_server_cert(const std::string &cert_pem, const std::string &key_pem, const std::string &dir);

// Appends a process-global, one-shot cert hook: it parks the next inbound handshake at
// TS_SSL_CERT_HOOK (records the VC, does not reenable), then disarms itself so every later
// handshake passes through -- unrelated tests sharing the process are unaffected regardless of
// run order. Registration happens once; observe the park via reducer_hook_fired()/reducer_hook_vc().
void               reducer_install_parking_cert_hook();
bool               reducer_hook_fired();
SSLNetVConnection *reducer_hook_vc();

class BarePeer
{
public:
  explicit BarePeer(bool server, const std::string &cert_pem, const std::string &key_pem);
  ~BarePeer();

  BIO *
  rbio() const
  {
    return _rbio;
  }
  BIO *
  wbio() const
  {
    return _wbio;
  }

  int do_handshake();
  bool
  handshake_done() const
  {
    return SSL_is_init_finished(_ssl);
  }
  int
  write_app(const void *buf, int len)
  {
    return SSL_write(_ssl, buf, len);
  }
  int
  read_app(void *buf, int len)
  {
    return SSL_read(_ssl, buf, len);
  }

private:
  SSL_CTX *_ctx  = nullptr;
  SSL     *_ssl  = nullptr;
  BIO     *_rbio = nullptr; // memory BIO the peer reads ciphertext from
  BIO     *_wbio = nullptr; // memory BIO the peer writes ciphertext to
};

class MockTransportVC : public UnixNetVConnection
{
public:
  MockTransportVC();

  VIO *do_io_read(Continuation *c, int64_t nbytes, MIOBuffer *buf) override;
  VIO *do_io_write(Continuation *c, int64_t nbytes, IOBufferReader *buf, bool owner = false) override;
  void do_io_close(int lerrno = -1) override;
  void do_io_shutdown(ShutdownHowTo_t howto) override;
  void reenable(VIO *vio) override;
  void reenable_re(VIO *vio) override;

  // Socket/timeout methods must not touch real NetHandler/fd state in a unit test.
  SOCKET
  get_socket() override { return _test_fd; }
  void
  set_active_timeout(ink_hrtime) override
  {
  }
  void
  set_inactivity_timeout(ink_hrtime) override
  {
  }
  void
  set_default_inactivity_timeout(ink_hrtime) override
  {
  }
  bool
  is_default_inactivity_timeout() override
  {
    return false;
  }
  void
  cancel_active_timeout() override
  {
  }
  void
  cancel_inactivity_timeout() override
  {
  }
  void
  add_to_keep_alive_queue() override
  {
  }
  void
  remove_from_keep_alive_queue() override
  {
  }
  bool
  add_to_active_queue() override
  {
    return true;
  }
  void
  apply_options() override
  {
  }

  VIO *
  read_vio()
  {
    return &_read_vio;
  }
  VIO *
  write_vio()
  {
    return &_write_vio;
  }
  MIOBuffer *
  sut_read_buf() const
  {
    return _sut_read_buf;
  }
  IOBufferReader *
  sut_write_reader() const
  {
    return _sut_write_reader;
  }
  bool
  closed() const
  {
    return _closed;
  }
  int
  close_errno() const
  {
    return _close_errno;
  }
  void
  set_test_fd(int fd)
  {
    _test_fd = fd;
  }

private:
  VIO             _read_vio{VIO::READ};
  VIO             _write_vio{VIO::WRITE};
  MIOBuffer      *_sut_read_buf     = nullptr;
  IOBufferReader *_sut_write_reader = nullptr;
  bool            _closed           = false;
  int             _close_errno      = 0;
  SOCKET          _test_fd          = NO_FD;
};

// A stand-in consumer (HttpSM's role): owns the user VIOs the SUT hands back and records the
// signals the SUT delivers, per side, so tests can assert on the exact event stream.
class ScriptableConsumer : public Continuation
{
public:
  explicit ScriptableConsumer(Ptr<ProxyMutex> m);
  ~ScriptableConsumer() override;

  int handle(int event, void *data);

  std::vector<int> read_signals;
  std::vector<int> write_signals;
  bool             got_open = false;
  bool             h2_mode  = false;

  MIOBuffer      *read_buf    = nullptr;
  IOBufferReader *read_reader = nullptr;
};

// Assembles the whole reducer scenario: the SUT (SSLNetVConnection), its mock transport, a real
// TLS peer, and the scriptable consumer, and drives ciphertext between them deterministically.
class ReducerFixture
{
public:
  explicit ReducerFixture(bool inbound);
  ~ReducerFixture();

  SSLNetVConnection *
  vc() const
  {
    return _vc;
  }
  MockTransportVC *
  mock() const
  {
    return _mock;
  }
  ScriptableConsumer *
  consumer() const
  {
    return _consumer;
  }
  BarePeer *
  peer() const
  {
    return _peer;
  }

  void attach(bool install_read = true);
  void attach_cancelled();
  void drive_handshake();
  void pump_sut_to_peer();
  void pump_peer_to_sut(bool corrupt = false);
  void inject(int event, bool write_side);
  void wake_sut(bool write_side);
  void resume_hook(bool error);

private:
  bool                _inbound;
  Ptr<ProxyMutex>     _mutex;
  SSLNetVConnection  *_vc       = nullptr;
  MockTransportVC    *_mock     = nullptr;
  ScriptableConsumer *_consumer = nullptr;
  BarePeer           *_peer     = nullptr;
  std::string         _cert, _key;
  int                 _sock_fd = NO_FD;
};
