/** @file

  Catch based unit tests for SSLNetVConnection ("reducer")

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

#include "ssl_reducer_harness.h"

#include "../P_SSLConfig.h"
#include "iocore/eventsystem/EThread.h"

#include <catch2/catch_test_macros.hpp>

TEST_CASE("reducer harness premises hold", "[SSLReducer]")
{
  REQUIRE(this_ethread() != nullptr);

  SSLConfig::scoped_config params;
  REQUIRE(params->client_ctx != nullptr); // outbound handshakes need this; must be non-null by default
}

TEST_CASE("BarePeer pair completes a real handshake and exchanges a record", "[SSLReducer]")
{
  std::string cert, key;
  reducer_make_self_signed(cert, key);

  BarePeer server(true, cert, key);
  BarePeer client(false, cert, key);

  // Pump ciphertext between the two mem-BIO pairs until both finish.
  auto move = [](BarePeer &from, BarePeer &to) {
    char buf[16384];
    int  n;
    while ((n = BIO_read(from.wbio(), buf, sizeof(buf))) > 0) {
      BIO_write(to.rbio(), buf, n);
    }
  };
  for (int i = 0; i < 20 && !(server.handshake_done() && client.handshake_done()); ++i) {
    client.do_handshake();
    move(client, server);
    server.do_handshake();
    move(server, client);
  }
  REQUIRE(client.handshake_done());
  REQUIRE(server.handshake_done());

  const char *msg = "hello";
  REQUIRE(client.write_app(msg, 5) == 5);
  move(client, server);
  char got[16] = {0};
  REQUIRE(server.read_app(got, sizeof(got)) == 5);
  CHECK(std::string(got, 5) == "hello");
}

TEST_CASE("MockTransportVC attaches under an outbound SSLNetVConnection", "[SSLReducer]")
{
  SSLNetVConnection *vc = sslNetVCAllocator.alloc();
  Ptr<ProxyMutex>    mtx{new_ProxyMutex()};
  vc->mutex = mtx;
  vc->set_context(NET_VCONNECTION_OUT);

  auto *mock   = new MockTransportVC();
  mock->mutex  = mtx;
  mock->thread = this_ethread();

  {
    SCOPED_MUTEX_LOCK(lock, vc->mutex, this_ethread());
    vc->startEvent(NET_EVENT_OPEN, mock); // wires _unvc, creates transport VIOs, SET_HANDLER(mainEvent)
  }

  REQUIRE(vc->getUnixNetVC() == mock);
  // The SUT called do_io_read/do_io_write on the mock; the mock captured the SUT buffers.
  REQUIRE(mock->sut_read_buf() != nullptr);
  REQUIRE(mock->sut_write_reader() != nullptr);
  // The transport VIOs the SUT drives are the mock's own VIOs, wired back to the SUT.
  REQUIRE(mock->read_vio()->cont == vc);
  REQUIRE(mock->read_vio()->vc_server == mock);
  REQUIRE(mock->write_vio()->op == VIO::WRITE);
}

TEST_CASE("baseline: outbound SUT completes a real handshake and moves a record", "[SSLReducer]")
{
  ReducerFixture fx(/* inbound */ false);
  fx.attach();
  fx.drive_handshake();

  REQUIRE(fx.vc()->getSSLHandShakeComplete());
  REQUIRE(fx.peer()->handshake_done());

  // Peer -> SUT app record surfaces to the consumer as plaintext.
  const char *msg = "ping";
  REQUIRE(fx.peer()->write_app(msg, 4) == 4);
  fx.pump_peer_to_sut();
  REQUIRE(fx.consumer()->read_reader->read_avail() >= 4);
  char got[8] = {0};
  fx.consumer()->read_reader->memcpy(got, 4);
  CHECK(std::string(got, 4) == "ping");
}

TEST_CASE("#7: cancel-before-open reclaims the outer and closes the inner", "[SSLReducer]")
{
  ReducerFixture fx(/* inbound */ false);
  fx.attach_cancelled();

  // Cancelled branch must close the mock inner and must NOT notify the consumer of an open.
  CHECK(fx.mock()->closed());
  CHECK_FALSE(fx.consumer()->got_open);
  // Reaching here without an assert/abort is the #7 regression signal (pre-Phase-A this aborted).
  SUCCEED("cancel-before-open did not crash");
}

// FIX: Phase B step 8 (idempotent fail(side,err) delivering to the explicit waiter).
// Correct behavior: a handshake timeout reaches the side the consumer is waiting on.
// Current tree routes by transport face (read side), so the write waiter is never notified.
TEST_CASE("#5: handshake timeout reaches the write-side waiter", "[SSLReducer][!shouldfail]")
{
  ReducerFixture fx(/* inbound */ false);
  fx.attach(/* install_read */ false);

  // Mimic HttpSM's direct-outbound path: a write-only waiter (do_io_write, no read VIO).
  {
    SCOPED_MUTEX_LOCK(lock, fx.vc()->mutex, this_ethread());
    MIOBuffer      *ob = new_MIOBuffer(BUFFER_SIZE_INDEX_128);
    IOBufferReader *rd = ob->alloc_reader();
    fx.vc()->do_io_write(fx.consumer(), 1, rd, false);
  }

  fx.wake_sut(/* write_side */ true); // begin the handshake (ClientHello emitted), then stall

  // The inner transport delivers timeouts on the read VIO; inject that.
  fx.inject(VC_EVENT_ACTIVE_TIMEOUT, /* write_side */ false);

  // Correct: the write-side waiter is told. (Fails today: signal went to the absent read side.)
  CHECK_FALSE(fx.consumer()->write_signals.empty());
}
