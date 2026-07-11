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

TEST_CASE("baseline: inbound SUT completes a real handshake", "[SSLReducer]")
{
  std::string cert, key;
  reducer_make_self_signed(cert, key);
  reducer_install_server_cert(cert, key, "/tmp/claude-1000/reducer-certs");

  ReducerFixture fx(/* inbound */ true);
  fx.attach();
  fx.drive_handshake();

  REQUIRE(fx.vc()->getSSLHandShakeComplete());
  REQUIRE(fx.peer()->handshake_done());
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

// FIX: Phase B step 8 (fail(side,err) sets terminal state before notify so a self-freeing
// consumer leaves no orphan). In the real system this is a UAF (VC self-frees on the error
// unwind, then Http2ClientSession::destroy touches the freed _vc); the reducer surfaces the
// underlying VC defect through the inner's close errno, which encodes which path closed it.
TEST_CASE("#8: post-handshake error reclaims a self-freeing consumer's VC", "[SSLReducer][!shouldfail]")
{
  std::string cert, key;
  reducer_make_self_signed(cert, key);
  reducer_install_server_cert(cert, key, "/tmp/claude-1000/reducer-certs");

  ReducerFixture fx(/* inbound */ true);
  fx.consumer()->h2_mode = true;
  fx.attach();
  fx.drive_handshake();
  REQUIRE(fx.vc()->getSSLHandShakeComplete());

  // Peer sends a valid record; corrupt it on the wire so the SUT's SSL_read errors.
  const char *msg = "corruptme";
  fx.peer()->write_app(msg, 9);
  fx.pump_peer_to_sut(/* corrupt */ true);

  // The inner's close errno tells which path closed it. Correct (post-fix): fail() sets terminal
  // before notify, the self-freeing consumer returns EVENT_DONE, and only the SUT's destructor
  // closes the inner -- with the default sentinel -1 -> the outer was reclaimed. Today (orphan):
  // the read-error handler closes the inner explicitly with ssl_read_errno (0 for an SSL-layer
  // error, no syscall errno) while the outer leaks -> close_errno() == 0, so this assertion fails.
  CHECK(fx.mock()->close_errno() == -1);
}

// FIX: Phase B steps 7-9 (notification/reclamation split + fail(side,err) + typed PendingWork).
// A transport error arriving while a cert hook is parked mid-handshake must tear the connection
// down cleanly: deliver the failure once, to the waiting side, and then reclaim the VC. On the
// current tree the delivery is already correct -- exactly one VC_EVENT_ERROR reaches the inbound
// consumer's read side, and never the (absent) write side, so there is no stale or misdirected
// delivery. The defect is reclamation: the handshake-error path signals the consumer but, because
// the consumer does not close, never reaches terminal state, so the outer VC is orphaned (never
// returned to its allocator, and its inner transport is never closed). Resuming the hook afterward
// is benign here -- the VC stays parked and alive, so this ordering is UAF-free on the current tree.
// The orphan is observed via the reclamation oracle (mirrors #8): close_errno() == -1 means the SUT
// destructor closed the inner (outer reclaimed). Pre-fix the inner is never closed at all, so
// close_errno() stays at the mock's default 0 (closed() is likewise false) and this assertion fails
// -- reported green by [!shouldfail] until steps 7-9 land, when the VC self-frees on the error.
TEST_CASE("async-hook: transport error while a cert hook is parked tears down cleanly", "[SSLReducer][!shouldfail]")
{
  std::string cert, key;
  reducer_make_self_signed(cert, key);
  reducer_install_server_cert(cert, key, "/tmp/claude-1000/reducer-certs");
  reducer_install_parking_cert_hook();

  ReducerFixture fx(/* inbound */ true);
  fx.attach();

  // Drive the inbound handshake far enough to invoke and park the cert hook.
  for (int i = 0; i < 10 && !reducer_hook_fired(); ++i) {
    fx.wake_sut(false);
    fx.pump_sut_to_peer();
    fx.peer()->do_handshake();
    fx.pump_peer_to_sut();
  }
  REQUIRE(reducer_hook_fired());                     // the hook actually parked ...
  REQUIRE(reducer_hook_vc() == fx.vc());             // ... on this VC ...
  REQUIRE_FALSE(fx.vc()->getSSLHandShakeComplete()); // ... mid-handshake.

  const size_t reads_before = fx.consumer()->read_signals.size();

  // Transport error arrives while parked, then the hook resumes. Do not touch fx.vc() past this
  // point: post-fix the SUT self-frees on the error, so only fixture-owned observers are safe.
  fx.inject(VC_EVENT_ERROR, /* write_side */ false);
  fx.resume_hook(/* error */ false);

  // Right-reason: the failure reached the waiting (read) side exactly once, and never the write
  // side -- no stale or misdirected delivery. This holds pre- and post-fix.
  REQUIRE(fx.consumer()->read_signals.size() == reads_before + 1);
  CHECK(fx.consumer()->read_signals.back() == VC_EVENT_ERROR);
  CHECK(fx.consumer()->write_signals.empty());

  // Primary invariant (fails pre-fix): the VC is reclaimed, so only the destructor closes the inner
  // (default sentinel -1). Pre-fix it is orphaned -- the inner is never closed -- so this is 0.
  CHECK(fx.mock()->close_errno() == -1);
}
