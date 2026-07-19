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

#include <algorithm>

namespace
{
bool
signals_contain(const std::vector<int> &signals, int event)
{
  return std::find(signals.begin(), signals.end(), event) != signals.end();
}
} // namespace

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

TEST_CASE("cancel-before-open-failed skips the notify and reclaims the outer", "[SSLReducer]")
{
  ReducerFixture fx(/* inbound */ false);
  fx.attach_cancelled_open_failed();

  // The cancelled consumer must see neither callback; the VC frees itself on this path.
  CHECK_FALSE(fx.consumer()->got_open);
  CHECK_FALSE(fx.consumer()->got_open_failed);
  SUCCEED("cancelled open-failed neither notified nor crashed");
}

// #5: a handshake timeout must reach the side the consumer is waiting on. The inner transport
// always times out on its read VIO, but a direct-outbound waiter installs only a do_io_write, so
// routing by the transport face would drop it. Consumer-driven: the timeout reaches the write
// waiter, which closes the VC (like HttpSM), and the reclaim frees it -- close_errno() == -1
// witnesses that only the SUT destructor closed the inner.
TEST_CASE("#5: handshake timeout reaches the write-side waiter", "[SSLReducer]")
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
  fx.pump(); // complete the consumer-driven close-drain

  // Routed to the write waiter (not the absent read face); the consumer's close reclaimed the VC.
  CHECK_FALSE(fx.consumer()->write_signals.empty());
  CHECK(fx.mock()->close_errno() == -1);
}

// #8: a post-handshake TLS error to an H2 client session with active streams. Consumer-driven:
// the session receives VC_EVENT_ERROR and marks its close pending -- master defers
// _vc->do_io_close() to destroy() when the last stream releases -- so the outer VC stays ALIVE
// across the error (no orphan, no self-free, and no pooled-session UAF) and is reclaimed only when
// the session finally closes it. Pre-pivot the eager self-free/orphan (a5da2d0672 + the read-error
// inner close) made close_errno() 0.
TEST_CASE("#8: post-handshake error, H2 session closes and reclaims the VC", "[SSLReducer]")
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

  // The error reached the h2 consumer. With active streams it has NOT closed yet, so the VC is
  // still alive -- not orphaned, not self-freed.
  CHECK(signals_contain(fx.consumer()->read_signals, VC_EVENT_ERROR));
  CHECK_FALSE(fx.mock()->closed());

  // The last stream releases -> destroy() -> _vc->do_io_close(): now the outer is reclaimed and
  // only the SUT destructor closes the inner (default sentinel -1).
  {
    SCOPED_MUTEX_LOCK(lock, fx.vc()->mutex, this_ethread());
    fx.consumer()->release();
  }
  fx.pump();
  CHECK(fx.mock()->close_errno() == -1);
}

// The write face can be the FIRST driver of an in-progress handshake: a fresh accept's socket is
// writable before its bytes are delivered, so a transport WRITE_READY can reach the SUT while the
// ClientHello sits unannounced in the read buffer. Drive the whole inbound handshake through
// write-face wakes only (peer bytes are moved without read-face events) to pin the write-face
// driver's arms: it must consume the buffered ClientHello, emit the server flight, and on the
// completing round deliver the cross-side VC_EVENT_WRITE_COMPLETE through the read VIO (no user
// write VIO is attached, so its ntodo() is 0) exactly once.
TEST_CASE("write-face-first: WRITE_READY drives the in-progress inbound handshake", "[SSLReducer]")
{
  std::string cert, key;
  reducer_make_self_signed(cert, key);
  reducer_install_server_cert(cert, key, "/tmp/claude-1000/reducer-certs");

  ReducerFixture fx(/* inbound */ true);
  fx.attach();

  // Move peer ciphertext into the SUT's read buffer WITHOUT delivering a read-face event.
  auto move_peer_bytes_quietly = [&fx]() {
    char buf[16384];
    int  n;
    while ((n = BIO_read(fx.peer()->wbio(), buf, sizeof(buf))) > 0) {
      fx.mock()->sut_read_buf()->write(buf, n);
    }
  };

  fx.peer()->do_handshake(); // the client emits its ClientHello
  move_peer_bytes_quietly();
  REQUIRE(fx.mock()->sut_read_buf()->max_read_avail() > 0);

  // First drive is a write-face wake: it must advance the handshake off the buffered bytes.
  REQUIRE_FALSE(fx.vc()->getSSLHandShakeComplete());
  fx.wake_sut(/* write_side */ true);
  REQUIRE(fx.mock()->sut_write_reader()->read_avail() > 0); // the server flight was produced

  // Finish the handshake, still via write-face wakes only.
  for (int i = 0; i < 20 && !(fx.vc()->getSSLHandShakeComplete() && fx.peer()->handshake_done()); ++i) {
    fx.pump_sut_to_peer();
    fx.peer()->do_handshake();
    move_peer_bytes_quietly();
    fx.wake_sut(/* write_side */ true);
  }
  REQUIRE(fx.vc()->getSSLHandShakeComplete());
  REQUIRE(fx.peer()->handshake_done());

  CHECK(std::count(fx.consumer()->read_signals.begin(), fx.consumer()->read_signals.end(), VC_EVENT_WRITE_COMPLETE) == 1);
  CHECK(fx.consumer()->write_signals.empty());

  // The established VC still moves data through the normal read path.
  const char *msg = "ping";
  REQUIRE(fx.peer()->write_app(msg, 4) == 4);
  fx.pump_peer_to_sut();
  REQUIRE(fx.consumer()->read_reader->read_avail() >= 4);
  char got[8] = {0};
  fx.consumer()->read_reader->memcpy(got, 4);
  CHECK(std::string(got, 4) == "ping");
}

// async-hook: a transport error while a cert hook is parked mid-handshake must tear down cleanly.
// Consumer-driven: the error reaches the waiting (read) consumer, which closes the VC; the reclaim
// is held off while the hook is parked (is_invoked_state -- the plugin still owns a live ref) and
// completes when the plugin reenables (reenable_with_event sees the RECLAIMABLE state and schedules the
// teardown instead of driving I/O). Exactly one VC_EVENT_ERROR reaches the read side, never the
// write side, and close_errno() == -1 confirms the reclaim.
TEST_CASE("async-hook: transport error while a cert hook is parked tears down cleanly", "[SSLReducer]")
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

  // Transport error arrives while parked -> the read consumer is signalled and closes (do_io_close);
  // the reclaim waits on the parked hook. The hook then resumes; reenable_with_event completes the
  // teardown. Do not touch fx.vc() past pump(): the VC frees.
  fx.inject(VC_EVENT_ERROR, /* write_side */ false);
  fx.resume_hook(/* error */ false);
  fx.pump();

  // The failure reached the waiting (read) side exactly once, never the write side.
  REQUIRE(fx.consumer()->read_signals.size() == reads_before + 1);
  CHECK(fx.consumer()->read_signals.back() == VC_EVENT_ERROR);
  CHECK(fx.consumer()->write_signals.empty());

  // The VC is reclaimed, so only the destructor closes the inner (default sentinel -1).
  CHECK(fx.mock()->close_errno() == -1);
}

// in-hook close: a plugin may close an outbound VC it owns from a verify-server hook, which runs
// nested inside SSL_connect. The close arms the graceful close-drain (severed VIOs,
// SHUTDOWN_IN_PROGRESS); the hook's ERROR verdict under an ENFORCED policy then fails the same
// round's SSL_connect, which stages the fatal TLS alert (e.g. unknown_ca) in the layered wbio.
// The failing round's EVENT_ERROR arm must yield to the armed drain so the transport flushes
// that alert (peer sees a definite handshake-failure alert, then FIN -- master's wire behavior,
// and the refactor's own behavior on its normal failure path). It must not tear the VC down on
// the unwinding drive stack, which destroys the staged alert unflushed and leaves the peer with
// a bare FIN.
TEST_CASE("in-hook close during SSL_connect: the failing round yields to the close-drain", "[SSLReducer]")
{
  ReducerFixture fx(/* inbound */ false);
  reducer_install_closing_verify_hook();
  fx.attach();
  fx.vc()->options.verifyServerPolicy     = YamlSNIConfig::Policy::ENFORCED;
  fx.vc()->options.verifyServerProperties = YamlSNIConfig::Property::NONE;

  // Move peer ciphertext into the SUT's read buffer WITHOUT a read-face event, so a write-face
  // wake finds the server flight already buffered (the write-face-first interleaving above).
  auto move_peer_bytes_quietly = [&fx]() {
    char buf[16384];
    int  n;
    while ((n = BIO_read(fx.peer()->wbio(), buf, sizeof(buf))) > 0) {
      fx.mock()->sut_read_buf()->write(buf, n);
    }
  };

  fx.wake_sut(/* write_side */ true); // ClientHello into _write_buf
  fx.pump_sut_to_peer();
  fx.peer()->do_handshake(); // server flight (ServerHello..Certificate..) into the peer wbio
  move_peer_bytes_quietly();
  REQUIRE(fx.mock()->sut_read_buf()->max_read_avail() > 0);

  // WRITE-face drive: SSL_connect consumes the flight, the verify hook closes in-hook (drain
  // armed) and fails the verify, and the round unwinds into the EVENT_ERROR arm.
  const int reenables_before = fx.mock()->write_reenables();
  fx.wake_sut(/* write_side */ true);
  REQUIRE(reducer_closing_verify_hook_fired());

  // The drain owns teardown: the VC must still be alive past the failing round, with the fatal
  // alert staged for the transport to flush. Without the arm's drain-yield it tears down inline
  // instead -- the null-cont owner-close frees the VC on this very stack, the destructor closes
  // the mock, and the staged alert is destroyed unflushed -- so this REQUIRE is the regression
  // witness (and gates the reader access below, which would be a use-after-free once the VC has
  // been freed).
  REQUIRE_FALSE(fx.mock()->closed());
  CHECK(fx.mock()->sut_write_reader()->read_avail() > 0);
  // The yield alone is not enough: the close-time reenable ran before the alert existed, so the
  // arm itself must ask the transport to flush (_flush_staged_ciphertext). The staged bytes
  // above cannot witness that -- the mock moves nothing on reenable and pump() drains
  // unconditionally -- so the recorded reenable is the flush's only witness.
  CHECK(fx.mock()->write_reenables() > reenables_before);

  // The in-hook close severed the consumer: no signal may reach it.
  CHECK(fx.consumer()->read_signals.empty());
  CHECK(fx.consumer()->write_signals.empty());

  // The transport flush + deferred dispatch complete the drain; the reclaim comes from the SUT
  // destructor (default sentinel -1, the harness's reclaim oracle).
  fx.pump();
  CHECK(fx.mock()->closed());
  CHECK(fx.mock()->close_errno() == -1);
}

// in-hook abort: the abort flavor of the case above (TSVConnAbort instead of TSVConnClose). An
// abort arms no drain -- do_io_close(EIO) authorizes the reclaim (RECLAIMABLE) and, because the
// OpenSSL frame blocks the free, defers it to the scheduled dispatch. The failing round must
// yield to that authorized reclaim the same way it yields to an armed drain: signalling the
// failure would find the severed VIOs' null cont, and the owner-close would free the VC on this
// very drive stack, under the live inner-transport frames that dispatched it.
TEST_CASE("in-hook abort during SSL_connect: the failing round yields to the deferred reclaim", "[SSLReducer]")
{
  ReducerFixture fx(/* inbound */ false);
  reducer_install_closing_verify_hook(EIO); // abort, not close: no drain is armed
  fx.attach();
  fx.vc()->options.verifyServerPolicy     = YamlSNIConfig::Policy::ENFORCED;
  fx.vc()->options.verifyServerProperties = YamlSNIConfig::Property::NONE;

  auto move_peer_bytes_quietly = [&fx]() {
    char buf[16384];
    int  n;
    while ((n = BIO_read(fx.peer()->wbio(), buf, sizeof(buf))) > 0) {
      fx.mock()->sut_read_buf()->write(buf, n);
    }
  };

  fx.wake_sut(/* write_side */ true); // ClientHello into _write_buf
  fx.pump_sut_to_peer();
  fx.peer()->do_handshake(); // server flight into the peer wbio
  move_peer_bytes_quietly();
  REQUIRE(fx.mock()->sut_read_buf()->max_read_avail() > 0);

  // WRITE-face drive: SSL_connect consumes the flight, the verify hook aborts in-hook (reclaim
  // authorized, free deferred) and fails the verify, and the round unwinds.
  fx.wake_sut(/* write_side */ true);
  REQUIRE(reducer_closing_verify_hook_fired());

  // The deferred dispatch owns the free: the VC must still be alive past the failing round.
  // Without the drive's yield, the round signals the failure into the severed VIOs' null cont
  // and the owner-close frees the VC on this unwinding stack (the destructor closes the mock).
  REQUIRE_FALSE(fx.mock()->closed());

  // The in-hook abort severed the consumer: no signal may reach it.
  CHECK(fx.consumer()->read_signals.empty());
  CHECK(fx.consumer()->write_signals.empty());

  // The scheduled dispatch completes the reclaim on a clean stack; the SUT destructor closes the
  // inner (default sentinel -1, the harness's reclaim oracle).
  fx.pump();
  CHECK(fx.mock()->closed());
  CHECK(fx.mock()->close_errno() == -1);
}
