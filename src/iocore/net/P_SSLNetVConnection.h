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

  SSLNetVConnection.h

  This file implements an I/O Processor for network I/O.


 ****************************************************************************/
#pragma once

#include "iocore/eventsystem/Continuation.h"
#include "iocore/eventsystem/IOBuffer.h"
#include "iocore/net/AsyncSignalEventIO.h"
#include "iocore/net/AsyncTLSEventIO.h"
#include "ts/apidefs.h"

#include "P_UnixNetVConnection.h"
#include "iocore/net/TLSALPNSupport.h"
#include "iocore/net/TLSSessionResumptionSupport.h"
#include "iocore/net/TLSSNISupport.h"
#include "iocore/net/TLSEarlyDataSupport.h"
#include "iocore/net/TLSTunnelSupport.h"
#include "iocore/net/TLSBasicSupport.h"
#include "iocore/net/TLSEventSupport.h"
#include "iocore/net/TLSCertSwitchSupport.h"
#include "P_SSLUtils.h"

#include <netinet/in.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/objects.h>

#include <cstring>
#include <memory>
#include <optional>
#include <string_view>

// These are included here because older OpenSSL libraries don't have them.
// Don't copy these defines, or use their values directly, they are merely
// here to avoid compiler errors.
#ifndef SSL_TLSEXT_ERR_OK
#define SSL_TLSEXT_ERR_OK 0
#endif

#ifndef SSL_TLSEXT_ERR_NOACK
#define SSL_TLSEXT_ERR_NOACK 3
#endif

constexpr char SSL_OP_HANDSHAKE = 0x16;

// TS-2503: dynamic TLS record sizing
// For smaller records, we should also reserve space for various TCP options
// (timestamps, SACKs.. up to 40 bytes [1]), and account for TLS record overhead
// (another 20-60 bytes on average, depending on the negotiated ciphersuite [2]).
// All in all: 1500 - 40 (IP) - 20 (TCP) - 40 (TCP options) - TLS overhead (60-100)
// For larger records, the size is determined by TLS protocol record size
constexpr uint32_t SSL_DEF_TLS_RECORD_SIZE           = 1300; // 1500 - 40 (IP) - 20 (TCP) - 40 (TCP options) - TLS overhead (60-100)
constexpr uint32_t SSL_MAX_TLS_RECORD_SIZE           = 16383; // 2^14 - 1
constexpr int64_t  SSL_DEF_TLS_RECORD_BYTE_THRESHOLD = 1000000;
constexpr int      SSL_DEF_TLS_RECORD_MSEC_THRESHOLD = 1000;

struct SSLCertLookup;
class Event;

enum class SslVConnOp {
  SSL_HOOK_OP_DEFAULT, ///< Null / initialization value. Do normal processing.
  SSL_HOOK_OP_TUNNEL   ///< Switch to blind tunnel
};

//////////////////////////////////////////////////////////////////
//
//  class NetVConnection
//
//  A VConnection for a network socket.
//
//////////////////////////////////////////////////////////////////
class SSLNetVConnection : public NetVConnection,
                          public ALPNSupport,
                          public TLSSessionResumptionSupport,
                          public TLSSNISupport,
                          public TLSEarlyDataSupport,
                          public TLSTunnelSupport,
                          public TLSCertSwitchSupport,
                          public TLSEventSupport,
                          public TLSBasicSupport
#if TS_USE_TLS_ASYNC
  ,
                          public AsyncTLSEventCallback
#endif
{
private:
  // SSL state management
  enum class SslState {
    HANDSHAKING = 0,          // Handshake not yet complete: created, in ClientHello, or mid-handshake.
                              // The sub-stages carried no read-side distinction, so they are one state.
    HANDSHAKE_DONE       = 1, // Handshake complete, ready for application data
    SHUTDOWN_IN_PROGRESS = 2, // Graceful close: draining buffered ciphertext (+ close-notify) to
                              // the transport before teardown. do_io_close's lingering close.
    FATAL_PENDING = 3,        // Terminal, with an armed handshake reject (a hook's
                              // reenable_with_event(TS_EVENT_ERROR)) not yet delivered to the
                              // waiter. Delivery IS the transition to TERMINATED -- exactly once,
                              // structurally -- so a consumer that has not yet closed (H2 with
                              // active streams) is never re-signalled by a later event.
    TERMINATED = 4,           // Terminal: failure delivered, or none to deliver. No further SSL
                              // I/O; awaiting the consumer's do_io_close to authorize the free.
                              // The why (clean close vs error) lives in lerrno and the per-site
                              // Dbg output, not here.
    RECLAIMABLE = 5           // Terminal + the free is authorized (master's UnixNetVConnection
                              // `closed` latch): the consumer closed us (do_io_close), or a
                              // terminal event landed on a severed/absent consumer (the null-cont
                              // owner-close). The outer VC is not NetHandler-managed, so it frees
                              // itself the moment _free_blocked() clears. See _reclaim_if_closed.
  };
  // Transition table: every transition of _sslState, grouped by destination; sites are named by
  // function. Each group is implemented by exactly one named mutator (defined below the enum),
  // so the table is checkable against six small bodies instead of every assignment in the class.
  // "Guarded" marks a mutator whose condition is the FROM set; for an unconditional mutator,
  // FROM is the state reachable at its call sites. Start state: HANDSHAKING at construction; the
  // destructor also resets to it directly, from whatever state the VC was freed in, for
  // allocator reuse. Terminal region (_is_terminal, below): FATAL_PENDING, TERMINATED,
  // RECLAIMABLE.
  //
  //   HANDSHAKING -> HANDSHAKE_DONE  -- _complete_handshake_if_active()
  //     - Handshake completion on SSL_ERROR_NONE: _complete_server_handshake /
  //       _complete_client_handshake. Guarded (== HANDSHAKING): a state moved past HANDSHAKING
  //       mid-flight -- a hook's reject or a close during SSL_accept/SSL_connect -- outranks
  //       completion, so the store is skipped.
  //     - Blind-tunnel marks on a transparent connection: _setup_server_ssl (per-IP OPT_TUNNEL,
  //       first server round) and _lookupContextByName (per-SNI OPT_TUNNEL; guarded
  //       (== HANDSHAKING) so an armed FATAL_PENDING from an earlier hook in the same flight
  //       outranks the tunnel).
  //     - The DOWNGRADE_PLAIN executor (_propagate_handshake_buffer), just before this VC hands its
  //       buffers to the plain successor and frees itself.
  //   HANDSHAKING -> FATAL_PENDING  -- _arm_fatal_failure()
  //     - The state's only entry: a non-verify handshake hook's reenable_with_event(
  //       TS_EVENT_ERROR). Guarded (not terminal, not draining): a close that already happened
  //       outranks the reject. (The guard would also admit HANDSHAKE_DONE, but a handshake hook
  //       only reenables while the handshake is parked on it.)
  //   HANDSHAKING -> TERMINATED  -- _fail_handshake()
  //     - The write-face EVENT_ERROR arm of _drive_handshake, stored before the failure is
  //       signalled, so it also consumes an armed FATAL_PENDING. It never sees an in-hook
  //       close's state: the drive yields to an authorized reclaim (RECLAIMABLE) before the
  //       post-round arms that signal or re-arm, and the arm yields to an armed close-drain (_is_draining())
  //       before either face's store or signal -- in both cases the close severed the user
  //       VIOs, so the failure has no waiter, and the drain flavor must flush the fatal alert
  //       the failing round staged in _write_buf. (The read-face EVENT_ERROR arm leaves the
  //       state in place; the consumer's close or the owner-close below moves it.)
  //   FATAL_PENDING -> TERMINATED  -- _consume_fatal_failure(): delivery IS this transition, exactly once
  //     - On the driver stack once _advance_handshake has returned (outside any OpenSSL frame):
  //       _drive_handshake's post-return terminal check (either face) and its read-face
  //       EVENT_ERROR arm (the write face's EVENT_ERROR is the unconditional store above).
  //     - Off-stack, when the hook's reenable was asynchronous: _run_deferred_work's FATAL_PENDING
  //       rung, or mainEvent's terminal-state transport-event gate (a transport event raced
  //       ahead of that dispatch).
  //   {HANDSHAKING, HANDSHAKE_DONE, FATAL_PENDING, TERMINATED} -> SHUTDOWN_IN_PROGRESS  -- _begin_graceful_shutdown()
  //     - do_io_close's DRAIN plan (_apply_close_plan; selected on a graceful CloseIntent, transport
  //       wired and not in error). A close of an already-failed VC re-enters the drain from inside the
  //       terminal region (_is_terminal() goes back to false), and it erases an undelivered
  //       FATAL_PENDING: there is no consumer left to deliver to. The drain still gates all I/O
  //       (_is_draining) and every exit from it is RECLAIMABLE.
  //   {HANDSHAKING, HANDSHAKE_DONE, FATAL_PENDING, TERMINATED} -> RECLAIMABLE  -- _authorize_reclaim()
  //     - do_io_close's RECLAIM_NOW/DEFER plans (_apply_close_plan): the drain is not warranted --
  //       an abortive CloseIntent, or the transport is absent/broken. (Both do_io_close
  //       transitions are unconditional; a second close of the same VC is not a designed path.)
  //   {HANDSHAKING, HANDSHAKE_DONE, TERMINATED, SHUTDOWN_IN_PROGRESS, RECLAIMABLE} -> RECLAIMABLE  -- _authorize_reclaim()
  //     - The null-cont owner-close (_signal_user): a terminal event (EOS/ERROR/timeout) with no
  //       live consumer to deliver it to, so nobody will ever close us. The transition is
  //       unconditional -- FROM is whatever state the event was delivered in (a RECLAIMABLE
  //       self-loop stays legal, though the handshake drive no longer signals there: it yields
  //       to an authorized reclaim before the post-round arms that signal or re-arm).
  //       SHUTDOWN_IN_PROGRESS is reached when a hook nested in a handshake drive closes the VC
  //       (legal on a plugin-owned outbound VC, e.g. TSVConnClose from a verify hook) and the
  //       unwinding round then abandons the WANT_READ wait: the transport read already ended
  //       (the handshake bytes can never arrive) or the handshake timeout has expired. The
  //       failure signal finds no cont and forgoes the flush -- a fourth drain exit. (A
  //       handshake ERROR on such a round does not exit here: the EVENT_ERROR arm's
  //       _is_draining() early-exit yields to the drain, which flushes the fatal alert the
  //       failing round staged in _write_buf.)
  //   SHUTDOWN_IN_PROGRESS -> RECLAIMABLE  -- _authorize_reclaim(); each site frees the VC right after it
  //     - Drain complete (_run_deferred_work); transport error mid-drain
  //       (_handle_transport_error); a drain stuck at an idle/active timeout (mainEvent). Each is
  //       held off while _free_blocked(), then completed by a later dispatch or the parked hook's
  //       reenable. (A drain armed by an in-hook close can instead exit through the owner-close
  //       above, on the unwinding drive's stack.)
  //
  // RECLAIMABLE is absorbing: no mutator leaves it -- the handshake drive yields to it before
  // the one store that historically overwrote it (_fail_handshake, which now asserts) -- and
  // every dispatch that sees it only reaps. The VC frees itself (running the destructor's reuse reset)
  // once _free_blocked() clears. Nothing enters TERMINATED after the handshake: a data-phase
  // failure is signalled to the consumer, and the state then moves only at its do_io_close or
  // the owner-close.
  enum SslState _sslState = SslState::HANDSHAKING;
  // The terminal region: no further SSL I/O of any kind. A terminal state gates I/O; only
  // RECLAIMABLE authorizes the free (consumer-driven teardown). SHUTDOWN_IN_PROGRESS is not
  // terminal (the drain is still flushing ciphertext) but is entered only from do_io_close,
  // so it too carries the close authorization.
  static bool
  _is_terminal(SslState state)
  {
    return state == SslState::FATAL_PENDING || state == SslState::TERMINATED || state == SslState::RECLAIMABLE;
  }

  // The named SslState mutators. Every transition of _sslState routes through exactly one of
  // these (the destructor's allocator-reuse reset aside), so the transition table above is
  // verifiable against these bodies rather than against every assignment in the class.

  // Handshake completion, and the marks that stand in for it (the blind-tunnel marks and
  // the downgrade executor): HANDSHAKING -> HANDSHAKE_DONE, guarded.
  // Completion must not exit the terminal region or the close-drain: an in-flight close
  // (RECLAIMABLE / SHUTDOWN_IN_PROGRESS -- e.g. a TSVConnClose from a verify hook on a
  // plugin-owned outbound VC) or an armed reject (FATAL_PENDING) outranks it, so the store is
  // skipped -- the separate booleans this enum absorbed used to survive completion. Callers
  // reachable only from HANDSHAKING share the guard vacuously.
  void
  _complete_handshake_if_active()
  {
    if (_sslState == SslState::HANDSHAKING) {
      _sslState = SslState::HANDSHAKE_DONE;
    }
  }

  // Arm the handshake reject (a non-verify handshake hook's reenable_with_event(TS_EVENT_ERROR)):
  // HANDSHAKING -> FATAL_PENDING, guarded. A close that already happened outranks the reject (a
  // late reject from a parked hook's queue, e.g. rate_limit, after the waiter closed): arming
  // would erase the close authorization, and there is no consumer left to deliver to.
  void
  _arm_fatal_failure()
  {
    if (!_is_terminal(_sslState) && !_is_draining()) {
      _sslState = SslState::FATAL_PENDING;
    }
  }

  // Consume the armed handshake reject: FATAL_PENDING -> TERMINATED. Delivering the reject to
  // the waiter IS this transition, and this is its only implementation, so delivery happens
  // exactly once by structure -- a later delivery site finds TERMINATED and nothing to consume.
  // Returns whether this call consumed the reject; every site that signals the waiter calls
  // this first, on the same stack as its _signal_and_reclaim.
  bool
  _consume_fatal_failure()
  {
    if (_sslState == SslState::FATAL_PENDING) {
      _sslState = SslState::TERMINATED;
      return true;
    }
    return false;
  }

  // The write-face handshake driver's EVENT_ERROR: entry to TERMINATED, made before the
  // failure is signalled, so it also consumes an armed FATAL_PENDING. Never called once the
  // consumer has closed us: the drive yields to an authorized reclaim (RECLAIMABLE) before
  // the post-round arms that signal or re-arm, and the EVENT_ERROR arm yields to an armed close-drain before
  // either face's store, preserving SHUTDOWN_IN_PROGRESS for the drain's alert flush. The
  // assert keeps RECLAIMABLE absorbing.
  void
  _fail_handshake()
  {
    ink_assert(!_is_draining() && _sslState != SslState::RECLAIMABLE);
    _sslState = SslState::TERMINATED;
  }

  // do_io_close arming the graceful close-drain (_apply_close_plan's DRAIN arm): ->
  // SHUTDOWN_IN_PROGRESS (== draining, see _is_draining). Legal from anywhere except the drain
  // itself and RECLAIMABLE (a second close of the same VC is not a designed path); entering
  // from FATAL_PENDING/TERMINATED is normal -- the close of an already-failed VC erases an
  // undelivered reject, since no consumer is left to deliver it to.
  void
  _begin_graceful_shutdown()
  {
    ink_assert(!_is_draining() && _sslState != SslState::RECLAIMABLE);
    _sslState = SslState::SHUTDOWN_IN_PROGRESS;
  }

  // Authorize the free: -> RECLAIMABLE (master's `closed` latch). Every source state is legal,
  // so there is no source assert: do_io_close/abort can arrive in any phase, the drain exits
  // enter from SHUTDOWN_IN_PROGRESS, and the null-cont owner-close may legally self-loop from
  // RECLAIMABLE (no remaining site is known to signal there: the drive yields to an authorized
  // reclaim, and mainEvent's terminal gate reaps without signalling). The physical free still
  // gates on _free_blocked() (see _reclaim_if_closed).
  void
  _authorize_reclaim()
  {
    _sslState = SslState::RECLAIMABLE;
  }
  // A handshake hook has parked (the driver returned SSL_WAIT_FOR_HOOK): a plugin owns a live
  // reference and will reenable_with_event into this VC. Set at the park, cleared when the plugin
  // reenables. It is a stable latch because do_io_close's close hook (_run_tls_close_hooks's
  // callHooks(VCONN_CLOSE)) advances the hook FSM to HANDSHAKE_HOOKS_DONE, so is_invoked_state()
  // can no longer witness the outstanding hold;
  // _reclaim_if_closed holds off on this so a consumer-driven close arriving while the hook is parked
  // (a transport error/timeout) cannot free the VC out from under the plugin's pending reenable. A
  // synchronous TSVConnAbort fails the handshake instead of parking, so it never sets this.
  bool _hook_parked = false;
  // do_io_close is running the VC's own TLS close hook (_run_tls_close_hooks). A plugin that
  // closes or aborts this same VC from within that hook would re-enter do_io_close and free the
  // VC under the outer close's frames -- and the close hook has already advanced the hook FSM to
  // HANDSHAKE_HOOKS_DONE, so is_invoked_state()/_hook_parked no longer witness the frames below.
  // Closing from a close hook is incoherent (the hook is the teardown notification, not a
  // disposition point like the handshake hooks), so do_io_close release-asserts on re-entry
  // rather than trying to make the reentrant free safe. Nothing internal closes from a close
  // hook, so the assert has no legitimate caller to exempt.
  bool _in_tls_close_hooks = false;
  // A verify hook (SSL_VERIFY_SERVER/CLIENT) is running. Such a hook reenabling with TS_EVENT_ERROR
  // is reporting a certificate verdict, NOT terminating the handshake: whether a failed check stops
  // the handshake is the verify policy's call, applied by the OpenSSL verify callback's return
  // (SSLClientUtils: !enforce_mode) -- ENFORCED fails via SSL_ERROR_SSL, PERMISSIVE continues. While
  // a hook is RUNNING, reenable_with_event records a TS_EVENT_ERROR as the verdict (-> RUNNING_REJECTED)
  // instead of latching the terminal FATAL_PENDING state, so a PERMISSIVE override still completes the
  // handshake. One three-state value (driven by VerifyHookScope) replaces the old bool pair, whose
  // (not-running, failed) combination was representable but meaningless.
  enum class VerifyHookState { INACTIVE, RUNNING, RUNNING_REJECTED };
  VerifyHookState _verify_hook_state = VerifyHookState::INACTIVE;
  // In the graceful close-drain (do_io_close's lingering close): user VIOs are severed and the
  // transport is flushing the final ciphertext before teardown. SHUTDOWN_IN_PROGRESS is reached
  // from exactly one site (do_io_close) and the VC is freed the instant it leaves the state, so
  // this is the sole meaning of "draining".
  bool
  _is_draining() const
  {
    return _sslState == SslState::SHUTDOWN_IN_PROGRESS;
  }

  // True while a stack frame or a plugin still needs this VC alive, so it must NOT be freed:
  // nested in our own notify or an OpenSSL callback frame (recursion), a handshake hook mid
  // invocation (is_invoked_state), or a hook parked with a live plugin ref that will reenable
  // (_hook_parked). Every VC free site -- _reclaim_if_closed, do_io_close's inline free, and the
  // graceful-drain frees -- gates on this so a close arriving mid-hook cannot pull the VC out
  // from under the plugin's pending reenable. (Orthogonal to _is_draining, which is a separate
  // "the drain owns the free" gate: the drain frees while this predicate holds off.)
  bool
  _free_blocked() const
  {
    return recursion != 0 || is_invoked_state() || _hook_parked;
  }

  // A deferred handshake-time handoff that frees this VC and hands its transport elsewhere. Both
  // arms are decided mid-handshake and executed out of line on a clean _run_deferred_work dispatch
  // (they cannot free this VC inline while a transport read handler still inspects it). Kept as its own
  // small axis rather than folded into SslState: the blind-tunnel arm can be armed while the SSL
  // state is still HANDSHAKE_DONE (the OPT_TUNNEL path), so it must not overwrite that value.
  enum class PendingHandoff {
    NONE,            // no deferred handoff armed
    BLIND_TUNNEL,    // hand the transport to a dedicated pass-through VC (SNI blind-tunnel route)
    DOWNGRADE_PLAIN, // convert to a plain UnixNetVConnection (leading bytes are not a ClientHello)
  };
  PendingHandoff _pending_handoff = PendingHandoff::NONE;

  void _track_first_handshake();

public:
  void free_thread(EThread *t);
  UnixNetVConnection *
  getUnixNetVC() const
  {
    return _unvc;
  }

  bool
  getSSLHandShakeComplete() const
  {
    return _sslState == SslState::HANDSHAKE_DONE;
  }

  // True only while the handshake is actually in progress -- false once the VC is
  // established, draining, or terminated, so a stale close of a post-handshake VC
  // does not read as mid-handshake.
  bool
  getSSLHandShakeInProgress() const
  {
    return _sslState == SslState::HANDSHAKING;
  }

  // True while do_io_close is running this VC's own TLS close hook: a plugin re-entering
  // do_io_close from that hook is the incoherent close the constructor's reject catches.
  bool
  in_tls_close_hooks() const
  {
    return _in_tls_close_hooks;
  }

  int sslServerHandShakeEvent(int &err);
  int sslClientHandShakeEvent(int &err);

  // NetVConnection
  VIO          *do_io_read(Continuation *c, int64_t nbytes, MIOBuffer *buf) override;
  VIO          *do_io_write(Continuation *c, int64_t nbytes, IOBufferReader *reader, bool owner) override;
  void          do_io_close(int lerrno = -1) override;
  void          do_io_shutdown(ShutdownHowTo_t howto) override;
  bool          get_data(int id, void *data) override;
  void          set_active_timeout(ink_hrtime timeout_in) override;
  void          set_inactivity_timeout(ink_hrtime timeout_in) override;
  void          set_default_inactivity_timeout(ink_hrtime timeout_in) override;
  bool          is_default_inactivity_timeout() override;
  void          cancel_active_timeout() override;
  void          cancel_inactivity_timeout() override;
  void          set_open_continuation(Continuation *c) override;
  Continuation *get_open_continuation() const override;
  // Arm the cancellable handle an outbound consumer holds and return it; see _connect_action.
  Action *
  arm_connect_action(Continuation *c)
  {
    _connect_action = c;
    return &_connect_action;
  }
  void       add_to_keep_alive_queue() override;
  void       remove_from_keep_alive_queue() override;
  bool       add_to_active_queue() override;
  ink_hrtime get_active_timeout() override;
  ink_hrtime get_inactivity_timeout() override;
  void       apply_options() override;
  void       reenable(VIO *vio) override;
  void       reenable_re(VIO *vio) override;
  SOCKET     get_socket() override;
  int        set_tcp_congestion_control(tcp_congestion_control_side side) override;
  void       set_local_addr() override;
  void       set_remote_addr() override;
  void       set_remote_addr(const sockaddr *addr) override;
  void       set_mptcp_state() override;

#if TS_USE_TLS_ASYNC
  // AsyncTLSEventCallback
  void handle_async_tls_ready() override;
#endif

  ////////////////////////////////////////////////////////////
  // Instances of NetVConnection should be allocated        //
  // only from the free list using NetVConnection::alloc(). //
  // The constructor is public just to avoid compile errors.//
  ////////////////////////////////////////////////////////////
  SSLNetVConnection();
  // Test-injection constructor: _unvc is private and unit tests (test_HttpUserAgent)
  // need to attach a mock inner transport at construction.
  explicit SSLNetVConnection(UnixNetVConnection *unvc);
  ~SSLNetVConnection() override;

  bool
  getSSLClientRenegotiationAbort() const
  {
    return sslClientRenegotiationAbort;
  }

  void
  setSSLClientRenegotiationAbort(bool state)
  {
    sslClientRenegotiationAbort = state;
  }

  bool
  getTransparentPassThrough() const
  {
    return transparentPassThrough;
  }

  void
  setTransparentPassThrough(bool val)
  {
    transparentPassThrough = val;
  }

  bool
  getAllowPlain() const
  {
    return allowPlain;
  }

  void
  setAllowPlain(bool val)
  {
    allowPlain = val;
  }

  /** Park a second reader on _read_buf to retain the raw handshake bytes.
   *
   * The inner transport fills @a _read_buf and the SSL rbio consumes it through
   * its own advancing reader. @a handShakeHolder is a second reader parked at
   * byte 0 so the raw CLIENT_HELLO can be replayed to the origin if the
   * connection becomes a blind tunnel, or handed to the read VIO on an
   * allow-plain downgrade. While it exists it pins every byte of @a _read_buf,
   * so it must be released as soon as the connection commits to TLS
   * termination (see _commit_inbound_handshake).
   */
  void
  initialize_handshake_buffers()
  {
    this->handShakeHolder = this->_read_buf->alloc_reader();
  }

  void
  free_handshake_buffers()
  {
    if (this->handShakeHolder) {
      this->handShakeHolder->dealloc();
    }
  }

  int         populate_protocol(std::string_view *results, int n) const override;
  const char *protocol_contains(std::string_view tag) const override;

  ink_hrtime sslLastWriteTime  = 0;
  int64_t    sslTotalBytesSent = 0;

  std::shared_ptr<SSL_SESSION> client_sess = nullptr;

  /// Set by asynchronous hooks to request a specific operation.
  SslVConnOp hookOpRequested = SslVConnOp::SSL_HOOK_OP_DEFAULT;

  // noncopyable
  SSLNetVConnection(const SSLNetVConnection &)            = delete;
  SSLNetVConnection &operator=(const SSLNetVConnection &) = delete;

  NetVConnection *migrateToCurrentThread(Continuation *cont, EThread *t) override;

  bool
  peer_provided_cert() const override
  {
#ifdef OPENSSL_IS_OPENSSL3
    X509 *cert = SSL_get1_peer_certificate(this->_ssl.get());
#else
    X509 *cert = SSL_get_peer_certificate(this->_ssl.get());
#endif
    if (cert != nullptr) {
      X509_free(cert);
      return true;
    } else {
      return false;
    }
  }

  int
  provided_cert() const override
  {
    if (this->get_context() == NET_VCONNECTION_OUT) {
      return this->sent_cert;
    } else {
      return 1;
    }
  }

  void
  set_sent_cert(int send_the_cert)
  {
    sent_cert = send_the_cert;
  }

  void set_ca_cert_file(std::string_view file, std::string_view dir);

  const char *
  get_ca_cert_file()
  {
    return _ca_cert_file.get();
  }
  const char *
  get_ca_cert_dir()
  {
    return _ca_cert_dir.get();
  }

  // TLSEventSupport
  /// Reenable the VC after a pre-accept or SNI hook is called.
  void            reenable_with_event(int event = TS_EVENT_CONTINUE) override;
  Continuation   *getContinuationForTLSEvents() override;
  EThread        *getThreadForTLSEvents() override;
  Ptr<ProxyMutex> getMutexForTLSEvents() override;

protected:
  // TLSBasicSupport
  SSL *
  _get_ssl_object() const override
  {
    return this->_ssl.get();
  }
  ssl_curve_id     _get_tls_curve() const override;
  std::string_view _get_tls_group() const override;
  int              _verify_certificate(X509_STORE_CTX *ctx) override;

  // TLSSessionResumptionSupport
  const IpEndpoint &
  _getLocalEndpoint() override
  {
    return local_addr;
  }

  // TLSSNISupport
  in_port_t _get_local_port() override;

  bool           _isTryingRenegotiation() const override;
  shared_SSL_CTX _lookupContextByName(const std::string &servername, SSLCertContextType ctxType) override;
  shared_SSL_CTX _lookupContextByIP() override;

  // TLSEventSupport
  bool
  _is_tunneling_requested() const override
  {
    return SslVConnOp::SSL_HOOK_OP_TUNNEL == hookOpRequested;
  }
  void
  _switch_to_tunneling_mode() override
  {
    this->attributes = HttpProxyPort::TRANSPORT_BLIND_TUNNEL;
  }

private:
  std::string_view map_tls_protocol_to_tag(const char *proto_string) const;
  void             increment_ssl_version_metric(int version) const;
  bool             sslClientRenegotiationAbort = false;
  bool             first_ssl_connect           = true;
  IOBufferReader  *handShakeHolder             = nullptr;

  bool transparentPassThrough = false;
  bool allowPlain             = false;

  int sent_cert = 0;

  // Null-terminated string, or nullptr if there is no SNI server name.
  std::unique_ptr<char[]> _ca_cert_file;
  std::unique_ptr<char[]> _ca_cert_dir;

  // Async TLS related
#if TS_USE_TLS_ASYNC
  AsyncTLSEventIO async_ep{*this};
#endif

  // early data related stuff
#if TS_HAS_TLS_EARLY_DATA
  bool            _early_data_finish = false;
  MIOBuffer      *_early_data_buf    = nullptr;
  IOBufferReader *_early_data_reader = nullptr;
#endif
  // Always-defined: _early_data_reader exists only under TS_HAS_TLS_EARLY_DATA, so the read-drive
  // gates that consult it must go through this to keep the feature-off build compiling.
  bool
  _early_data_pending() const
  {
#if TS_HAS_TLS_EARLY_DATA
    return _early_data_reader != nullptr && _early_data_reader->read_avail() > 0;
#else
    return false;
#endif
  }

  // True when SSL-side read work exists that no future transport signal will announce: bytes
  // staged in the rbio, plaintext buffered inside SSL, pending early data, a latched
  // close_notify, or a terminated transport (EOS/ERROR is persistent state). Any gate deciding
  // "wait for the transport" vs "re-drive out of line" must use this union -- per-site subsets
  // are how the read-side stalls happened.
  bool _ssl_read_pending() const;

  // The write dual of _ssl_read_pending(): the consumer has an attached, enabled write VIO with
  // bytes still to encrypt -- a write genuinely in flight. Gates the paths that act on the
  // consumer's write (the close-time final encrypt, write-error delivery, and the write-rearm).
  bool
  _user_write_active() const
  {
    return _user_write_vio.op == VIO::WRITE && !_user_write_vio.is_disabled() && _user_write_vio.ntodo() > 0;
  }

  // An out-of-line read drive would do useful work: SSL-side read work exists that no future
  // transport signal will announce (_ssl_read_pending) AND an enabled reader with bytes still
  // wanted is attached to receive it. Without the consumer half a drive would signal nobody;
  // without the work half the transport read announces any future work itself.
  bool
  _read_drive_warranted() const
  {
    return _user_read_vio.op == VIO::READ && !_user_read_vio.is_disabled() && _user_read_vio.ntodo() > 0 && _ssl_read_pending();
  }

  // Typed pump results: each face drive runs one pump batch and reads its outcome from one
  // struct, instead of an int return with correlated out-params.
  struct ReadBatch {
    int     event = 0; // SSL_READ_* classification of how the batch ended (never SSL_READ_ERROR_NONE)
    int64_t bytes = 0; // plaintext delivered to the user buffer; already counted into _user_read_vio.ndone
    int     error = 0; // errno at the failing SSL_read (SSL_READ_ERROR only; mapped to -ENET_SSL_FAILED when 0)
  };
  struct EncryptBatch {
    int64_t plaintext_consumed = 0; // plaintext consumed from the user buffer; the CALLER advances _user_write_vio.ndone
    int64_t error              = 0; // 0 = batch ok; -EAGAIN = SSL wants a transport read; other negative = fatal
    int     needs              = 0; // EVENTIO_* transport re-arms the batch requires
  };

  // The symmetric face drivers, called by the matching transport gates (_handle_transport_*_ready):
  // advance the handshake if still in it, else pump one batch and deliver its outcome. Either may
  // free `this` on any delivered signal -- the caller must touch nothing afterwards. The read
  // driver is also the deferred read-drive (_run_deferred_work's default rung); the write driver
  // never falls from a completed handshake into data delivery (post-handshake encryption starts
  // when the consumer's write VIO drives it).
  void _drive_ssl_read();
  int  _drive_ssl_write();

  EncryptBatch        _encrypt_data_for_transport(int64_t towrite, MIOBufferAccessor &buf);
  void                _make_ssl_connection(SSL_CTX *ctx);
  void                _bind_ssl_object();
  UnixNetVConnection *_downgrade_to_plain();
  void                _propagate_handshake_buffer(UnixNetVConnection *target, EThread *t);
  void                _handoff_blind_tunnel();
  void                _arm_pending_handoff(PendingHandoff which);
  void                _adopt_consumer_mutex(Continuation *c);

  ReadBatch   _decrypt_data_from_transport();
  ssl_error_t _ssl_read_buffer(void *buf, int64_t nbytes, int64_t &nread);
  ssl_error_t _ssl_write_buffer(const void *buf, int64_t nbytes, int64_t &nwritten);
  ssl_error_t _ssl_connect();
  ssl_error_t _ssl_accept();

  bool _is_tunnel_endpoint{false};
  void _in_context_tunnel();
  void _out_context_tunnel();

  // underlying TCP connection
  UnixNetVConnection *_unvc = nullptr;

  // We give these VIOs to our consumer
  VIO _user_read_vio;
  VIO _user_write_vio;

  // The transport protocol (usually TCP) gives these to us
  VIO *_transport_read_vio  = nullptr;
  VIO *_transport_write_vio = nullptr;

  // The transport composition seam: arm both transport VIOs on _unvc (definition above
  // startEvent) and close a transport fd-inline when its NetHandler lock is takable
  // (definition above the destructor).
  void        _wire_transport_vios();
  static void _close_transport(UnixNetVConnection *transport);

  enum class SignalSide { READ, WRITE };
  // Notification only: deliver `event` to the consumer's VIO on `side` (or, for a severed/
  // mismatched cont, run the null-cont owner-close arm, which moves a terminal event straight to
  // RECLAIMABLE). It NEVER frees `this`. Called only from _signal_and_reclaim, which fuses the
  // paired reclaim onto the same stack.
  void _signal_user(SignalSide side, int event);
  // The reclaim half of _signal_and_reclaim; called bare only on the no-notify teardown paths
  // (_run_deferred_work's RECLAIMABLE rung and mainEvent's terminal transport-event gate).
  // Frees `this` (returning true) iff the consumer requested the close (RECLAIMABLE) and no
  // frame that still needs `this` alive is on the stack: recursion == 0 (own notify reentrancy or
  // an OpenSSL callback frame), not mid graceful-drain (_is_draining -- the drain owns the free),
  // and no handshake hook parked (is_invoked_state -- a plugin holds a live ref and will
  // reenable). NEVER frees from a terminal _sslState alone: master frees on `closed`, not on the
  // SSL error state. The caller must touch nothing after this returns true.
  bool _reclaim_if_closed();
  enum class SignalOutcome { ALIVE, RECLAIMED };
  // The one way to notify the consumer: _signal_user fused with its paired _reclaim_if_closed.
  // See the contract at the definition; RECLAIMED means `this` was freed -- touch no member.
  [[nodiscard]] SignalOutcome _signal_and_reclaim(SignalSide side, int event);
  SignalSide                  _handshake_fail_side() const;
  // The completion mirror of _handshake_fail_side; empty when no completion waiter is attached.
  // See the definition for who listens on which side.
  std::optional<SignalSide> _handshake_done_side() const;
  // Deliver the user-facing WRITE_COMPLETE synchronously and, if that causes the consumer to
  // reentrantly queue a new write, self-schedule a clean-stack rearm (see the definition and
  // _write_rearm_pending).
  int  _deliver_write_complete();
  void _schedule_write_rearm();
  // The read-face delivery mirror of _deliver_write_complete: route the batch outcome to the
  // consumer. May free `this` (any delivered signal); call in tail position only.
  void _deliver_read_result(const ReadBatch &batch);
  // Gate WRITE_COMPLETE on _write_buf having drained to the transport; see the definition.
  int _complete_write_when_drained();
  // Re-arm the transport write iff ciphertext is staged; see the definition.
  void _flush_staged_ciphertext();

  // do_io_close's ordered close pipeline: encrypt the final plaintext, sever the user VIOs,
  // run the TLS close hooks, queue the close-notify (or arm a quiet shutdown), then take
  // exactly one of the three exits below. Selection (_select_close_plan, side-effect-free) is
  // split from application (_apply_close_plan) so which exit a close takes is checkable against
  // one body. Contracts at the definitions, above do_io_close.
  enum class ClosePlan {
    DRAIN,       // graceful: defer teardown until the transport has flushed the staged
                 // ciphertext (+ close-notify); every drain exit is RECLAIMABLE
    RECLAIM_NOW, // free the VC inline, on this stack
    DEFER,       // free authorized but not safe on this stack; completed at the blocking
                 // frame's unwind or _run_deferred_work's RECLAIMABLE rung
  };
  // How do_io_close was called, decoded once from the public int lerrno at the override boundary
  // (VConnection's -1 == graceful convention). The private close pipeline never needs the numeric
  // abort errno -- only this classification -- so it carries CloseIntent, not a raw sentinel.
  enum class CloseIntent { GRACEFUL, ABORTIVE };

  // A graceful close whose transport can still take the drain: the precondition shared by the
  // final-plaintext encrypt and the DRAIN close plan. Tying both to one predicate guarantees we
  // only pre-encrypt the consumer's last write when the close will in fact drain it. Re-evaluated
  // at each site (hooks / SSL_shutdown run between them), so it is a structural refinement, not a
  // cached promise that an earlier encrypt "will" drain.
  bool
  _graceful_drain_possible(CloseIntent intent) const
  {
    return intent == CloseIntent::GRACEFUL && _unvc != nullptr && _transport_write_vio != nullptr && _transport_write_usable();
  }
  void      _encrypt_final_plaintext(CloseIntent intent);
  void      _detach_consumer_vios();
  void      _run_tls_close_hooks();
  void      _queue_close_notify_or_quiet_shutdown();
  ClosePlan _select_close_plan(CloseIntent intent, EThread *t, bool free_blocked_at_entry) const;
  void      _apply_close_plan(ClosePlan plan, CloseIntent intent, EThread *t);

  // Re-entrancy depth covering two distinct hazards with the same fix: (1) _signal_user's own
  // synchronous re-entrancy (a consumer's handler drives more work on this same VC before
  // unwinding), and (2) synchronous re-entrancy into a foreign C callback frame -- OpenSSL
  // invoking one of our registered hooks (SNI/cert/client-hello/verify) mid SSL_accept()/
  // SSL_connect()/SSL_read()/SSL_write()/SSL_shutdown(), which may itself call back into us
  // (e.g. a plugin calling TSVConnAbort from a hook). Both cases make it unsafe to free `this`
  // or its owned _ssl inline: case (1) because an enclosing frame on our own stack still
  // expects `this` to be valid, case (2) because OpenSSL's own C code keeps running after the
  // callback returns and would touch a freed _ssl. do_io_close's inline-free decision and
  // _reclaim_if_closed (the reclaim half of every _signal_and_reclaim) both gate on recursion == 0
  // -- never on lerrno or on which specific call triggered the close. See RecursionGuard below;
  // wrap every OpenSSL entry point with one, scoped tightly to just that call.
  int recursion = 0;

  // RAII guard for `recursion` -- construct immediately before an OpenSSL call that may invoke
  // a registered ATS callback (SSL_accept/SSL_connect/SSL_do_handshake/SSL_read/SSL_write/
  // SSL_shutdown), scoped to end immediately after that call returns. Using RAII here (rather
  // than manual increment/decrement, as _signal_user still does for its own narrower,
  // single-exit-path case) avoids the classic bug of forgetting to decrement on one of several
  // early-return paths through the surrounding function.
  struct RecursionGuard {
    int &r;
    explicit RecursionGuard(int &r) : r(r) { ++r; }
    ~RecursionGuard() { --r; }
    RecursionGuard(const RecursionGuard &)            = delete;
    RecursionGuard &operator=(const RecursionGuard &) = delete;
  };

  // RAII guard for a bool flag that must track the dynamic scope of a call whose body other frames
  // read during the call (same rationale as RecursionGuard: no missed clear on an early return).
  // Asserts the flag is clear on entry, so an illegal nesting crashes rather than silently
  // corrupting the flag.
  struct ScopedFlag {
    bool &f;
    explicit ScopedFlag(bool &flag) : f(flag)
    {
      ink_assert(!f);
      f = true;
    }
    ~ScopedFlag() { f = false; }
    ScopedFlag(const ScopedFlag &)            = delete;
    ScopedFlag &operator=(const ScopedFlag &) = delete;
  };

  // RAII scope for a running verify hook: enters RUNNING (from INACTIVE only) and restores INACTIVE
  // on exit; rejected() reports whether a hook recorded a bad-certificate verdict while running.
  // Read rejected() before the scope ends.
  struct VerifyHookScope {
    VerifyHookState &s;
    explicit VerifyHookScope(VerifyHookState &state) : s(state)
    {
      ink_assert(s == VerifyHookState::INACTIVE);
      s = VerifyHookState::RUNNING;
    }
    ~VerifyHookScope() { s = VerifyHookState::INACTIVE; }
    bool
    rejected() const
    {
      return s == VerifyHookState::RUNNING_REJECTED;
    }
    VerifyHookScope(const VerifyHookScope &)            = delete;
    VerifyHookScope &operator=(const VerifyHookScope &) = delete;
  };

  std::unique_ptr<SSL, decltype(&SSL_free)>                              _ssl{nullptr, &SSL_free};
  std::unique_ptr<MIOBuffer, decltype(&free_MIOBuffer)>                  _read_buf;
  std::unique_ptr<MIOBuffer, decltype(&free_MIOBuffer)>                  _write_buf;
  std::unique_ptr<IOBufferReader, std::function<void(IOBufferReader *)>> _write_buf_reader;

public:
  void              mark_as_tunnel_endpoint() override;
  AllocationStorage allocation_storage{AllocationStorage::THREAD_LOCAL};

  // initial connect or accept event handler
  int startEvent(int event, void *data);
  // transport events handling function
  int mainEvent(int event, void *data);

private:
  // The connecting/connected progression carried no observable behavior (nothing ever read it),
  // so the transport axis holds only three states: live, or terminated by EOS/error. The
  // terminal status is orthogonal to _sslState -- after transport EOS the VC keeps delivering
  // ciphertext still buffered in the rbio while _sslState remains HANDSHAKE_DONE.
  enum class TransportState {
    TRANSPORT_LIVE, // Connecting or established -- not terminated
    READ_EOS,       // read side ended: peer FIN or normal close initiated; the write side may
                    // still be usable (see _transport_write_usable)
    TRANSPORT_ERROR // TCP connection encountered an error
  };
  TransportState _transport_state = TransportState::TRANSPORT_LIVE;
  // No more bytes will ever arrive from the peer (EOS or a broken transport) -- persistent
  // state, not an edge. NOT "the connection is dead": after a peer half-close (READ_EOS) the
  // write side stays open and we may still owe the response; write-path gates must use
  // _transport_write_usable() instead.
  bool
  _transport_read_ended() const
  {
    return _transport_state == TransportState::READ_EOS || _transport_state == TransportState::TRANSPORT_ERROR;
  }
  // The transport can still take our bytes: only a broken transport (TRANSPORT_ERROR) is
  // unwritable. A peer that half-closed (READ_EOS) still reads our response, and skipping the
  // write path on it would truncate the response and the close-notify.
  bool
  _transport_write_usable() const
  {
    return _transport_state != TransportState::TRANSPORT_ERROR;
  }
  // The pending self-targeted deferred-work event (schedule_imm), or nullptr when none is
  // outstanding -- we never queue more than one. This one slot multiplexes several purposes --
  // the rbio read-drive (do_io_read / _handle_transport_eos / _run_deferred_work), blind-tunnel handoff,
  // downgrade-to-plain, async-hook handshake resumption, and the write-rearm follow-up
  // (_schedule_write_rearm) -- all of them self-targeted (re-invoke this VC's own mainEvent, never
  // a consumer), so none carry the receiver-liveness risk deferred consumer-facing signals do.
  // See _run_deferred_work for the dispatch-time disambiguation among these purposes.
  // Held as a pointer (not a bool) so it can be cancelled if this VC is freed, its
  // mutex changes (_adopt_consumer_mutex), or it migrates threads before the event fires (otherwise
  // the stale event would run on freed memory, under the wrong lock, or on the wrong thread).
  Event *_deferred_work_event = nullptr;
  bool
  _deferred_work_pending() const
  {
    return _deferred_work_event != nullptr;
  }
  // The one arming point for _deferred_work_event; see the contract at the definition.
  void _schedule_deferred_work(EThread *t);
  // The dispatch for the slot (tier 2 of mainEvent's demux); precedence ladder at the definition.
  int _run_deferred_work();
  // Set when a consumer reentrantly queues a new write from its (synchronously-delivered)
  // WRITE_COMPLETE handler while we're nested inside the inner transport's net_write_io. That
  // reentrant reenable() is doomed on this stack -- net_write_io's own still-executing tail
  // finds _write_buf empty (demand-driven encryption hasn't run yet) and disables the write,
  // undoing it. This flag arms a self-targeted, clean-stack re-issue of that reenable() once
  // net_write_io's current pass has fully unwound. See _deliver_write_complete / _run_deferred_work.
  bool _write_rearm_pending = false;

  // Event handlers for transport (UnixNetVConnection)
  int _handle_transport_read_ready(VIO *vio);
  int _handle_transport_write_ready(VIO *vio);
  int _handle_transport_eos(VIO *vio);
  int _handle_transport_error(VIO *vio, int err);
  int _parse_proxy_protocol(IOBufferReader *reader);

  // Which transport face is driving a handshake round. Handshake records arrive as transport
  // READ events, but a fresh accept's socket is writable before its ClientHello is announced,
  // so any round -- including the first -- can also be driven from the transport write face.
  enum class TransportFace { READ, WRITE };
  enum class HandshakeDriveOutcome {
    DATA_READY, // handshake completed on this drive with decryptable input already buffered:
                // the read face continues into post-handshake data delivery (`this` is alive)
    YIELD,      // round over: waiting on peer bytes / a parked hook / async, a deferred
                // handoff was armed, or a failing round yielded to an armed close-drain
                // (the drain flushes the staged alert and owns the teardown)
    FAILED,     // a handshake failure was signalled to the waiter
  };
  // One-time SSL-object build + configuration, split out of the per-round _advance_handshake
  // and guarded there by _ssl == nullptr so re-driven rounds never rebuild a live handshake's
  // SSL object. Both return EVENT_CONT with a live _ssl on success, or EVENT_ERROR; the server
  // setup also returns EVENT_DONE when a transparent per-IP OPT_TUNNEL converts the connection
  // to a blind tunnel instead of building an SSL object.
  int _setup_server_ssl();
  int _setup_client_ssl();
  // One per-round handshake advance, dispatching to the role's driver (sslServerHandShakeEvent
  // / sslClientHandShakeEvent). The role is derived from the stored VC context -- set exactly
  // once at accept/connect wiring before any drive can run, asserted at the definition -- not
  // from a caller-passed direction.
  int _advance_handshake(int &err);
  // The one handshake driver, shared by both faces; contract at the definition. Only DATA_READY
  // permits touching `this` afterwards -- after YIELD or FAILED a delivered signal may already
  // have freed the VC.
  [[nodiscard]] HandshakeDriveOutcome _drive_handshake(TransportFace face);

  // The two role drivers (sslServerHandShakeEvent / sslClientHandShakeEvent) share one visible
  // phase skeleton: prepare (hook stepping + PROXY-protocol step), enter OpenSSL (_ssl_accept /
  // _ssl_connect), the inbound-only not-a-ClientHello fallback, then complete-or-classify. Only
  // genuinely role-free steps live in the shared helpers (_step_pre_handshake_hooks,
  // _finish_handshake_common); each phase body stays with its role. Contracts at the definitions.
  bool               _step_pre_handshake_hooks(TLSEventSupport::SSLHandshakeHookState pre_state);
  int                _prepare_server_handshake();
  int                _prepare_client_handshake();
  int                _strip_inbound_proxy_protocol();
  bool               _stage_outbound_proxy_protocol();
  std::optional<int> _fallback_to_plain_or_tunnel();
  // The negotiated-protocol query result (ALPN preferred over NPN); len == 0 when the peer
  // selected nothing.
  struct NegotiatedProtocol {
    const unsigned char *proto = nullptr;
    unsigned             len   = 0;
  };
  NegotiatedProtocol _finish_handshake_common();
  int                _complete_server_handshake();
  int                _complete_client_handshake();
  int                _classify_server_handshake_error(ssl_error_t ssl_error);
  int                _classify_client_handshake_error(ssl_error_t ssl_error, int &err);
#if TS_USE_TLS_ASYNC
  void _update_async_wait_state(ssl_error_t ssl_error);
#endif
#if TS_HAS_TLS_EARLY_DATA
  // _ssl_accept's early-data drain; see the definition.
  int _drain_early_data();
#endif

  // Release the handshake reader (handShakeHolder) once the handshake is established and no
  // blind tunnel will adopt it, so it stops pinning _read_buf. See the definition for why a
  // lingering second reader otherwise wedges the rbio and stalls large reads.
  void _release_handshake_reader();

  // Inbound-only: release handShakeHolder once the hook FSM has passed the client-hello stage,
  // mirroring master's update_rbio(!in_client_hello). Call ONLY from the read-face WANT_READ
  // arm of _drive_handshake (never the pre-handshake-call sites), where the round's SNI/cert
  // hooks have already run and any tunnel/downgrade is resolved. See the definition.
  void _commit_inbound_handshake();

  // The outbound consumer's handle on this VC's open (returned by SSLNetProcessor::connect_re).
  // Its continuation is the one to notify on open/open-failed (set_open_continuation delegates
  // here), and cancelling it targets THIS outer VC rather than the inner transport connect, so a
  // cancel cleans this VC up in startEvent instead of orphaning it -- or crashing the inner's
  // cancelled-before-connectUp teardown. Unused on the inbound (accept) path.
  Action _connect_action;
};

extern ClassAllocator<SSLNetVConnection, true> sslNetVCAllocator;
