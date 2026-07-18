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
  SSL_HOOK_OP_DEFAULT,  ///< Null / initialization value. Do normal processing.
  SSL_HOOK_OP_TUNNEL,   ///< Switch to blind tunnel
  SSL_HOOK_OP_TERMINATE ///< Termination connection / transaction.
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
    CLOSED = 3,               // Clean SSL shutdown complete (close_notify sent/received)
    ERROR  = 4                // An SSL error occurred (handshake, read/write, or shutdown)
  };
  enum SslState _sslState = SslState::HANDSHAKING;
  static bool
  isTerminated(SslState state)
  {
    return state == SslState::CLOSED || state == SslState::ERROR;
  }
  // Consumer-driven teardown latch (master's UnixNetVConnection `closed`). The outer VC is not
  // NetHandler-managed, so it must physically free itself -- but ONLY when its consumer has
  // requested the close (do_io_close), or when a terminal event lands on a severed/absent consumer
  // (the null-cont owner-close). A terminal _sslState gates I/O; it never authorizes the free. Set
  // once, never reset (the VC frees the moment the gate opens). See _reclaimIfClosed.
  bool _close_requested = false;
  // A terminal error was armed out of line (a handshake hook's reenable_with_event(TS_EVENT_ERROR),
  // e.g. an SNI/rate-limit reject) with no handshake driver on the stack to deliver it. The
  // scheduled mainEvent dispatch delivers VC_EVENT_ERROR to the waiter EXACTLY ONCE and clears
  // this; the consumer's do_io_close then drives the free. Separate from _close_requested so a
  // consumer that has not yet closed (H2 with active streams) is not re-signalled on a later event.
  bool _fatal_pending = false;
  // A handshake hook has parked (the driver returned SSL_WAIT_FOR_HOOK): a plugin owns a live
  // reference and will reenable_with_event into this VC. Set at the park, cleared when the plugin
  // reenables. It is a stable latch because do_io_close's callHooks(VCONN_CLOSE) advances the hook
  // FSM to HANDSHAKE_HOOKS_DONE, so is_invoked_state() can no longer witness the outstanding hold;
  // _reclaimIfClosed holds off on this so a consumer-driven close arriving while the hook is parked
  // (a transport error/timeout) cannot free the VC out from under the plugin's pending reenable. A
  // synchronous TSVConnAbort fails the handshake instead of parking, so it never sets this.
  bool _hook_parked = false;
  // A verify hook (SSL_VERIFY_SERVER/CLIENT) is running. Such a hook reenabling with TS_EVENT_ERROR
  // is reporting a certificate verdict, NOT terminating the handshake: whether a failed check stops
  // the handshake is the verify policy's call, applied by the OpenSSL verify callback's return
  // (SSLClientUtils: !enforce_mode) -- ENFORCED fails via SSL_ERROR_SSL, PERMISSIVE continues. While
  // this is set, reenable_with_event routes the error into _verify_hook_failed (read once by
  // _verify_certificate) instead of the terminal _sslState/_fatal_pending, so a PERMISSIVE override
  // still completes the handshake instead of being torn down.
  bool _in_verify_hook     = false;
  bool _verify_hook_failed = false;
  // In the graceful close-drain (do_io_close's lingering close): user VIOs are severed and the
  // transport is flushing the final ciphertext before teardown. SHUTDOWN_IN_PROGRESS is reached
  // from exactly one site (do_io_close) and the VC is freed the instant it leaves the state, so
  // this is the sole meaning of "draining".
  bool
  _isDraining() const
  {
    return _sslState == SslState::SHUTDOWN_IN_PROGRESS;
  }

  // True while a stack frame or a plugin still needs this VC alive, so it must NOT be freed:
  // nested in our own notify or an OpenSSL callback frame (recursion), a handshake hook mid
  // invocation (is_invoked_state), or a hook parked with a live plugin ref that will reenable
  // (_hook_parked). Every VC free site -- _reclaimIfClosed, do_io_close's inline free, and the
  // graceful-drain frees -- gates on this so a close arriving mid-hook cannot pull the VC out
  // from under the plugin's pending reenable. (Orthogonal to _isDraining, which is a separate
  // "the drain owns the free" gate: the drain frees while this predicate holds off.)
  bool
  _freeBlocked() const
  {
    return recursion != 0 || is_invoked_state() || _hook_parked;
  }

  // A deferred handshake-time handoff that frees this VC and hands its transport elsewhere. Both
  // arms are decided mid-handshake and executed out of line on a clean mainEvent dispatch (they
  // cannot free this VC inline while a transport read handler still inspects it). Kept as its own
  // small axis rather than folded into SslState: the blind-tunnel arm can be armed while the SSL
  // state is still HANDSHAKE_DONE (the OPT_TUNNEL path), so it must not overwrite that value.
  enum class PendingHandoff {
    NONE,            // no deferred handoff armed
    BLIND_TUNNEL,    // hand the transport to a dedicated pass-through VC (SNI blind-tunnel route)
    DOWNGRADE_PLAIN, // convert to a plain UnixNetVConnection (leading bytes are not a ClientHello)
  };
  PendingHandoff _pending_handoff = PendingHandoff::NONE;

  void _trackFirstHandshake();

public:
  int  sslStartHandShake(int event, int &err);
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
   * termination (see _commitInboundHandshake).
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

  void                _trigger_ssl_read();
  int64_t             _encrypt_data_for_transport(int64_t towrite, MIOBufferAccessor &buf, int64_t &total_written, int &needs);
  void                _make_ssl_connection(SSL_CTX *ctx);
  void                _bindSSLObject();
  UnixNetVConnection *_downgradeToPlain();
  void                _propagateHandShakeBuffer(UnixNetVConnection *target, EThread *t);
  void                _handoffBlindTunnel();
  void                _adoptConsumerMutex(Continuation *c);

  int         _ssl_read_from_net(int64_t &ret);
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

  enum class SignalSide { READ, WRITE };
  // Notification only: deliver `event` to the consumer's VIO on `side` (or, for a severed/
  // mismatched cont, run the null-cont owner-close arm, which sets a terminal _sslState and the
  // _close_requested latch for a terminal event). It NEVER frees `this`. Reclamation is a separate,
  // explicit step the caller makes on the same stack immediately after, via _reclaimIfClosed --
  // which frees only when the consumer has requested the close (consumer-driven teardown), never
  // from the terminal state alone.
  void _signal_user(SignalSide side, int event);
  // The single same-turn reclaim point paired with _signal_user (consumer-driven teardown).
  // Frees `this` (returning true) iff the consumer requested the close (_close_requested) and no
  // frame that still needs `this` alive is on the stack: recursion == 0 (own notify reentrancy or
  // an OpenSSL callback frame), not mid graceful-drain (_isDraining -- the drain owns the free),
  // and no handshake hook parked (is_invoked_state -- a plugin holds a live ref and will
  // reenable). NEVER frees from a terminal _sslState alone: master frees on `closed`, not on the
  // SSL error state. The caller must touch nothing after this returns true.
  bool       _reclaimIfClosed();
  SignalSide _handshake_fail_side() const;
  // Deliver the user-facing WRITE_COMPLETE synchronously and, if that causes the consumer to
  // reentrantly queue a new write, self-schedule a clean-stack rearm (see the definition and
  // _write_rearm_pending).
  int  _deliverWriteComplete();
  void _scheduleWriteRearm();

  // Re-entrancy depth covering two distinct hazards with the same fix: (1) _signal_user's own
  // synchronous re-entrancy (a consumer's handler drives more work on this same VC before
  // unwinding), and (2) synchronous re-entrancy into a foreign C callback frame -- OpenSSL
  // invoking one of our registered hooks (SNI/cert/client-hello/verify) mid SSL_accept()/
  // SSL_connect()/SSL_read()/SSL_write()/SSL_shutdown(), which may itself call back into us
  // (e.g. a plugin calling TSVConnAbort from a hook). Both cases make it unsafe to free `this`
  // or its owned _ssl inline: case (1) because an enclosing frame on our own stack still
  // expects `this` to be valid, case (2) because OpenSSL's own C code keeps running after the
  // callback returns and would touch a freed _ssl. do_io_close's inline-free decision and
  // _reclaimIfClosed (the reclaim paired with each _signal_user) both gate on recursion == 0
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

  std::unique_ptr<SSL, decltype(&SSL_free)>                              _ssl{nullptr, &SSL_free};
  std::unique_ptr<MIOBuffer, decltype(&free_MIOBuffer)>                  _read_buf;
  std::unique_ptr<MIOBuffer, decltype(&free_MIOBuffer)>                  _write_buf;
  std::unique_ptr<IOBufferReader, std::function<void(IOBufferReader *)>> _write_buf_reader;

public:
  void mark_as_tunnel_endpoint() override;
  bool from_accept_thread{false};

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
    TRANSPORT_LIVE,   // Connecting or established -- not terminated
    TRANSPORT_CLOSED, // TCP connection received EOS or normal close initiated
    TRANSPORT_ERROR   // TCP connection encountered an error
  };
  TransportState _transport_state = TransportState::TRANSPORT_LIVE;
  // The pending self-targeted deferred-work event (schedule_imm), or nullptr when none is
  // outstanding -- we never queue more than one. This one slot multiplexes several purposes --
  // the rbio read-drive (do_io_read / _handle_transport_eos / mainEvent), blind-tunnel handoff,
  // downgrade-to-plain, async-hook handshake resumption, and the write-rearm follow-up
  // (_scheduleWriteRearm) -- all of them self-targeted (re-invoke this VC's own mainEvent, never
  // a consumer), so none carry the receiver-liveness risk deferred consumer-facing signals do.
  // See mainEvent's scheduled-dispatch branch for the dispatch-time disambiguation among these
  // purposes. Held as a pointer (not a bool) so it can be cancelled if this VC is freed, its
  // mutex changes (_adoptConsumerMutex), or it migrates threads before the event fires (otherwise
  // the stale event would run on freed memory, under the wrong lock, or on the wrong thread).
  Event *_deferred_work_event = nullptr;
  bool
  _deferred_work_pending() const
  {
    return _deferred_work_event != nullptr;
  }
  // Set when a consumer reentrantly queues a new write from its (synchronously-delivered)
  // WRITE_COMPLETE handler while we're nested inside the inner transport's net_write_io. That
  // reentrant reenable() is doomed on this stack -- net_write_io's own still-executing tail
  // finds _write_buf empty (demand-driven encryption hasn't run yet) and disables the write,
  // undoing it. This flag arms a self-targeted, clean-stack re-issue of that reenable() once
  // net_write_io's current pass has fully unwound. See _deliverWriteComplete / mainEvent.
  bool _write_rearm_pending = false;
  static bool
  isTerminated(TransportState state)
  {
    return state == TransportState::TRANSPORT_CLOSED || state == TransportState::TRANSPORT_ERROR;
  }

  // Event handlers for transport (UnixNetVConnection)
  int _handle_transport_read_ready(VIO *vio);
  int _handle_transport_write_ready(VIO *vio);
  int _handle_transport_eos(VIO *vio);
  int _handle_transport_error(VIO *vio, int err);
  int _parse_proxy_protocol(IOBufferReader *reader);

  // Release the handshake reader (handShakeHolder) once the handshake is established and no
  // blind tunnel will adopt it, so it stops pinning _read_buf. See the definition for why a
  // lingering second reader otherwise wedges the rbio and stalls large reads.
  void _releaseHandshakeReader();

  // Inbound-only: release handShakeHolder once the hook FSM has passed the client-hello stage,
  // mirroring master's update_rbio(!in_client_hello). Call ONLY from the WANT_READ tail of
  // _trigger_ssl_read (never the pre-handshake-call sites), where the round's SNI/cert hooks
  // have already run and any tunnel/downgrade is resolved. See the definition.
  void _commitInboundHandshake();

  // The outbound consumer's handle on this VC's open (returned by SSLNetProcessor::connect_re).
  // Its continuation is the one to notify on open/open-failed (set_open_continuation delegates
  // here), and cancelling it targets THIS outer VC rather than the inner transport connect, so a
  // cancel cleans this VC up in startEvent instead of orphaning it -- or crashing the inner's
  // cancelled-before-connectUp teardown. Unused on the inbound (accept) path.
  Action _connect_action;
};

extern ClassAllocator<SSLNetVConnection, true> sslNetVCAllocator;
