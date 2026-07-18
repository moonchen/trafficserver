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

#include "BIO_MIOBuffer.h"
#include "P_UnixNet.h"
#include "P_UnixNetVConnection.h"
#include "SSLStats.h"
#include "P_Net.h"
#include "P_SSLUtils.h"
#include "P_SSLNextProtocolSet.h"
#include "P_SSLConfig.h"
#include "P_SSLClientUtils.h"
#include "P_SSLNetVConnection.h"
#include "P_TunnelNetVConnection.h"
#include "P_UnixNetProcessor.h"
#include "iocore/eventsystem/Continuation.h"
#include "iocore/eventsystem/Event.h"
#include "iocore/eventsystem/EventSystem.h"
#include "iocore/eventsystem/IOBuffer.h"
#include "iocore/eventsystem/Lock.h"
#include "iocore/net/Net.h"
#include "iocore/net/NetHandler.h"
#include "iocore/net/NetVConnection.h"
#include "iocore/net/ProxyProtocol.h"
#include "iocore/net/SSLDiags.h"
#include "iocore/net/SSLSNIConfig.h"
#include "iocore/net/SSLTypes.h"
#include "iocore/net/TLSALPNSupport.h"
#include "ts/apidefs.h"
#include "tscore/ink_assert.h"
#include "tscore/ink_config.h"
#include "tscore/Layout.h"
#include "tscore/InkErrno.h"
#include "tscore/TSSystemState.h"

#include <cerrno>
#include <cstdint>
#include <netinet/in.h>
#include <string>
#include <cstring>
#include <memory>

#if TS_USE_TLS_ASYNC
#include <openssl/async.h>
#endif

using namespace std::literals;

// This is missing from BoringSSL
#ifndef BIO_eof
#define BIO_eof(b) (int)BIO_ctrl(b, BIO_CTRL_EOF, 0, nullptr)
#endif

#define SSL_READ_ERROR_NONE        0
#define SSL_READ_ERROR             1
#define SSL_READ_READY             2
#define SSL_READ_COMPLETE          3
#define SSL_READ_WOULD_BLOCK       4
#define SSL_READ_EOS               5
#define SSL_HANDSHAKE_WANT_READ    6
#define SSL_HANDSHAKE_WANT_WRITE   7
#define SSL_HANDSHAKE_WANT_ACCEPT  8
#define SSL_HANDSHAKE_WANT_CONNECT 9
#define SSL_WRITE_WOULD_BLOCK      10
#define SSL_WAIT_FOR_HOOK          11
#define SSL_WAIT_FOR_ASYNC         12
#define SSL_RESTART                13

ClassAllocator<SSLNetVConnection, true> sslNetVCAllocator("sslNetVCAllocator");

namespace
{
DbgCtl dbg_ctl_ssl_early_data{"ssl_early_data"};
DbgCtl dbg_ctl_ssl_early_data_show_received{"ssl_early_data_show_received"};
DbgCtl dbg_ctl_ssl{"ssl"};
DbgCtl dbg_ctl_v_ssl{"v_ssl"};
DbgCtl dbg_ctl_ssl_error{"ssl.error"};
DbgCtl dbg_ctl_ssl_error_accept{"ssl.error.accept"};
DbgCtl dbg_ctl_ssl_error_connect{"ssl.error.connect"};
DbgCtl dbg_ctl_ssl_error_write{"ssl.error.write"};
DbgCtl dbg_ctl_ssl_error_read{"ssl.error.read"};
DbgCtl dbg_ctl_ssl_shutdown{"ssl-shutdown"};
DbgCtl dbg_ctl_ssl_alpn{"ssl_alpn"};
DbgCtl dbg_ctl_ssl_origin_session_cache{"ssl.origin_session_cache"};
DbgCtl dbg_ctl_proxyprotocol{"proxyprotocol"};
DbgCtl dbg_ctl_inactivity_cop{"inactivity_cop"};
DbgCtl dbg_ctl_ssl_io{"ssl_io"};

const char *
resolve_client_ca_cert_path(const SSLConfigParams *params, const char *path, std::string &storage)
{
  if (path == nullptr) {
    return params->clientCACertPath;
  }

  storage = Layout::get()->relative_to(Layout::get()->prefix, path);
  return storage.c_str();
}

} // namespace

//
// Private
//
template <typename T, typename Deleter>
std::unique_ptr<T, Deleter>
make_resource(T *raw, Deleter d)
{
  return std::unique_ptr<T, Deleter>{raw, d};
}

void
SSLNetVConnection::_make_ssl_connection(SSL_CTX *ctx)
{
  std::unique_ptr<SSL, decltype(&SSL_free)> temp_ssl = make_resource(SSL_new(ctx), SSL_free);
  if (temp_ssl == nullptr) {
    return;
  }

  // The handshake holder is a second reader parked at the head of _read_buf so the inbound
  // ClientHello can be replayed to a blind tunnel / plain downgrade or stripped of its PROXY
  // header. The outbound (origin) face never replays anything -- it is the TLS client -- and a
  // parked reader there would only pin _read_buf and stall large origin flights, so do not create
  // it. (The rbio/wbio the SSL object reads and writes through are set up below for both faces.)
  if (get_context() != NET_VCONNECTION_OUT) {
    this->initialize_handshake_buffers();
  }

  // Hold the BIOs in RAII guards until SSL_set_bio takes ownership: an early
  // return between BIO_new and SSL_set_bio would otherwise leak them.
  auto rbio = make_resource(BIO_new(BIO_s_miobuffer()), BIO_free);
  if (rbio == nullptr) {
    return;
  }

  // miobuffer_set_buffer only returns 0 on a null BIO context, which a successful
  // BIO_new(BIO_s_miobuffer()) cannot produce; assert the invariant while keeping the call's
  // load-bearing side effects (BIO_set_init / retry flags).
  ink_release_assert(miobuffer_set_buffer(rbio.get(), nullptr, _read_buf->alloc_reader()) == 1);

  auto wbio = make_resource(BIO_new(BIO_s_miobuffer()), BIO_free);
  if (wbio == nullptr) {
    return;
  }

  ink_release_assert(miobuffer_set_buffer(wbio.get(), _write_buf.get(), nullptr) == 1);

  // ownership of rbio and wbio is transferred to the SSL object
  SSL_set_bio(temp_ssl.get(), rbio.release(), wbio.release());

#if TS_HAS_TLS_EARLY_DATA
  update_early_data_config(temp_ssl.get(), SSLConfigParams::server_max_early_data, SSLConfigParams::server_recv_max_early_data);
#endif

  this->_ssl = std::move(temp_ssl);

  this->_bindSSLObject();
}

void
SSLNetVConnection::_bindSSLObject()
{
  SSLNetVCAttach(this->_ssl.get(), this);
  TLSBasicSupport::bind(this->_ssl.get(), this);
  TLSEventSupport::bind(this->_ssl.get(), this);
  ALPNSupport::bind(this->_ssl.get(), this);
  TLSSessionResumptionSupport::bind(this->_ssl.get(), this);
  TLSSNISupport::bind(this->_ssl.get(), this);
  TLSEarlyDataSupport::bind(this->_ssl.get(), this);
  TLSTunnelSupport::bind(this->_ssl.get(), this);
  TLSCertSwitchSupport::bind(this->_ssl.get(), this);
}

static void
debug_certificate_name(const char *msg, X509_NAME *name)
{
  BIO *bio;

  if (name == nullptr) {
    return;
  }

  bio = BIO_new(BIO_s_mem());
  if (bio == nullptr) {
    return;
  }

  if (X509_NAME_print_ex(bio, name, 0 /* indent */, XN_FLAG_ONELINE) > 0) {
    long  len;
    char *ptr;
    len = BIO_get_mem_data(bio, &ptr);
    Dbg(dbg_ctl_ssl, "%s %.*s", msg, static_cast<int>(len), ptr);
  }

  BIO_free(bio);
}

int
SSLNetVConnection::_ssl_read_from_net(int64_t &ret)
{
  MIOBufferAccessor &buf        = _user_read_vio.buffer;
  int                event      = SSL_READ_ERROR_NONE;
  int64_t            bytes_read = 0;
  ssl_error_t        sslErr     = SSL_ERROR_NONE;

  // Find out the max we can read, based on buffer size and user's request size
  int64_t toread = buf.writer()->write_avail();
  ink_release_assert(toread > 0);
  int64_t read_available = _user_read_vio.ntodo();
  toread                 = std::min(toread, read_available);

  bytes_read = 0;
  while (sslErr == SSL_ERROR_NONE && bytes_read < toread) {
    int64_t nread             = 0;
    int64_t block_write_avail = buf.writer()->block_write_avail();
    ink_release_assert(block_write_avail > 0);
    int64_t amount_to_read = toread - bytes_read;
    if (amount_to_read > block_write_avail) {
      amount_to_read = block_write_avail;
    }

    Dbg(dbg_ctl_ssl, "amount_to_read=%" PRId64, amount_to_read);
    char *current_block = buf.writer()->end();
    ink_release_assert(current_block != nullptr);
    sslErr = this->_ssl_read_buffer(current_block, amount_to_read, nread);

    Dbg(dbg_ctl_ssl, "nread=%" PRId64, nread);

    switch (sslErr) {
    case SSL_ERROR_NONE:
#if DEBUG
    {
      static DbgCtl dbg_ctl{"ssl_buff"};
      SSLDebugBufferPrint(dbg_ctl, current_block, nread, "SSL Read");
    }
#endif
      ink_assert(nread);
      bytes_read += nread;
      if (nread > 0) {
        buf.writer()->fill(nread); // Tell the buffer, we've used the bytes
      }
      break;
    case SSL_ERROR_WANT_WRITE:
      event = SSL_WRITE_WOULD_BLOCK;
      Dbg(dbg_ctl_ssl_error, "SSL_ERROR_WOULD_BLOCK(write)");
      break;
    case SSL_ERROR_WANT_READ:
      event = SSL_READ_WOULD_BLOCK;
      Dbg(dbg_ctl_ssl_error, "SSL_ERROR_WOULD_BLOCK(read)");
      break;
#ifdef SSL_ERROR_WANT_CLIENT_HELLO_CB
    case SSL_ERROR_WANT_CLIENT_HELLO_CB:
      event = SSL_READ_WOULD_BLOCK;
      Dbg(dbg_ctl_ssl_error, "SSL_ERROR_WOULD_BLOCK(read/client hello cb)");
      break;
#endif
    case SSL_ERROR_WANT_X509_LOOKUP:
      event = SSL_READ_WOULD_BLOCK;
      Dbg(dbg_ctl_ssl_error, "SSL_ERROR_WOULD_BLOCK(read/x509 lookup)");
      break;
    case SSL_ERROR_SYSCALL:
      if (nread != 0) {
        // not EOF
        Metrics::Counter::increment(ssl_rsb.error_syscall);
        event = SSL_READ_ERROR;
        ret   = errno;
        Dbg(dbg_ctl_ssl_error, "SSL_ERROR_SYSCALL, underlying IO error: %s", strerror(errno));
      } else {
        // then EOF observed, treat it as EOS
        event = SSL_READ_EOS;
      }
      break;
    case SSL_ERROR_ZERO_RETURN:
      event = SSL_READ_EOS;
      Dbg(dbg_ctl_ssl_error, "SSL_ERROR_ZERO_RETURN");
      break;
    case SSL_ERROR_SSL:
    default: {
      char          buf[512];
      unsigned long e = ERR_peek_last_error();
      ERR_error_string_n(e, buf, sizeof(buf));
      event = SSL_READ_ERROR;
      ret   = errno;
      SSLVCDebug(this, "errno=%d", errno);
      Metrics::Counter::increment(ssl_rsb.error_ssl);
    } break;
    } // switch
  } // while

  if (bytes_read > 0) {
    Dbg(dbg_ctl_ssl, "bytes_read=%" PRId64, bytes_read);

    _user_read_vio.ndone += bytes_read;
    ret                   = bytes_read;

    // If we read it all, don't worry about the other events and just send read complete
    event = (_user_read_vio.ntodo() <= 0) ? SSL_READ_COMPLETE : SSL_READ_READY;
  } else { // if( bytes_read > 0 )
#if defined(_DEBUG)
    if (bytes_read == 0) {
      Dbg(dbg_ctl_ssl, "bytes_read == 0");
    }
#endif
  }
  return event;
}

/**
 * @brief Proxy Protocol header processing
 *
 * Checks for the Proxy Protocol header (v1 or v2) and consumes it if appropriate.
 *
 * @param reader Buffered read data; the PROXY header is consumed from it when present.
 * @return > 0: A proxy protocol header was successfully parsed.
 * @return 0: No header present (or a partial header, treated as absent).
 * @return -ENOTCONN: A PROXY header was present but the source IP is not in the allowlist.
 */
int
SSLNetVConnection::_parse_proxy_protocol(IOBufferReader *reader)
{
  swoc::IPRangeSet *pp_ipmap;
  pp_ipmap = SSLConfigParams::proxy_protocol_ip_addrs;

  if (this->get_is_proxy_protocol() && this->get_proxy_protocol_version() == ProxyProtocolVersion::UNDEFINED) {
    Dbg(dbg_ctl_proxyprotocol, "proxy protocol is enabled on this port");
    // The allowlist gate only applies once a PROXY preface is actually present: a connection from an
    // untrusted source that sends no PROXY header is an ordinary client, not one to refuse.
    if (this->has_proxy_protocol_preface(reader)) {
      if (pp_ipmap != nullptr && pp_ipmap->count() > 0) {
        Dbg(dbg_ctl_proxyprotocol, "proxy protocol has a configured allowlist of trusted IPs - checking");
        if (!pp_ipmap->contains(swoc::IPAddr(get_remote_addr()))) {
          Dbg(dbg_ctl_proxyprotocol, "Source IP is NOT in the configured allowlist of trusted IPs - closing connection");
          return -ENOTCONN;
        } else {
          char new_host[INET6_ADDRSTRLEN];
          Dbg(dbg_ctl_proxyprotocol, "Source IP [%s] is in the trusted allowlist for proxy protocol",
              ats_ip_ntop(this->get_remote_addr(), new_host, sizeof(new_host)));
        }
      } else {
        Dbg(dbg_ctl_proxyprotocol, "proxy protocol DOES NOT have a configured allowlist of trusted IPs but "
                                   "proxy protocol is enabled on this port - processing all connections");
      }

      if (has_proxy_protocol(reader, SSLConfigParams::proxy_protocol_hdr_max_size)) {
        Dbg(dbg_ctl_proxyprotocol, "ssl has proxy protocol header");
        if (dbg_ctl_proxyprotocol.on()) {
          IpEndpoint dst;
          dst.sa = *(this->get_proxy_protocol_dst_addr());
          ip_port_text_buffer ipb1;
          ats_ip_nptop(&dst, ipb1, sizeof(ipb1));
          DbgPrint(dbg_ctl_proxyprotocol, "ssl_has_proxy_v1, dest IP received [%s]", ipb1);
        }
        return 1;
      } else {
        Dbg(dbg_ctl_proxyprotocol, "proxy protocol preface was present, but Proxy Protocol header could not be parsed");
      }
    } else {
      Dbg(dbg_ctl_proxyprotocol, "proxy protocol was enabled, but Proxy Protocol header was not present");
    }
  }
  return 0;
}

//
// Notify the consumer of an event. Notification only -- see _reclaimIfClosed for the
// paired reclaim.
//
void
SSLNetVConnection::_signal_user(SignalSide side, int event)
{
  recursion++;
  VIO        &vio      = side == SignalSide::READ ? _user_read_vio : _user_write_vio;
  const char *side_str = side == SignalSide::READ ? "read" : "write";
  if (vio.cont && vio.mutex == vio.cont->mutex) {
    vio.cont->handleEvent(event, &vio);
  } else {
    if (vio.cont) {
      Note("signal %s: mutexes are different? vc=%p, event=%d", side_str, this, event);
    }
    switch (event) {
    case VC_EVENT_EOS:
    case VC_EVENT_ERROR:
    case VC_EVENT_ACTIVE_TIMEOUT:
    case VC_EVENT_INACTIVITY_TIMEOUT:
      // A terminal event with no live consumer to hand it to: the consumer is gone (severed by a
      // prior do_io_close) or never attached, so nobody will call do_io_close to drive the free.
      // Own the close here -- master's read_signal_and_update sets `closed = 1` in exactly this
      // case (UnixNetVConnection.cc). _reclaimIfClosed then reaps this VC on the unwind.
      Dbg(dbg_ctl_inactivity_cop, "%s event %d: null vio cont, closing vc %p", side_str, event, this);
      _sslState        = SslState::TERMINATED;
      _close_requested = true;
      break;
    default:
      // A delivery aimed at a consumer that's already gone (severed cont, or a mutex that no
      // longer matches) is an expected, benign occurrence -- not evidence of a deeper bug --
      // for any event, not just the terminal ones above: synchronous delivery closes most of
      // the window where this can happen, but does not make it structurally impossible (e.g.
      // a consumer that dropped its VIO without going through do_io_close first). Log and
      // drop it rather than aborting the process over a delivery nobody can act on.
      Dbg(dbg_ctl_ssl_io, "%s event %d: stale vio cont on vc %p, dropping", side_str, event, this);
      break;
    }
  }
  --recursion;
}

// Consumer-driven teardown reclaim, paired with _signal_user. The outer VC frees ONLY when its
// consumer has requested the close (_close_requested, set by do_io_close or the null-cont
// owner-close) -- never merely because the SSL state went terminal. A terminal _sslState gates
// I/O; it does not authorize the free. This mirrors master (UnixNetVConnection frees on `closed`,
// not on SSL_HANDSHAKE_ERROR). The physical free lives here rather than in the NetHandler because
// the layered outer VC is not NetHandler-managed. Deferred while a frame still needs `this`:
// recursion > 0 (our own notify reentrancy or an OpenSSL callback frame), a graceful drain in
// flight (_isDraining -- the drain machinery owns that free), or a handshake hook parked
// (is_invoked_state -- the plugin holds a live ref and will reenable). Returns true when it
// reclaimed; the caller must touch nothing afterward.
bool
SSLNetVConnection::_reclaimIfClosed()
{
  if (_close_requested && !_isDraining() && !_freeBlocked()) {
    /* BZ  31932 */
    ink_assert(thread == this_ethread());
    this->free_thread(this_ethread());
    return true;
  }
  return false;
}

// Which side to deliver a handshake failure on: the consumer waiting on the handshake
// listens with a (zero-byte) read VIO on the pooled/trampoline paths (ConnectingEntry,
// SSLNextProtocolTrampoline), but the direct outbound connect (HttpSM) attaches only a
// 1-byte do_io_write -- signalling its absent read side would silently drop the error.
SSLNetVConnection::SignalSide
SSLNetVConnection::_handshake_fail_side() const
{
  return _user_read_vio.op == VIO::READ ? SignalSide::READ : SignalSide::WRITE;
}

void
SSLNetVConnection::_releaseHandshakeReader()
{
  // handShakeHolder is a second IOBufferReader on _read_buf, allocated by
  // initialize_handshake_buffers() for the inbound ClientHello replay / blind-tunnel handoff (only
  // the inbound face creates one). On a normal (TLS-terminated) connection nothing ever consumes
  // it, and it is otherwise only freed at teardown -- so it stays pinned at the head of _read_buf
  // for the whole data phase. That keeps _read_buf->max_read_avail() at the full buffer; with
  // _read_buf's water_mark of 0, MIOBuffer::high_water() is then always true and check_add_block()
  // never grows the rbio. Once the transport read fills the first block, write_avail() is 0 forever
  // and the transport read disables on a "full" buffer -- the layered VC reads at most one rbio
  // block (~one DATA frame) of any response and stalls, and a handshake flight larger than one
  // block (a big mTLS client-cert bundle) never completes. Release it as soon as it can no longer
  // be needed so the rbio recycles and can stream bodies -- and read handshake flights -- larger
  // than one block.
  //
  // This is the established-handshake release; _commitInboundHandshake drops it earlier (once the
  // hook FSM passes CLIENT_HELLO) for the common no-tunnel case. A FORWARD / PARTIAL_BLIND route
  // keeps it through the handshake and releases here.
  if (handShakeHolder != nullptr && getSSLHandShakeComplete() && get_tunnel_type() != SNIRoutingType::BLIND &&
      _pending_handoff != PendingHandoff::BLIND_TUNNEL) {
    handShakeHolder->dealloc();
    handShakeHolder = nullptr;
  }
}

void
SSLNetVConnection::_commitInboundHandshake()
{
  // Inbound analog of master's update_rbio(!in_client_hello) + free_handshake_buffers()
  // (upstream net_read_io, SSLNetVConnection.cc:597-604): once the handshake-hook FSM has
  // advanced past HANDSHAKE_HOOKS_CLIENT_HELLO, ATS has committed to terminating TLS -- no
  // blind tunnel or plain downgrade can follow -- so the ClientHello no longer needs to be
  // replayable. Release handShakeHolder here so it stops pinning _read_buf and the single
  // ciphertext buffer can stream the client's post-ServerHello flight (a large mTLS
  // client-cert bundle) and, afterwards, response bodies larger than one rbio block. Master
  // switches SSL to a socket BIO instead; the layered VC has no socket to switch to, so
  // dropping the second reader is the whole move.
  //
  // Call site matters as much as the state: this runs ONLY from the WANT_READ/WANT_ACCEPT
  // tail of _trigger_ssl_read, after sslStartHandShake() has returned and after the
  // SSL_RESTART (downgrade), blind-tunnel, terminated, and EVENT_ERROR early-returns. That is
  // where the round's SNI/cert hooks have already run and any tunnel/downgrade decision is
  // final -- the same knowledge master's line-604 position encodes. Evaluating the same state
  // predicate from _releaseHandshakeReader's other call sites (pre-sslStartHandShake, or the
  // write face) would release a round too early: a resumed parked client-hello hook can leave
  // the FSM at SNI before this round's SSL_accept runs the servername/cert hooks, one of which
  // may still TSVConnTunnel -- and _handoffBlindTunnel would then replay a headless stream.
  //
  // Three gate conditions -- master's two plus the layered tunnel exclusion:
  //   - handShakeHolder != nullptr: master's first condition, and idempotent -- null after the
  //     first release, and _trigger_ssl_read runs every WANT_READ round. Because the holder is
  //     only created for the inbound face (_make_ssl_connection), a non-null holder already
  //     implies an inbound VC -- the context is asserted below rather than branched.
  //   - state != CLIENT_HELLO: master's commit signal -- past the client-hello stage, TLS
  //     termination is committed and no blind tunnel / plain downgrade can follow.
  //   - tunnel_type == NONE: unlike master (which switches SSL to a socket BIO and lets the kernel
  //     hold the raw stream), a FORWARD / PARTIAL_BLIND route terminates TLS here but its tunnel
  //     still forwards through _read_buf, so the second reader must stay. BLIND is redundant with
  //     this (it also sets attributes, caught by the blind-tunnel early-return in _trigger_ssl_read),
  //     but FORWARD / PARTIAL_BLIND are not.
  //
  // Everything else that must hold to make the release safe is guaranteed by this call site (past
  // the SSL_RESTART / blind-tunnel / terminated / EVENT_ERROR early-returns, on a WANT_READ round
  // where no hook is parked), so it is asserted rather than branched -- a future change that breaks
  // the sequencing then crashes loudly here instead of silently releasing the holder into a
  // still-pending tunnel/downgrade.
  if (handShakeHolder != nullptr &&
      get_handshake_hook_state() != TLSEventSupport::SSLHandshakeHookState::HANDSHAKE_HOOKS_CLIENT_HELLO &&
      get_tunnel_type() == SNIRoutingType::NONE) {
    // The holder is created only for the inbound face, so a live one here is never outbound.
    ink_release_assert(get_context() != NET_VCONNECTION_OUT);
    // A WANT_READ return means no hook is parked (a parked hook returns EVENT_CONT /
    // SSL_WAIT_FOR_HOOK, a different switch case), so the FSM is never at a *_INVOKE substate --
    // in particular not CLIENT_HELLO_INVOKE, which the state check above would otherwise admit.
    ink_release_assert(!is_invoked_state());
    // A blind tunnel from a cert/servername-hook TSVConnTunnel or tr-pass sets attributes =
    // BLIND_TUNNEL and returned at the blind-tunnel early-return in _trigger_ssl_read, so it cannot
    // be pending here (the SNI-route BLIND is already excluded by the tunnel_type gate above).
    ink_release_assert(attributes != HttpProxyPort::TRANSPORT_BLIND_TUNNEL);
    // DOWNGRADE_PLAIN returned via SSL_RESTART and BLIND_TUNNEL via the line-541 path; neither
    // handoff can be pending here.
    ink_release_assert(_pending_handoff == PendingHandoff::NONE);
    handShakeHolder->dealloc();
    handShakeHolder = nullptr;
  }
}

// changed by YTS Team, yamsat
void
SSLNetVConnection::_trigger_ssl_read()
{
  int     ret;
  int64_t r     = 0;
  int64_t bytes = 0;

  Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: _trigger_ssl_read called", this);
  ink_release_assert(HttpProxyPort::TRANSPORT_BLIND_TUNNEL != this->attributes);
  _releaseHandshakeReader();

  // Lock the user read VIO's mutex when a consumer has attached (so we can signal it safely);
  // otherwise -- the outbound handshake reads the ServerHello before any consumer calls
  // do_io_read (notably the multiplexed/ConnectingEntry origin path, where the consumer attaches
  // only after ALPN) -- fall back to this VC's own mutex. That mutex is what the transport read
  // VIO carries (it was created with this VC as continuation) and is therefore already held by the
  // net_read_io that drove us here, so the try-lock succeeds. Using _user_read_vio.mutex blindly
  // would dereference a null Ptr during the pre-consumer handshake.
  Ptr<ProxyMutex> &read_lock_mutex = _user_read_vio.mutex ? _user_read_vio.mutex : this->mutex;
  MUTEX_TRY_LOCK(lock, read_lock_mutex, this_ethread());
  ink_release_assert(lock.is_locked());

  // If the key renegotiation failed it's over, just signal the error and finish.
  if (sslClientRenegotiationAbort == true) {
    lerrno = -ENET_SSL_FAILED;
    _signal_user(SignalSide::READ, VC_EVENT_ERROR);
    _reclaimIfClosed();
    Dbg(dbg_ctl_ssl, "client renegotiation setting read signal error");
    return;
  }

  // Continue on if we are still in the handshake. This must come BEFORE the user-read-VIO
  // gate below: handshake records arrive as transport read events regardless of whether a
  // consumer has attached a read VIO, and on the outbound direct-connect path none ever is
  // (HttpSM attaches only a 1-byte do_io_write and expects a WRITE_READY once the handshake
  // completes; ConnectingEntry's zero-byte do_io_read masks this on the pooled path). Gating
  // first would silently disable the transport read with the ServerHello stranded in the
  // rbio and freeze the handshake until an external timeout. The user-VIO gate governs
  // post-handshake data delivery only; the write face orders its handshake block the same
  // way (_handle_transport_write_ready).
  if (!getSSLHandShakeComplete()) {
    this->_trackFirstHandshake();

    int err = 0;

    if (get_context() == NET_VCONNECTION_OUT) {
      ret = sslStartHandShake(SSL_EVENT_CLIENT, err);
    } else {
      ret = sslStartHandShake(SSL_EVENT_SERVER, err);
    }
    if (ret == SSL_RESTART) {
      // VC migrated into a new object
      // Just give up and go home. Events should trigger on the new vc
      Dbg(dbg_ctl_ssl, "Restart for allow plain");
      return;
    }
    // If we have flipped to blind tunnel, don't read ahead. We check for a
    // non-error return first, though, because if TLS has already failed with
    // the CLIENT_HELLO, then there is no need to continue toward the origin
    // with the blind tunnel.
    if (ret != EVENT_ERROR && this->attributes == HttpProxyPort::TRANSPORT_BLIND_TUNNEL) {
      // The SNI callback selected a blind tunnel_route, so we must NOT terminate TLS:
      // the buffered ClientHello (and everything after it) is forwarded raw to the origin
      // so the client's handshake completes against the origin's certificate. In the
      // layered model we cannot revert this VC to a plain socket (it only has-a
      // transport), so hand the transport off to a dedicated pass-through VC.
      //
      // Defer the handoff out of line: it frees this VC, and we may be on the stack of a
      // transport read handler that inspects _sslState after we return. The scheduled
      // mainEvent dispatch is the one safe place to free inline.
      _pending_handoff = PendingHandoff::BLIND_TUNNEL;
      if (_transport_read_vio != nullptr) {
        // No more SSL-side reads before the handoff; the pass-through VC re-drives the
        // transport itself, and the buffered bytes remain in _read_buf.
        _transport_read_vio->disable();
      }
      if (!_deferred_work_pending()) {
        _deferred_work_event = this_ethread()->schedule_imm(this);
      }
      return; // Leave if we are tunneling
    }

    // A hook may have synchronously flagged an error (reenable_with_event(TS_EVENT_ERROR),
    // called from within a hook still nested mid SSL_accept()/SSL_connect()) without the
    // handshake call itself returning an outright error this round -- e.g. SSL_HANDSHAKE_WANT_READ,
    // if the hook didn't force a fatal alert. None of the switch branches below check
    // _sslState, so routed through anything but the `case EVENT_ERROR` branch, a hook-flagged
    // error would otherwise be silently dropped here and only caught later by the scheduled
    // fallback (mainEvent's terminated-state branch). sslStartHandShake() has already returned, so
    // we are unconditionally outside any OpenSSL frame here -- always safe to deliver
    // synchronously. Skip this when `ret == EVENT_ERROR`: the switch's own case below has the
    // more specific `err` to report.
    if (ret != EVENT_ERROR && _sslState == SslState::TERMINATED) {
      _signal_user(_handshake_fail_side(), VC_EVENT_ERROR);
      _reclaimIfClosed();
      return;
    }

    switch (ret) {
    case EVENT_ERROR:
      lerrno = err;
      // The paired reclaim may free this VC; on error there is nothing more to do, so
      // return rather than falling through to the member access below.
      _signal_user(_handshake_fail_side(), VC_EVENT_ERROR);
      _reclaimIfClosed();
      return;
    case SSL_HANDSHAKE_WANT_READ:
    case SSL_HANDSHAKE_WANT_ACCEPT:
      // The handshake needs more peer bytes; if the transport is already gone they can
      // never arrive. Master surfaced the socket error straight through SSL's BIO as a
      // handshake EVENT_ERROR, but the layered rbio decouples SSL from the socket: the
      // failure lands as a separate transport EOS/ERROR event (recorded in
      // _transport_state by its handler, whose scheduled read drive brings us here) while
      // SSL only sees an empty rbio (WANT_READ). Waiting would strand the consumer until
      // its connect/inactivity timeout (misreported as ETIMEDOUT) -- and a ConnectingEntry
      // is never told at all. A connection that dies mid-handshake is a connect ERROR
      // (EPIPE for a bare FIN, matching master's EOS-during-connect classification; a
      // transport error keeps its real errno).
      if (isTerminated(_transport_state)) {
        if (_transport_state == TransportState::TRANSPORT_CLOSED || lerrno == 0) {
          lerrno = EPIPE;
        }
        _signal_user(_handshake_fail_side(), VC_EVENT_ERROR);
        _reclaimIfClosed();
        return;
      }
      if (SSLConfigParams::ssl_handshake_timeout_in > 0) {
        double handshake_time = (static_cast<double>(ink_get_hrtime() - this->get_tls_handshake_begin_time()) / 1000000000);
        Dbg(dbg_ctl_ssl, "ssl handshake for vc %p, took %.3f seconds, configured handshake_timer: %d", this, handshake_time,
            SSLConfigParams::ssl_handshake_timeout_in);
        if (handshake_time > SSLConfigParams::ssl_handshake_timeout_in) {
          Dbg(dbg_ctl_ssl, "ssl handshake for vc %p, expired, release the connection", this);
          lerrno = ETIMEDOUT;
          _signal_user(_handshake_fail_side(), VC_EVENT_ERROR);
          _reclaimIfClosed();
          return;
        }
      }
      // The handshake is progressing and waiting for the client's next flight. If the hook FSM
      // has passed the client-hello stage, TLS termination is committed -- release the
      // ClientHello holder so the (possibly large) inbound flight streams unpinned. See the
      // method: this is the only safe call site for the inbound release.
      _commitInboundHandshake();
      _transport_read_vio->reenable();
      break;
    case SSL_HANDSHAKE_WANT_CONNECT:
      // The SSL object is given only MIOBuffer BIOs; the inner transport owns the connect, so
      // the SSL stack can never be in a connecting state. (Master attached a socket BIO here,
      // which the layered VC eliminates.)
      ink_release_assert(!"handshake WANT_CONNECT: no socket BIO is attached to the SSL object");
      break;
    case SSL_HANDSHAKE_WANT_WRITE:
      // The MIOBuffer wbio always absorbs the full handshake flight, so the SSL stack can never
      // ask to retry a write (mirrors the post-handshake assert in _encrypt_data_for_transport).
      ink_release_assert(!"handshake WANT_WRITE: the MIOBuffer wbio must never refuse a write");
      break;
    case EVENT_DONE:
      Dbg(dbg_ctl_ssl, "ssl handshake EVENT_DONE vc %p ntodo=%" PRId64, this, _user_read_vio.ntodo());
      // If this was driven by a zero length read (e.g. ConnectingEntry's handshake-completion
      // probe), signal complete when the handshake is complete. The signal may free this VC, so
      // bail out before the member access below if it did.
      if (_user_read_vio.op == VIO::READ && !_user_read_vio.is_disabled() && _user_read_vio.ntodo() <= 0) {
        _signal_user(SignalSide::READ, VC_EVENT_READ_COMPLETE);
        if (_reclaimIfClosed()) {
          return;
        }
      } else if (_user_read_vio.op != VIO::READ && _user_write_vio.op == VIO::WRITE && !_user_write_vio.is_disabled() &&
                 _write_buf_reader->read_avail() == 0) {
        // Write-only waiter with an empty wbio: the outbound direct connect (HttpSM) attaches only a
        // 1-byte do_io_write and treats WRITE_READY as "handshake done", with no read VIO to signal.
        // A full TLS-1.2 handshake completes on this transport READ pass with the client's final
        // flight already flushed, so no wbio bytes remain to re-arm the write face and drive its
        // WRITE_READY (the flush below and in _handle_transport_write_ready). TLS-1.3 and TLS-1.2
        // resumption complete with the client flight still in the wbio and stay on that flush path;
        // the pooled ConnectingEntry probe uses a read VIO and is signalled above. Deliver the
        // write-side wakeup directly so the connect does not strand to its timeout. The signal may
        // free this VC, so bail out before the member access below if it did.
        _signal_user(SignalSide::WRITE, VC_EVENT_WRITE_READY);
        if (_reclaimIfClosed()) {
          return;
        }
      }
      break;
    case SSL_WAIT_FOR_HOOK:
      Dbg(dbg_ctl_ssl, "ssl wait for hook for vc %p", this);
      // A handshake hook has genuinely parked: the driver returned here because the plugin owns
      // control and will reenable_with_event later. Record it so a consumer-driven close arriving
      // while it is parked (a transport error/timeout to the trampoline) does not free the VC out
      // from under the plugin's pending reenable -- do_io_close's callHooks(VCONN_CLOSE) advances
      // the hook FSM to DONE, so is_invoked_state() alone can no longer witness the hold. Cleared
      // in reenable_with_event. (A synchronous TSVConnAbort fails the handshake instead of parking,
      // so it never reaches here and its teardown is not blocked.)
      // Key on is_invoked_state(): a hook that reenabled synchronously already cleared _hook_parked
      // and advanced the FSM, so re-latching here would leave a stale hold that blocks the free
      // forever (a leak now that every free site honors _hook_parked).
      if (is_invoked_state()) {
        _hook_parked = true;
      }
      break;
    case SSL_WAIT_FOR_ASYNC:
      Dbg(dbg_ctl_ssl, "ssl wait for async for vc %p", this);
      break;
    default:
      break;
    }

    if (_write_buf_reader->read_avail() > 0) {
      // handshake produced bytes to write
      _transport_write_vio->reenable();
    }

    if (ret == EVENT_DONE && miobuffer_has_read_avail(SSL_get_rbio(this->_ssl.get()))) {
      // There is data in the read buffer, so continue reading
      Dbg(dbg_ctl_ssl, "data in read buffer after handshake for vc %p, continuing to read", this);
    } else {
      return;
    }
  }

  // If it is not enabled, lower its priority.  This allows
  // a fast connection to speed match a slower connection by
  // shifting down in priority even if it could read.
  if (_user_read_vio.op != VIO::READ || _user_read_vio.is_disabled()) {
    _transport_read_vio->disable();
    return;
  }

  MIOBufferAccessor &buf = _user_read_vio.buffer;
  ink_assert(buf.writer() != nullptr);

  // If there is nothing to do or no space available, disable connection
  // re-read _user_read_vio.ntodo() because it may have changed after _signal_user()
  if (_user_read_vio.ntodo() <= 0 || !buf.writer()->write_avail() || _user_read_vio.is_disabled()) {
    _transport_read_vio->disable();
    return;
  }

  // At this point we are at the post-handshake SSL processing
  //
  // not sure if this do-while loop is really needed here, please replace
  // this comment if you know
  int ssl_read_errno = 0;
  do {
    ret = this->_ssl_read_from_net(r);
    if (ret == SSL_READ_READY || ret == SSL_READ_ERROR_NONE) {
      bytes += r;
    }
    ink_assert(bytes >= 0);
  } while ((ret == SSL_READ_READY && bytes == 0) || ret == SSL_READ_ERROR_NONE);
  ssl_read_errno = errno;

  // SSL_read can produce protocol output of its own, with no SSL_write in flight to carry it:
  // the no_renegotiation alert answering a client's renegotiation request (OpenSSL 3.x never
  // honors one unless SSL_OP_ALLOW_CLIENT_RENEGOTIATION is set, which ATS does not do, so this
  // refusal happens regardless of proxy.config.ssl.allow_client_renegotiation), the server
  // flights of a renegotiation a pre-3.0 library does honor, or a KeyUpdate response on an
  // otherwise idle connection. Master's SSL object wrote these straight to the socket BIO; the
  // layered wbio only reaches the wire when the transport write drive runs, and with the user
  // write face idle nothing else re-arms it -- the peer would wait forever for bytes stranded
  // in the wbio (a renegotiating client hangs instead of receiving the prompt refusal master
  // sent). Flush them before the user signals below, which may free this VC.
  if (_write_buf_reader->read_avail() > 0) {
    _transport_write_vio->reenable();
  }

  if (bytes > 0) {
    if (ret == SSL_READ_WOULD_BLOCK || ret == SSL_READ_READY) {
      _signal_user(SignalSide::READ, VC_EVENT_READ_READY);
      if (_reclaimIfClosed()) {
        Dbg(dbg_ctl_ssl, "read signal reclaimed the vc");
        return;
      }
    }
  }

  int wants = SSL_want(this->_ssl.get());
  Dbg(dbg_ctl_ssl, "SSL_want=%d", wants);
  switch (ret) {
  case SSL_READ_READY:
    // We delivered a buffer-full of plaintext and the consumer still wants more. _ssl_read_from_net
    // stops at the downstream buffer's capacity (toread = write_avail), so SSL_READ_READY can mean
    // the rbio STILL holds ciphertext we have not decrypted yet. The transport read will NOT
    // re-signal us for ciphertext already buffered in the rbio -- net_read_io signals only when it
    // reads fresh bytes off the socket -- so handing the continuation to it would strand those
    // records until the peer happens to send more (the layered-VC read stall). Now that _signal_user
    // has drained room downstream, if the rbio still has ciphertext keep draining it out of line (a
    // clean stack, so we do not re-enter the consumer here); mainEvent clears _deferred_work_event.
    // Otherwise the rbio is dry: re-arm the transport read and wait for the next socket data --
    // unless the peer's close_notify was coalesced into the same fill as this final app data.
    // _ssl_read_from_net records SSL_READ_EOS for the alert but then overwrites it with
    // SSL_READ_READY here because plaintext was produced; SSL has already latched
    // SSL_RECEIVED_SHUTDOWN, so re-drive out of line to let the next read surface the pending EOS.
    // A TLS half-close leaves TCP open (no prompt FIN), so waiting on a transport read would strand
    // the EOS until the inactivity timeout (INV-8: EOS is persistent state, not a socket edge).
    if (this->_ssl != nullptr && !_deferred_work_pending() && _user_read_vio.op == VIO::READ && !_user_read_vio.is_disabled() &&
        _user_read_vio.ntodo() > 0 && buf.writer() != nullptr && buf.writer()->write_avail() > 0 &&
        (miobuffer_has_read_avail(SSL_get_rbio(this->_ssl.get())) || SSL_pending(this->_ssl.get()) > 0 || _early_data_pending() ||
         (SSL_get_shutdown(this->_ssl.get()) & SSL_RECEIVED_SHUTDOWN))) {
      _deferred_work_event = this_ethread()->schedule_imm(this);
    } else {
      _transport_read_vio->reenable();
    }
    return;
    break;
  case SSL_WRITE_WOULD_BLOCK:
    _transport_write_vio->reenable();
    Dbg(dbg_ctl_ssl, "read finished - would block - need write");
    break;
  case SSL_READ_WOULD_BLOCK:
    if (isTerminated(_transport_state)) {
      // The transport is gone (FIN or error) and the rbio is drained: no more bytes will
      // ever arrive, so surface the close to the enabled reader now -- master re-reads the
      // socket EOF on every enabled read pass and delivers EOS the same way. Distinguish a
      // broken transport (e.g. an RST) from a clean close: it must surface as
      // VC_EVENT_ERROR so HttpSM classifies it as a connection error rather than a closed
      // connection. A bare-FIN half-close mid-transaction is the CONSUMER's call, exactly
      // as on master: HttpSM's allow_half_open path answers EOS with a TLS-aware
      // IO_SHUTDOWN_READ and the response still proceeds, while an idle keep-alive session
      // closes (suppressing EOS here instead left idle sessions lingering forever -- their
      // session-close hooks never fired, e.g. traffic_dump's unfinished session logs).
      // EOS/ERROR is a persistent state, not an edge: do_io_read and reenable re-drive
      // this path so a consumer that attaches or re-enables later still observes it.
      if (_transport_state == TransportState::TRANSPORT_ERROR) {
        Dbg(dbg_ctl_ssl, "read would block but transport errored - signalling ERROR vc %p", this);
        _signal_user(SignalSide::READ, VC_EVENT_ERROR);
      } else {
        Dbg(dbg_ctl_ssl, "read would block but transport closed - signalling EOS vc %p", this);
        _signal_user(SignalSide::READ, VC_EVENT_EOS);
      }
      // The paired reclaim may free this VC; touch nothing after it.
      _reclaimIfClosed();
    } else {
      _transport_read_vio->reenable();
      Dbg(dbg_ctl_ssl, "read finished - would block - need read");
    }
    break;

  case SSL_READ_EOS:
    // close the connection if we have SSL_READ_EOS, this is the return value from ssl_read_from_net() if we get an
    // SSL_ERROR_ZERO_RETURN from SSL_get_error()
    // SSL_ERROR_ZERO_RETURN means that the origin server closed the SSL connection
    _signal_user(SignalSide::READ, VC_EVENT_EOS);
    _reclaimIfClosed();

    if (bytes > 0) {
      Dbg(dbg_ctl_ssl, "read finished - EOS");
    } else {
      Dbg(dbg_ctl_ssl, "read finished - 0 useful bytes read, bytes used by SSL layer");
    }
    break;
  case SSL_READ_COMPLETE:
    Dbg(dbg_ctl_ssl, "read finished - signal done");
    _signal_user(SignalSide::READ, VC_EVENT_READ_COMPLETE);
    _reclaimIfClosed();
    break;
  case SSL_READ_ERROR:
    Dbg(dbg_ctl_ssl, "read finished - read error");
    // Consumer-driven: record the error and deliver VC_EVENT_ERROR; the consumer's do_io_close
    // frees the outer (and, via the destructor, the inner). Do NOT close _unvc here -- the outer
    // may legitimately outlive this delivery (H2 with active streams keeps the VC until its
    // streams drain), and _transport_*_vio point into _unvc, so an early inner close leaves the
    // surviving outer holding dangling transport VIOs. Set lerrno before the signal, mapping an
    // SSL-layer error (ssl_read_errno == 0) to -ENET_SSL_FAILED so HttpSM/ConnectingEntry does not
    // read lerrno == 0 as "no error" (master _readSignalError parity).
    this->lerrno = ssl_read_errno ? ssl_read_errno : -ENET_SSL_FAILED;
    _signal_user(SignalSide::READ, VC_EVENT_ERROR);
    _reclaimIfClosed();
    break;
  }
}

int64_t
SSLNetVConnection::_encrypt_data_for_transport(int64_t towrite, MIOBufferAccessor &buf, int64_t &total_written, int &needs)
{
  int64_t     try_to_write;
  int64_t     num_really_written      = 0;
  int64_t     l                       = 0;
  uint32_t    dynamic_tls_record_size = 0;
  ssl_error_t err                     = SSL_ERROR_NONE;

  // Dynamic TLS record sizing
  ink_hrtime now = 0;
  if (SSLConfigParams::ssl_maxrecord == -1) {
    now                       = ink_get_hrtime();
    int msec_since_last_write = ink_hrtime_diff_msec(now, sslLastWriteTime);

    if (msec_since_last_write > SSL_DEF_TLS_RECORD_MSEC_THRESHOLD) {
      // reset sslTotalBytesSent upon inactivity for SSL_DEF_TLS_RECORD_MSEC_THRESHOLD
      sslTotalBytesSent = 0;
    }
    Dbg(dbg_ctl_ssl, "now=%" PRId64 " lastwrite=%" PRId64 " msec_since_last_write=%d", now, sslLastWriteTime,
        msec_since_last_write);
  }

  // Blind tunnel should have been downgraded to UnixNetVConnection
  ink_release_assert(this->attributes != HttpProxyPort::TRANSPORT_BLIND_TUNNEL);

  Dbg(dbg_ctl_ssl, "towrite=%" PRId64, towrite);

  ERR_clear_error();
  do {
    // What is remaining left in the next block?
    l                   = buf.reader()->block_read_avail();
    char *current_block = buf.reader()->start();

    // check if to amount to write exceeds that in this buffer
    int64_t wavail = towrite - total_written;

    if (l > wavail) {
      l = wavail;
    }

    // TS-2365: If the SSL max record size is set and we have
    // more data than that, break this into smaller write
    // operations.
    if (SSLConfigParams::ssl_maxrecord > 0 && l > SSLConfigParams::ssl_maxrecord) {
      l = SSLConfigParams::ssl_maxrecord;
    } else if (SSLConfigParams::ssl_maxrecord == -1) {
      if (sslTotalBytesSent < SSL_DEF_TLS_RECORD_BYTE_THRESHOLD) {
        dynamic_tls_record_size = SSL_DEF_TLS_RECORD_SIZE;
        Metrics::Counter::increment(ssl_rsb.total_dyn_def_tls_record_count);
      } else {
        dynamic_tls_record_size = SSL_MAX_TLS_RECORD_SIZE;
        Metrics::Counter::increment(ssl_rsb.total_dyn_max_tls_record_count);
      }
      if (l > dynamic_tls_record_size) {
        l = dynamic_tls_record_size;
      }
    }

    if (!l) {
      break;
    }

    try_to_write       = l;
    num_really_written = 0;
    Dbg(dbg_ctl_v_ssl, "b=%p l=%" PRId64, current_block, l);
    err = this->_ssl_write_buffer(current_block, l, num_really_written);

    // We wrote all that we thought we should
    if (num_really_written > 0) {
      total_written += num_really_written;
      buf.reader()->consume(num_really_written);
    }

    Dbg(dbg_ctl_ssl, "try_to_write=%" PRId64 " written=%" PRId64 " total_written=%" PRId64, try_to_write, num_really_written,
        total_written);
    Metrics::Counter::increment(net_rsb.calls_to_write);
    // Stop pulling plaintext once enough ciphertext is queued for the transport. This
    // bounds _write_buf to ~the water mark plus one record and lets backpressure reach
    // the producer, instead of encrypting all staged plaintext into memory in one pull.
  } while (num_really_written == try_to_write && total_written < towrite && !_write_buf->high_water());

  if (total_written > 0) {
    sslLastWriteTime   = now;
    sslTotalBytesSent += total_written;
  }
  if (num_really_written > 0) {
    needs |= EVENTIO_WRITE;
  } else {
    switch (err) {
    case SSL_ERROR_NONE:
      Dbg(dbg_ctl_ssl, "SSL_write-SSL_ERROR_NONE");
      break;
    case SSL_ERROR_WANT_READ:
      needs              |= EVENTIO_READ;
      num_really_written  = -EAGAIN;
      Dbg(dbg_ctl_ssl_error, "SSL_write-SSL_ERROR_WANT_READ");
      break;
    case SSL_ERROR_WANT_WRITE:
      // The transport-bound wbio is a MIOBuffer that grows on demand and always absorbs
      // the whole record (see BIO_s_miobuffer), so SSL_write can never need a write retry.
      // WANT_WRITE here means the SSL library broke that assumption; fail loud rather than
      // silently mishandle it. The old same-pointer retry machinery (redoWriteSize) is gone
      // precisely because this is now unreachable.
      ink_release_assert(!"SSL_write returned WANT_WRITE; the MIOBuffer wbio must never refuse a write");
      break;
#ifdef SSL_ERROR_WANT_CLIENT_HELLO_CB
    case SSL_ERROR_WANT_CLIENT_HELLO_CB:
#endif
    case SSL_ERROR_WANT_X509_LOOKUP: {
      needs              |= EVENTIO_WRITE;
      num_really_written  = -EAGAIN;
      Dbg(dbg_ctl_ssl_error, "SSL_write-SSL_ERROR_WANT_X509_LOOKUP/CLIENT_HELLO_CB");
      break;
    }
    case SSL_ERROR_SYSCALL:
      // SSL_ERROR_SYSCALL is an IO error. errno is likely 0, so set EPIPE, as
      // we do with SSL_ERROR_SSL below, to indicate a connection error.
      num_really_written = -EPIPE;
      Metrics::Counter::increment(ssl_rsb.error_syscall);
      Dbg(dbg_ctl_ssl_error, "SSL_write-SSL_ERROR_SYSCALL");
      break;
    // end of stream
    case SSL_ERROR_ZERO_RETURN:
      num_really_written = -errno;
      Dbg(dbg_ctl_ssl_error, "SSL_write-SSL_ERROR_ZERO_RETURN");
      break;
    case SSL_ERROR_SSL:
    default: {
      // Treat SSL_ERROR_SSL as EPIPE error.
      num_really_written = -EPIPE;
      SSLVCDebug(this, "SSL_write-SSL_ERROR_SSL errno=%d", errno);
      Metrics::Counter::increment(ssl_rsb.error_ssl);
    } break;
    }
  }
  return num_really_written;
}

SSLNetVConnection::SSLNetVConnection()
  : _ssl{nullptr, SSL_free},
    _read_buf{make_resource(new_MIOBuffer(SSLConfigParams::ssl_misc_max_iobuffer_size_index), free_MIOBuffer)},
    _write_buf{make_resource(new_MIOBuffer(SSLConfigParams::ssl_misc_max_iobuffer_size_index), free_MIOBuffer)},
    _write_buf_reader{make_resource(_write_buf->alloc_reader(), [](IOBufferReader *r) { r->dealloc(); })}
{
  this->_set_service(static_cast<ALPNSupport *>(this));
  this->_set_service(static_cast<TLSBasicSupport *>(this));
  this->_set_service(static_cast<TLSEventSupport *>(this));
  this->_set_service(static_cast<TLSCertSwitchSupport *>(this));
  this->_set_service(static_cast<TLSEarlyDataSupport *>(this));
  this->_set_service(static_cast<TLSSNISupport *>(this));
  this->_set_service(static_cast<TLSSessionResumptionSupport *>(this));
  this->_set_service(static_cast<TLSTunnelSupport *>(this));

  // Bound the outbound ciphertext queue: encryption yields once this much enciphered
  // data is buffered for the transport (see _encrypt_data_for_transport), keeping
  // _write_buf small and propagating backpressure to the producer.
  this->_write_buf->water_mark = SSLConfigParams::ssl_write_buffer_water_mark;

  SET_HANDLER(&SSLNetVConnection::startEvent);
}

SSLNetVConnection::SSLNetVConnection(UnixNetVConnection *unvc) : SSLNetVConnection()
{
  _unvc = unvc;
}

void
SSLNetVConnection::do_io_close([[maybe_unused]] int lerrno)
{
  // A consumer may close right after queuing a final plaintext write (e.g. an HTTP/2 GOAWAY
  // frame) via do_io_write()+reenable(), without waiting for WRITE_COMPLETE. The graceful-close
  // drain below only looks at already-encrypted ciphertext, and the VIO sever just below discards
  // the plaintext, so that final write would otherwise be silently dropped. Encrypt it now,
  // synchronously and without signalling the consumer, before the sever and SSL_shutdown() below
  // (SSL_write() is invalid once SSL_shutdown() has run).
  if (lerrno == -1 && _unvc != nullptr && _transport_write_vio != nullptr && _transport_state != TransportState::TRANSPORT_ERROR &&
      getSSLHandShakeComplete() && _user_write_vio.op == VIO::WRITE && !_user_write_vio.is_disabled() &&
      _user_write_vio.ntodo() > 0) {
    MUTEX_TRY_LOCK(lock, _user_write_vio.mutex, this_ethread());
    if (lock.is_locked()) {
      int64_t total_plaintext_written = 0;
      int     needs                   = 0;
      _encrypt_data_for_transport(_user_write_vio.ntodo(), _user_write_vio.buffer, total_plaintext_written, needs);
      if (total_plaintext_written > 0) {
        _user_write_vio.ndone += total_plaintext_written;
      }
    }
  }

  // The consumer has detached: sever the user VIOs first, so no signal delivered after
  // this point -- the unwinding handshake error path, a terminated-state mainEvent
  // dispatch, a transport event during the close drain -- can reach a continuation that
  // may already be freed (the deferred close-drain below returns with the VC still
  // live). The transport VC does the same (UnixNetVConnection::do_io_close sets
  // op = NONE); _signal_user's null-cont branch absorbs the late signals.
  _user_read_vio.cont    = nullptr;
  _user_read_vio.op      = VIO::NONE;
  _user_read_vio.nbytes  = 0;
  _user_write_vio.cont   = nullptr;
  _user_write_vio.op     = VIO::NONE;
  _user_write_vio.nbytes = 0;
  _write_rearm_pending   = false; // no consumer left to rearm for
  // The consumer has now requested the close -- this is what authorizes the physical free
  // (consumer-driven teardown; see _reclaimIfClosed). Whether the free happens inline here, on a
  // reclaim unwind, or at drain completion, it happens because of THIS call, not an error state.
  _close_requested = true;

  if (this->_ssl.get() != nullptr) {
    if (get_context() == NET_VCONNECTION_OUT) {
      callHooks(TS_EVENT_VCONN_OUTBOUND_CLOSE);
    } else {
      callHooks(TS_EVENT_VCONN_CLOSE);
    }

    if (getSSLHandShakeComplete()) {
      int shutdown_mode = SSL_get_shutdown(this->_ssl.get());
      Dbg(dbg_ctl_ssl_shutdown, "previous shutdown state 0x%x", shutdown_mode);
      int new_shutdown_mode = shutdown_mode | SSL_RECEIVED_SHUTDOWN;

      if (new_shutdown_mode != shutdown_mode) {
        // We do not need to sit around and wait for the client's close-notify if
        // they have not already sent it.  We will still be standards compliant
        Dbg(dbg_ctl_ssl_shutdown, "new SSL_set_shutdown 0x%x", new_shutdown_mode);
        SSL_set_shutdown(this->_ssl.get(), new_shutdown_mode);
      }

      // Send the close-notify unless the transport is broken. A peer that merely
      // half-closed its write side (TRANSPORT_CLOSED, set when the inner unvc fires
      // VC_EVENT_EOS) still has its read side open and expects the close-notify to
      // shut the TLS session down cleanly; skipping it leaves the peer's SSL_read at
      // an unexpected EOF, which (if it has shutdown(SHUT_WR)) makes it emit an alert
      // onto a closed write side -> EPIPE. Only a truly broken transport skips it.
      bool do_shutdown = _transport_state != TransportState::TRANSPORT_ERROR;

      if (do_shutdown) {
        // Send the close-notify. May synchronously invoke a registered hook (session-ticket),
        // which may itself call back into us.
        int ret;
        {
          RecursionGuard openssl_guard(recursion);
          ret = SSL_shutdown(this->_ssl.get());
        }
        Dbg(dbg_ctl_ssl_shutdown, "SSL_shutdown %s", (ret) ? "success" : "failed");
      } else {
        // Request a quiet shutdown to OpenSSL
        SSL_set_quiet_shutdown(this->_ssl.get(), 1);
        SSL_set_shutdown(this->_ssl.get(), SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);
        Dbg(dbg_ctl_ssl_shutdown, "Enable quiet shutdown");
      }
    }
  }

  EThread *t = this_ethread();

  // Graceful close of a layered (TLS-terminated) connection. The consumer typically closes
  // us re-entrantly from its WRITE_COMPLETE handler, which runs on the inner transport's
  // net_write_io stack. That net_write_io keeps running to its tail after this returns
  // (write_signal_and_update ignores handler return values), dereferencing _write_buf's
  // reader; and SSL_shutdown above may have queued a close-notify still to flush. Freeing
  // this VC (and that reader) inline here -- directly, or via _signal_user's
  // terminated-state teardown -- would crash that live net_write_io. So defer teardown to a
  // clean stack and let the transport flush any close-notify first. The peer may have
  // half-closed its write side (TRANSPORT_CLOSED) while still reading our response; only a
  // truly broken transport (TRANSPORT_ERROR) skips the drain and tears down inline.
  if (lerrno == -1 && _unvc != nullptr && _transport_write_vio != nullptr && _transport_state != TransportState::TRANSPORT_ERROR) {
    _sslState = SslState::SHUTDOWN_IN_PROGRESS; // == draining; see _isDraining()
    if (_write_buf_reader && _write_buf_reader->read_avail() > 0) {
      Dbg(dbg_ctl_ssl, "SSLNetVConnection::do_io_close: draining %" PRId64 " buffered bytes before close vc %p",
          _write_buf_reader->read_avail(), this);
      _transport_write_vio->reenable();
    }
    if (!_deferred_work_pending()) {
      _deferred_work_event = t->schedule_imm(this);
    }
    return;
  }

  // Whether it's safe to free this VC right now, rather than on `lerrno` (which only ever
  // reflects why the caller is closing us, not whether it's safe to act). _freeBlocked() covers
  // the hazards that make an inline free unsafe: still nested in _signal_user's own call to a
  // consumer (its unwind will free us instead -- see below) or inside an OpenSSL callback frame
  // (e.g. a plugin calling TSVConnAbort(vc, error) from an SSL hook mid SSL_accept()/
  // SSL_connect()) that must not have its _ssl freed out from under it (recursion), a hook mid
  // invocation (is_invoked_state), or a hook parked with a live plugin ref (_hook_parked) -- a
  // TSVConnAbort/close arriving while a hook is parked must not free the VC before the plugin's
  // reenable. When blocked, the deferred dispatch below completes the free via _reclaimIfClosed
  // once the frame unwinds / the plugin reenables.
  bool close_inline = !_freeBlocked() && this->mutex->thread_holding == t;

  Dbg(dbg_ctl_ssl, "SSLNetVConnection::do_io_close: terminating (%s).", lerrno == -1 ? "close" : "abort");
  _sslState = SslState::TERMINATED;

  if (close_inline) {
    this->free_thread(t);
  } else if (!_deferred_work_pending()) {
    // Not safe to free inline. If we're nested in _signal_user's own reentrancy, its unwind's
    // _reclaimIfClosed will free us first and the destructor will harmlessly cancel this scheduled
    // dispatch. If we're nested in an OpenSSL frame instead, nothing else will free us -- the
    // scheduled dispatch's _close_requested branch does it once that frame has returned.
    _deferred_work_event = t->schedule_imm(this);
  }
}

void
SSLNetVConnection::free_thread(EThread *t)
{
  if (from_accept_thread) {
    sslNetVCAllocator.free(this);
  } else {
    THREAD_FREE(this, sslNetVCAllocator, t);
  }
}

SSLNetVConnection::~SSLNetVConnection()
{
  // Cancel any pending out-of-line read drive so it does not fire on freed memory.
  if (_deferred_work_event != nullptr) {
    _deferred_work_event->cancel();
    _deferred_work_event = nullptr;
  }

  if (_is_tunnel_endpoint) {
    ink_assert(get_context() != NET_VCONNECTION_UNSET);

    Metrics::Gauge::decrement(([&]() -> Metrics::Gauge::AtomicType * {
      if (get_context() == NET_VCONNECTION_IN) {
        switch (get_tunnel_type()) {
        case SNIRoutingType::BLIND:
          return net_rsb.tunnel_current_client_connections_tls_tunnel;
        case SNIRoutingType::FORWARD:
          return net_rsb.tunnel_current_client_connections_tls_forward;
        case SNIRoutingType::PARTIAL_BLIND:
          return net_rsb.tunnel_current_client_connections_tls_partial_blind;
        default:
          return net_rsb.tunnel_current_client_connections_tls_http;
        }
      }
      // NET_VCONNECTION_OUT - Never a tunnel type for out (to server) context.
      ink_assert(get_tunnel_type() == SNIRoutingType::NONE);

      return net_rsb.tunnel_current_server_connections_tls;
    })());
  }

#if TS_HAS_TLS_EARLY_DATA
  if (_early_data_reader != nullptr) {
    _early_data_reader->dealloc();
  }

  if (_early_data_buf != nullptr) {
    free_MIOBuffer(_early_data_buf);
  }

  _early_data_reader = nullptr;
  _early_data_buf    = nullptr;
#endif

  // clear variables for reuse
  this->mutex.clear();
  _connect_action = nullptr;
  _user_read_vio.mutex.clear();
  _user_read_vio.cont = nullptr;
  _user_write_vio.mutex.clear();
  _user_write_vio.cont = nullptr;
  if (netvc_context == NET_VCONNECTION_OUT) {
    _user_read_vio.buffer.clear();
    _user_write_vio.buffer.clear();
  }
  got_remote_addr = false;
  got_local_addr  = false;
  attributes      = 0;
  options.reset();
  _sslState = SslState::HANDSHAKING;

  netvc_context = NET_VCONNECTION_UNSET;
  ink_assert(!link.next && !link.prev);

  _ca_cert_file.reset();
  _ca_cert_dir.reset();

  // SSL_SESSION_free() must only be called for SSL_SESSION objects,
  // for which the reference count was explicitly incremented (e.g.
  // by calling SSL_get1_session(), see SSL_get_session(3)) or when
  // the SSL_SESSION object was generated outside a TLS handshake
  // operation, e.g. by using d2i_SSL_SESSION(3). It must not be called
  // on other SSL_SESSION objects, as this would cause incorrect
  // reference counts and therefore program failures.
  // Since we created the shared pointer with a custom deleter,
  // resetting here will decrement the ref-counter.
  client_sess.reset();

  _ssl = nullptr;

  ALPNSupport::clear();
  TLSBasicSupport::clear();
  TLSEventSupport::clear();
  TLSSessionResumptionSupport::clear();
  TLSSNISupport::_clear();
  TLSTunnelSupport::_clear();
  TLSCertSwitchSupport::_clear();

  hookOpRequested = SslVConnOp::SSL_HOOK_OP_DEFAULT;
  free_handshake_buffers();

  if (_unvc != nullptr) {
    // Close the transport under its NetHandler's lock when we can take it (same thread,
    // not contended) so UnixNetVConnection::do_io_close closes the fd inline
    // (close_inline requires nh->mutex held). This teardown usually runs from a
    // scheduled dispatch outside the NetHandler, where the fd close would otherwise be
    // deferred to the InactivityCop's next 1-second sweep -- holding the socket open up
    // to ~1s after the consumer abandoned the connection (master closes it inline on
    // its signal unwind), which the peer observes (e.g. a connect-retry storm sees
    // different errnos). If the lock is unavailable the close still defers to the cop.
    if (_unvc->nh != nullptr && _unvc->nh->thread == this_ethread()) {
      MUTEX_TRY_LOCK(lock, _unvc->nh->mutex, this_ethread());
      _unvc->do_io_close();
    } else {
      _unvc->do_io_close();
    }
    _unvc = nullptr;
  }
}

int
SSLNetVConnection::sslStartHandShake(int event, int &err)
{
  if (TSSystemState::is_ssl_handshaking_stopped()) {
    Dbg(dbg_ctl_ssl, "Stopping handshake due to server shutting down.");
    return EVENT_ERROR;
  }
  // The handshake begin time and its inactivity timeout are recorded/installed together in
  // _trackFirstHandshake(), which every caller runs before reaching here.
  SSLConfig::scoped_config params;
  switch (event) {
  case SSL_EVENT_SERVER:
    if (this->_ssl.get() == nullptr) {
      SSLCertificateConfig::scoped_config lookup;
      IpEndpoint                          dst;
      int                                 namelen = sizeof(dst);
      if (0 != safe_getsockname(this->get_socket(), &dst.sa, &namelen)) {
        Dbg(dbg_ctl_ssl, "Failed to get dest ip, errno = [%d]", errno);
        return EVENT_ERROR;
      }
      SSLCertContext *cc = lookup->find(dst);
      if (dbg_ctl_ssl.on()) {
        IpEndpoint          src;
        ip_port_text_buffer ipb1, ipb2;
        int                 ip_len = sizeof(src);

        if (0 != safe_getpeername(this->get_socket(), &src.sa, &ip_len)) {
          DbgPrint(dbg_ctl_ssl, "Failed to get src ip, errno = [%d]", errno);
          return EVENT_ERROR;
        }
        ats_ip_nptop(&dst, ipb1, sizeof(ipb1));
        ats_ip_nptop(&src, ipb2, sizeof(ipb2));
        DbgPrint(dbg_ctl_ssl, "IP context is %p for [%s] -> [%s], default context %p", cc, ipb2, ipb1, lookup->defaultContext());
      }

      // Escape if this is marked to be a tunnel.
      // No data has been read at this point, so we can go
      // directly into blind tunnel mode

      if (cc && SSLCertContextOption::OPT_TUNNEL == cc->opt) {
        if (this->is_transparent) {
          this->attributes = HttpProxyPort::TRANSPORT_BLIND_TUNNEL;
          _sslState        = SslState::HANDSHAKE_DONE;
          this->_ssl       = nullptr;
          return EVENT_DONE;
        } else {
          hookOpRequested = SslVConnOp::SSL_HOOK_OP_TUNNEL;
        }
      }

      // Attach the default SSL_CTX to this SSL session. The default context is never going to be able
      // to negotiate a SSL session, but it's enough to trampoline us into the SNI callback where we
      // can select the right server certificate.
      this->_make_ssl_connection(lookup->defaultContext());
    }

    if (this->_ssl.get() == nullptr) {
      SSLErrorVC(this, "failed to create SSL server session");
      return EVENT_ERROR;
    }
    return sslServerHandShakeEvent(err);

  case SSL_EVENT_CLIENT:

    char buff[INET6_ADDRSTRLEN];

    if (this->_ssl.get() == nullptr) {
      // Making the check here instead of later, so we only
      // do this setting immediately after we create the SSL object
      SNIConfig::scoped_config sniParam;
      const char              *serverKey = this->options.sni_servername;
      if (!serverKey) {
        ats_ip_ntop(this->get_remote_addr(), buff, INET6_ADDRSTRLEN);
        serverKey = buff;
      }
      auto           nps       = sniParam->get_property_config(serverKey);
      shared_SSL_CTX sharedCTX = nullptr;
      SSL_CTX       *clientCTX = nullptr;
      std::string    caCertPathStorage;
      const char    *caCertPath = resolve_client_ca_cert_path(params, options.ssl_client_ca_cert_path, caCertPathStorage);

      // First Look to see if there are override parameters
      Dbg(dbg_ctl_ssl, "Checking for outbound client cert override [%p]", options.ssl_client_cert_name.get());
      if (options.ssl_client_cert_name) {
        std::string certFilePath;
        std::string keyFilePath;
        std::string caCertFilePath;
        // Enable override to explicitly disable the client certificate. That is, don't fill
        // in any of the cert paths if the cert file name is empty or "NULL".
        if (*options.ssl_client_cert_name != '\0' && 0 != strcasecmp("NULL", options.ssl_client_cert_name)) {
          certFilePath = Layout::get()->relative_to(params->clientCertPathOnly, options.ssl_client_cert_name.get());
          if (options.ssl_client_private_key_name) {
            keyFilePath = Layout::get()->relative_to(params->clientKeyPathOnly, options.ssl_client_private_key_name);
          }
          if (options.ssl_client_ca_cert_name) {
            caCertFilePath = Layout::get()->relative_to(caCertPath, options.ssl_client_ca_cert_name);
          }
          Dbg(dbg_ctl_ssl, "Using outbound client cert `%s'", options.ssl_client_cert_name.get());
        } else {
          Dbg(dbg_ctl_ssl, "Clearing outbound client cert");
        }
        sharedCTX = params->getCTX(certFilePath, keyFilePath,
                                   caCertFilePath.empty() ? params->clientCACertFilename : caCertFilePath.c_str(), caCertPath);
      } else if (options.ssl_client_ca_cert_name || options.ssl_client_ca_cert_path) {
        std::string caCertFilePath;
        if (options.ssl_client_ca_cert_name) {
          caCertFilePath = Layout::get()->relative_to(caCertPath, options.ssl_client_ca_cert_name);
        }
        sharedCTX = params->getCTX(params->clientCertPath, params->clientKeyPath,
                                   caCertFilePath.empty() ? params->clientCACertFilename : caCertFilePath.c_str(), caCertPath);
      } else if (nps && !nps->client_cert_file.empty()) {
        // If no overrides available, try the available nextHopProperty by reading from context mappings
        sharedCTX =
          params->getCTX(nps->client_cert_file, nps->client_key_file, params->clientCACertFilename, params->clientCACertPath);
      } else { // Just stay with the values passed down from the SM for verify
        clientCTX = params->client_ctx.get();
      }

      if (sharedCTX) {
        clientCTX = sharedCTX.get();
      }

      if (options.verifyServerPolicy != YamlSNIConfig::Policy::UNSET) {
        // Stay with conf-override version as the highest priority
      } else if (nps && nps->verify_server_policy != YamlSNIConfig::Policy::UNSET) {
        options.verifyServerPolicy = nps->verify_server_policy;
      } else {
        options.verifyServerPolicy = params->verifyServerPolicy;
      }

      if (options.verifyServerProperties != YamlSNIConfig::Property::UNSET) {
        // Stay with conf-override version as the highest priority
      } else if (nps && nps->verify_server_properties != YamlSNIConfig::Property::UNSET) {
        options.verifyServerProperties = nps->verify_server_properties;
      } else {
        options.verifyServerProperties = params->verifyServerProperties;
      }

      if (!clientCTX) {
        SSLErrorVC(this, "failed to create SSL client session");
        return EVENT_ERROR;
      }

      this->_make_ssl_connection(clientCTX);
      if (this->_ssl.get() == nullptr) {
        SSLErrorVC(this, "failed to create SSL client session");
        return EVENT_ERROR;
      }

      // If it is negative, we are consciously not setting ALPN (e.g. for private server sessions)
      if (options.alpn_protocols_array_size >= 0) {
        if (options.alpn_protocols_array_size > 0) {
          SSL_set_alpn_protos(this->_ssl.get(), options.alpn_protocols_array, options.alpn_protocols_array_size);
        } else if (params->alpn_protocols_array_size > 0) {
          // Set the ALPN protocols we are requesting.
          SSL_set_alpn_protos(this->_ssl.get(), params->alpn_protocols_array, params->alpn_protocols_array_size);
        }
      }

      SSL_set_verify(this->_ssl.get(), SSL_VERIFY_PEER, verify_callback);

      // SNI
      ats_scoped_str &tlsext_host_name = this->options.sni_hostname ? this->options.sni_hostname : this->options.sni_servername;
      if (tlsext_host_name) {
        if (this->set_sni_server_name(this->_ssl.get(), tlsext_host_name)) {
          Dbg(dbg_ctl_ssl, "using SNI name '%s' for client handshake", tlsext_host_name.get());
        } else {
          Dbg(dbg_ctl_ssl_error, "failed to set SNI name '%s' for client handshake", tlsext_host_name.get());
          Metrics::Counter::increment(ssl_rsb.sni_name_set_failure);
        }
      }

      // ALPN
      if (!this->options.alpn_protos.empty()) {
        if (int res = SSL_set_alpn_protos(this->_ssl.get(), reinterpret_cast<const uint8_t *>(this->options.alpn_protos.data()),
                                          this->options.alpn_protos.size());
            res != 0) {
          Dbg(dbg_ctl_ssl_error, "failed to set ALPN '%.*s' for client handshake",
              static_cast<int>(this->options.alpn_protos.size()), this->options.alpn_protos.data());
        }
      }
    }

    return sslClientHandShakeEvent(err);

  default:
    ink_assert(0);
    return EVENT_ERROR;
  }
}

int
SSLNetVConnection::sslServerHandShakeEvent(int &err)
{
  // Continue on if we are in the invoked state.  The hook has not yet reenabled
  if (this->is_invoked_state()) {
    return SSL_WAIT_FOR_HOOK;
  }

  // Go do the preaccept hooks
  if (this->get_handshake_hook_state() == TLSEventSupport::SSLHandshakeHookState::HANDSHAKE_HOOKS_PRE) {
    if (this->invoke_tls_event() == 1) {
      return SSL_WAIT_FOR_HOOK;
    }
  }

  // If a blind tunnel was requested in the pre-accept calls, convert.
  // Again no data has been exchanged, so we can go directly
  // without data replay.
  // Note we can't arrive here if a hook is active.

  if (SslVConnOp::SSL_HOOK_OP_TUNNEL == hookOpRequested) {
    this->attributes = HttpProxyPort::TRANSPORT_BLIND_TUNNEL;
    this->_ssl       = nullptr;
    // Don't mark the handshake as complete yet,
    // Will be checking for that flag not being set after
    // we get out of this callback, and then will shuffle
    // over the buffered handshake packets to the O.S.
    return EVENT_DONE;
  } else if (SslVConnOp::SSL_HOOK_OP_TERMINATE == hookOpRequested) {
    _sslState = SslState::HANDSHAKE_DONE;
    return EVENT_DONE;
  }

  Dbg(dbg_ctl_ssl, "Go on with the handshake state=%s",
      TLSEventSupport::get_ssl_handshake_hook_state_name(this->get_handshake_hook_state()));

  // Strip any PROXY protocol header from the raw stream before SSL_accept (and before a
  // possible blind-tunnel replay of the buffered ClientHello). In the layered model the
  // handshake bytes are already buffered in _read_buf and read through independent
  // readers -- the rbio that SSL_accept consumes and handShakeHolder for the replay -- so
  // the header, parsed here via a throwaway reader, must be consumed from each of them.
  // (_parse_proxy_protocol self-guards on the version, so it parses at most once.)
  if (this->get_is_proxy_protocol() && this->get_proxy_protocol_version() == ProxyProtocolVersion::UNDEFINED) {
    auto    reader = make_resource(this->_read_buf->alloc_reader(), [](IOBufferReader *reader) { reader->dealloc(); });
    int64_t before = reader->read_avail();
    int     retval = this->_parse_proxy_protocol(reader.get());
    if (retval < 0) {
      if (retval == -EAGAIN) {
        // No data at the moment, hang tight
        SSLVCDebug(this, "Proxy protocol: need more data");
        return SSL_HANDSHAKE_WANT_READ;
      } else {
        // An error, make us go away
        SSLVCDebug(this, "Proxy protocol error: _parse_proxy_protocol() returned %d", retval);
        return EVENT_ERROR;
      }
    }
    if (int64_t consumed = before - reader->read_avail(); consumed > 0) {
      this->handShakeHolder->consume(consumed);
      miobuffer_consume(SSL_get_rbio(this->_ssl.get()), consumed);
    }
  }

  if (this->handShakeHolder != nullptr && !this->handShakeHolder->is_read_avail_more_than(0)) {
    Dbg(dbg_ctl_ssl, "%p first read\n", this);
  }
#if TS_USE_TLS_ASYNC
  // SSL_MODE_ASYNC must be set before the SSL_accept that runs the engine's private-key
  // operation so the op executes inside an OpenSSL async job (suspending with
  // SSL_ERROR_WANT_ASYNC instead of blocking the event thread). The mode is sticky and
  // idempotent, and this is the server (inbound) handshake path. The previous gate on an
  // empty handShakeHolder never fired in the layered model -- the ClientHello is
  // pre-buffered into the holder for blind-tunnel replay, so it is never empty here --
  // which left async mode disabled and ran the private-key op synchronously.
  if (SSLConfigParams::async_handshake_enabled) {
    SSL_set_mode(this->_ssl.get(), SSL_MODE_ASYNC);
  }
#endif

  ssl_error_t ssl_error = this->_ssl_accept();
#if TS_USE_TLS_ASYNC
  if (ssl_error == SSL_ERROR_WANT_ASYNC) {
    // Do we need to set up the async eventfd?  Or is it already registered?
    if (async_ep.fd < 0) {
      size_t numfds;
      // Set up the epoll entry for the signalling
      if (SSL_get_all_async_fds(this->_ssl.get(), nullptr, &numfds) && numfds > 0) {
        // A TLS handshake is a single OpenSSL ASYNC_JOB whose wait-ctx fd is stable across
        // re-suspensions, and standard engines expose exactly one fd; AsyncTLSEventIO/EventIO
        // tracks a single fd, so register once (gated on async_ep.fd < 0) and reuse it. The
        // registration copies the fd, so the storage need not outlive this block.
        std::vector<OSSL_ASYNC_FD> waitfds(numfds);
        if (SSL_get_all_async_fds(this->_ssl.get(), waitfds.data(), &numfds) && numfds > 0) {
          ink_assert(numfds == 1);
          PollDescriptor *pd = get_PollDescriptor(this_ethread());
          this->async_ep.start(pd, {waitfds.data(), numfds});
        }
      }
    }
  } else if (SSLConfigParams::async_handshake_enabled) {
    // Make sure the net fd read vio is in the right state
    if (ssl_error == SSL_ERROR_WANT_READ) {
      _transport_read_vio->reenable();
    }
  }
#endif
  if (ssl_error != SSL_ERROR_NONE) {
    err = errno;
    SSLVCDebug(this, "SSL handshake error: %s (%d), errno=%d", SSLErrorName(ssl_error), ssl_error, err);

    // Sniff the first raw byte the client sent to tell a real ClientHello (0x16) from plain
    // HTTP (allow-plain / tr-pass). Read it through handShakeHolder, whose position IS the byte
    // that would be replayed to a plain/tunnel successor: _read_buf->buf() returns the write
    // block's base, which after a stripped PROXY header (consumed from the holder above) is the
    // header's first byte, not the client's. The holder != nullptr guard also means we never
    // sniff after _commitInboundHandshake has released it -- once TLS is committed the head
    // block recycles and buf()[0] would be mid-stream ciphertext, which could spuriously arm a
    // DOWNGRADE_PLAIN whose executor dereferences the (now null) holder.
    if (handShakeHolder != nullptr && handShakeHolder->is_read_avail_more_than(0)) {
      char *buf = handShakeHolder->start();
      if (buf && *buf != SSL_OP_HANDSHAKE) {
        SSLVCDebug(this, "SSL hanshake error with bad HS buffer");
        if (getAllowPlain()) {
          SSLVCDebug(this, "Try plain");
          // The leading bytes are not a ClientHello: convert this connection to a UnixNetVC and
          // hand the buffered packet to HTTP processing. _downgradeToPlain() frees this VC, and we
          // are on the handshake read stack that still dereferences `this` after we return, so defer
          // it out of line to a clean mainEvent dispatch -- the same handoff the blind tunnel uses.
          _pending_handoff = PendingHandoff::DOWNGRADE_PLAIN;
          if (_transport_read_vio != nullptr) {
            _transport_read_vio->disable();
          }
          if (!_deferred_work_pending()) {
            _deferred_work_event = this_ethread()->schedule_imm(this);
          }
          return SSL_RESTART;
        } else if (getTransparentPassThrough()) {
          // start a blind tunnel if tr-pass is set and data does not look like ClientHello
          SSLVCDebug(this, "Data does not look like SSL handshake, starting blind tunnel");
          this->attributes = HttpProxyPort::TRANSPORT_BLIND_TUNNEL;
          return EVENT_CONT;
        } else {
          SSLVCDebug(this, "Give up");
        }
      }
    }
  }

  switch (ssl_error) {
  case SSL_ERROR_NONE:
    if (dbg_ctl_ssl.on()) {
#ifdef OPENSSL_IS_OPENSSL3
      X509 *cert = SSL_get1_peer_certificate(this->_ssl.get());
#else
      X509 *cert = SSL_get_peer_certificate(this->_ssl.get());
#endif

      DbgPrint(dbg_ctl_ssl, "SSL server handshake completed successfully");
      if (cert) {
        debug_certificate_name("client certificate subject CN is", X509_get_subject_name(cert));
        debug_certificate_name("client certificate issuer CN is", X509_get_issuer_name(cert));
        X509_free(cert);
      }
    }

    _sslState = SslState::HANDSHAKE_DONE;

    if (this->get_tls_handshake_begin_time()) {
      this->_record_tls_handshake_end_time();
      this->_update_end_of_handshake_stats();
    }

    // We're fully SSL now, so we can throw away the downgrade buffer (the read-path handshake
    // driver may already have released it once ClientHello/SNI processing was past -- see
    // _releaseHandshakeReader).
    if (this->handShakeHolder != nullptr) {
      this->handShakeHolder->dealloc();
      this->handShakeHolder = nullptr;
    }

    if (this->get_tunnel_type() != SNIRoutingType::NONE) {
      // Foce to use HTTP/1.1 endpoint for SNI Routing
      if (!this->setSelectedProtocol(reinterpret_cast<const unsigned char *>(IP_PROTO_TAG_HTTP_1_1.data()),
                                     IP_PROTO_TAG_HTTP_1_1.size())) {
        return EVENT_ERROR;
      }
    }

    {
      const unsigned char *proto = nullptr;
      unsigned             len   = 0;

      increment_ssl_version_metric(SSL_version(this->_ssl.get()));

      // If it's possible to negotiate both NPN and ALPN, then ALPN
      // is preferred since it is the server's preference.  The server
      // preference would not be meaningful if we let the client
      // preference have priority.
      SSL_get0_alpn_selected(this->_ssl.get(), &proto, &len);
      if (len == 0) {
        SSL_get0_next_proto_negotiated(this->_ssl.get(), &proto, &len);
      }

      if (len) {
        if (this->get_tunnel_type() == SNIRoutingType::NONE && !this->setSelectedProtocol(proto, len)) {
          return EVENT_ERROR;
        }
        this->set_negotiated_protocol_id({reinterpret_cast<const char *>(proto), static_cast<size_t>(len)});

        Dbg(dbg_ctl_ssl, "Origin selected next protocol '%.*s'", len, proto);
      } else {
        Dbg(dbg_ctl_ssl, "Origin did not select a next protocol");
      }
    }

#if TS_USE_TLS_ASYNC
    if (SSLConfigParams::async_handshake_enabled) {
      SSL_clear_mode(this->_ssl.get(), SSL_MODE_ASYNC);
      if (async_ep.fd >= 0) {
        async_ep.stop();
      }
    }
#endif
    return EVENT_DONE;

  case SSL_ERROR_WANT_CONNECT:
    return SSL_HANDSHAKE_WANT_CONNECT;

  case SSL_ERROR_WANT_WRITE:
    return SSL_HANDSHAKE_WANT_WRITE;

  case SSL_ERROR_WANT_READ:
    return SSL_HANDSHAKE_WANT_READ;
#ifdef SSL_ERROR_WANT_CLIENT_HELLO_CB
  case SSL_ERROR_WANT_CLIENT_HELLO_CB:
    // A TS_SSL_CLIENT_HELLO hook parked (SSL_accept suspended in the client-hello callback).
    // Unlike the SSL_WAIT_FOR_HOOK paths this returns EVENT_CONT, so the read/write drivers never
    // see a park to latch -- arm the parked-hook hold here so a consumer-driven close cannot free
    // the VC before the plugin reenables. Keyed on is_invoked_state() (the client-hello park sets
    // HANDSHAKE_HOOKS_CLIENT_HELLO_INVOKE) so a non-park RETRY does not falsely latch.
    if (this->is_invoked_state()) {
      _hook_parked = true;
    }
    return EVENT_CONT;
#endif
// This value is only defined in openssl has been patched to
// enable the sni callback to break out of the SSL_accept processing
#ifdef SSL_ERROR_WANT_SNI_RESOLVE
  case SSL_ERROR_WANT_X509_LOOKUP:
    return EVENT_CONT;
  case SSL_ERROR_WANT_SNI_RESOLVE:
#elif SSL_ERROR_WANT_X509_LOOKUP
  case SSL_ERROR_WANT_X509_LOOKUP:
#endif
#ifdef SSL_ERROR_PENDING_CERTIFICATE
  case SSL_ERROR_PENDING_CERTIFICATE:
#endif
#if defined(SSL_ERROR_WANT_SNI_RESOLVE) || defined(SSL_ERROR_WANT_X509_LOOKUP) || defined(SSL_ERROR_PENDING_CERTIFICATE)
    if (this->attributes == HttpProxyPort::TRANSPORT_BLIND_TUNNEL || SslVConnOp::SSL_HOOK_OP_TUNNEL == hookOpRequested) {
      this->attributes = HttpProxyPort::TRANSPORT_BLIND_TUNNEL;
      return EVENT_CONT;
    } else {
      //  Stopping for some other reason, perhaps loading certificate
      return SSL_WAIT_FOR_HOOK;
    }
#endif

#if TS_USE_TLS_ASYNC
  case SSL_ERROR_WANT_ASYNC:
    Metrics::Counter::increment(ssl_rsb.error_async);
    return SSL_WAIT_FOR_ASYNC;
#endif

  case SSL_ERROR_WANT_ACCEPT:
    return EVENT_CONT;

  case SSL_ERROR_SSL: {
    SSLVCDebug(this, "SSLNetVConnection::sslServerHandShakeEvent, SSL_ERROR_SSL errno=%d", errno);
    return EVENT_ERROR;
  }

  case SSL_ERROR_ZERO_RETURN:
    return EVENT_ERROR;
  case SSL_ERROR_SYSCALL:
    return EVENT_ERROR;
  default:
    return EVENT_ERROR;
  }
}

int
SSLNetVConnection::sslClientHandShakeEvent(int &err)
{
  ssl_error_t ssl_error;

  ink_assert(TLSBasicSupport::getInstance(this->_ssl.get()) == this);

  // Initialize properly for a client connection
  if (this->get_handshake_hook_state() == TLSEventSupport::SSLHandshakeHookState::HANDSHAKE_HOOKS_PRE) {
    if (this->pp_info.version != ProxyProtocolVersion::UNDEFINED) {
      // Outbound PROXY Protocol. The v1/v2 preamble must reach the origin as cleartext,
      // ahead of the TLS ClientHello. SSL_write would encrypt it, so copy the preamble
      // straight into _write_buf (the transport-bound buffer) before _ssl_connect() appends
      // the ClientHello; the transport then drains [PROXY header][ClientHello...] in order.
      // (Master writes it raw via super::load_buffer_and_write; this is the layered
      // equivalent now that the SSL VC no longer is-a UnixNetVConnection.)
      VIO    &vio     = this->_user_write_vio;
      int64_t towrite = std::min(vio.ntodo(), vio.get_reader()->read_avail());

      if (towrite > 0) {
        int64_t written = _write_buf->write(vio.get_reader(), towrite);
        vio.get_reader()->consume(written);
        vio.ndone += written;
      }
      if (vio.ntodo() != 0) {
        // Preamble not fully buffered yet; the caller flushes _write_buf, then re-drives
        // the handshake (still in HANDSHAKE_HOOKS_PRE) to write the remainder.
        return SSL_WAIT_FOR_HOOK;
      }
    }

    this->set_handshake_hook_state(TLSEventSupport::SSLHandshakeHookState::HANDSHAKE_HOOKS_OUTBOUND_PRE);
  }

  // Do outbound hook processing here
  // Continue on if we are in the invoked state.  The hook has not yet reenabled
  if (this->is_invoked_state()) {
    return SSL_WAIT_FOR_HOOK;
  }

  // Go do the preaccept hooks
  if (this->get_handshake_hook_state() == TLSEventSupport::SSLHandshakeHookState::HANDSHAKE_HOOKS_OUTBOUND_PRE) {
    if (this->invoke_tls_event() == 1) {
      return SSL_WAIT_FOR_HOOK;
    }
  }

  ssl_error = this->_ssl_connect();
  switch (ssl_error) {
  case SSL_ERROR_NONE:
    if (dbg_ctl_ssl.on()) {
#ifdef OPENSSL_IS_OPENSSL3
      X509 *cert = SSL_get1_peer_certificate(this->_ssl.get());
#else
      X509 *cert = SSL_get_peer_certificate(this->_ssl.get());
#endif

      DbgPrint(dbg_ctl_ssl, "SSL client handshake completed successfully");

      if (cert) {
        debug_certificate_name("server certificate subject CN is", X509_get_subject_name(cert));
        debug_certificate_name("server certificate issuer CN is", X509_get_issuer_name(cert));
        X509_free(cert);
      }
    }
    {
      unsigned char const *proto = nullptr;
      unsigned int         len   = 0;
      // Make note of the negotiated protocol
      SSL_get0_alpn_selected(this->_ssl.get(), &proto, &len);
      if (len == 0) {
        SSL_get0_next_proto_negotiated(this->_ssl.get(), &proto, &len);
      }
      Dbg(dbg_ctl_ssl_alpn, "Negotiated ALPN: %.*s", len, proto);
      this->set_negotiated_protocol_id({reinterpret_cast<const char *>(proto), static_cast<size_t>(len)});
    }

    Metrics::Counter::increment(ssl_rsb.total_success_handshake_count_out);

    _sslState = SslState::HANDSHAKE_DONE;
    return EVENT_DONE;

  case SSL_ERROR_WANT_WRITE:
    Dbg(dbg_ctl_ssl_error, "SSL_ERROR_WANT_WRITE");
    return SSL_HANDSHAKE_WANT_WRITE;

  case SSL_ERROR_WANT_READ:
    Dbg(dbg_ctl_ssl_error, "SSL_ERROR_WANT_READ");
    return SSL_HANDSHAKE_WANT_READ;
#ifdef SSL_ERROR_WANT_CLIENT_HELLO_CB
  case SSL_ERROR_WANT_CLIENT_HELLO_CB:
    Dbg(dbg_ctl_ssl_error, "SSL_ERROR_WANT_CLIENT_HELLO_CB");
    break;
#endif
  case SSL_ERROR_WANT_X509_LOOKUP:
    Dbg(dbg_ctl_ssl_error, "SSL_ERROR_WANT_X509_LOOKUP");
    break;

  case SSL_ERROR_WANT_ACCEPT:
    return SSL_HANDSHAKE_WANT_ACCEPT;

  case SSL_ERROR_WANT_CONNECT:
    break;

  case SSL_ERROR_ZERO_RETURN:
    Dbg(dbg_ctl_ssl_error, "EOS");
    return EVENT_ERROR;

  case SSL_ERROR_SYSCALL:
    err = errno;
    Metrics::Counter::increment(ssl_rsb.error_syscall);
    Dbg(dbg_ctl_ssl_error, "syscall");
    return EVENT_ERROR;
    break;

  case SSL_ERROR_SSL:
  default: {
    err = (errno) ? errno : -ENET_SSL_CONNECT_FAILED;
    char          buf[512];
    unsigned long e = ERR_peek_last_error();
    ERR_error_string_n(e, buf, sizeof(buf));
    // FIXME -- This triggers a retry on cases of cert validation errors...
    SSLVCDebug(this, "SSL_ERROR_SSL errno=%d", errno);
    Metrics::Counter::increment(ssl_rsb.error_ssl);
    Dbg(dbg_ctl_ssl_error, "SSL_ERROR_SSL");
    if (e) {
      if (this->options.sni_servername) {
        Dbg(dbg_ctl_ssl_error, "SSL connection failed for '%s': %s", this->options.sni_servername.get(), buf);
      } else {
        char buff[INET6_ADDRSTRLEN];
        ats_ip_ntop(this->get_remote_addr(), buff, INET6_ADDRSTRLEN);
        Dbg(dbg_ctl_ssl_error, "SSL connection failed for '%s': %s", buff, buf);
      }
    }
    return EVENT_ERROR;
  } break;
  }
  return EVENT_CONT;
}

void
SSLNetVConnection::reenable_with_event(int event)
{
  if (event != TS_EVENT_ERROR && event != TS_EVENT_CONTINUE) {
    Error("SSLNetVConnection::reenable_with_event called with invalid event: %d", event);
  }

  if (event == TS_EVENT_ERROR) {
    if (_in_verify_hook) {
      // A verify hook (SSL_VERIFY_SERVER/CLIENT) reporting a bad certificate. This is a verdict,
      // not a handshake termination: the verify policy decides (the OpenSSL verify callback returns
      // !enforce_mode), so ENFORCED fails the handshake via SSL_ERROR_SSL while PERMISSIVE continues.
      // Record the verdict only; do NOT latch the terminal _sslState/_fatal_pending, or the
      // terminated-state teardown paths would abort even a PERMISSIVE handshake that must complete.
      _verify_hook_failed = true;
    } else {
      // A hook failed the handshake: record it and keep iterating hooks (the remaining
      // hooks of the chain must still see their event). The failure reaches the consumer
      // exactly once, downstream: a synchronous reenable (hook callout mid-SSL_connect/
      // accept) via the unwinding handshake error path, an asynchronous one via the
      // scheduled dispatch's _fatal_pending branch in mainEvent. Signalling from here
      // would let the consumer tear us down while the hook chain is still running.
      _sslState      = SslState::TERMINATED;
      _fatal_pending = true;
    }
  }

  resume_tls_event();
  // The plugin has returned its reference; the parked-hook hold on the reclaim is released (the
  // teardown a consumer close started while this hook was parked can now complete).
  _hook_parked = false;

  if (invoke_tls_event() == 2) {
    _transport_write_vio->reenable();
  }

  // The handshake was suspended waiting for this hook. The peer's handshake
  // bytes were already consumed into the SSL read BIO, so reenabling the
  // transport read VIO alone will not re-drive SSL_do_handshake() when there is
  // no fresh socket data (e.g. a delayed cert/SNI/client-hello hook fires after
  // the ClientHello was already read). Schedule an out-of-line read-drive to
  // re-invoke the handshake, mirroring master's readReschedule()/net_read_io()
  // pass. Use the home thread: a plugin may reenable from any thread. mainEvent
  // tears the VC down here if the reenable carried an error (terminated state).
  if (!getSSLHandShakeComplete() && !_deferred_work_pending()) {
    _deferred_work_event = this->thread->schedule_imm(this);
  }

  _transport_read_vio->reenable();
}

Continuation *
SSLNetVConnection::getContinuationForTLSEvents()
{
  return this;
}

EThread *
SSLNetVConnection::getThreadForTLSEvents()
{
  return this->thread;
}

Ptr<ProxyMutex>
SSLNetVConnection::getMutexForTLSEvents()
{
  // Secondary lock for the ContWrapper that reschedules a TLS hook when the
  // plugin continuation's lock can't be taken immediately. Returning null (the
  // old stub) builds a ContWrapper with no mutex, which crashes when the event
  // system later locks it. Master used nh->mutex; the connection mutex is the
  // equivalent stable lock here.
  return this->mutex;
}

void
SSLNetVConnection::_in_context_tunnel()
{
  ink_assert(get_context() == NET_VCONNECTION_IN);

  Metrics::Counter::AtomicType *t;
  Metrics::Gauge::AtomicType   *c;

  switch (get_tunnel_type()) {
  case SNIRoutingType::BLIND:
    t = net_rsb.tunnel_total_client_connections_tls_tunnel;
    c = net_rsb.tunnel_current_client_connections_tls_tunnel;
    break;
  case SNIRoutingType::FORWARD:
    t = net_rsb.tunnel_total_client_connections_tls_forward;
    c = net_rsb.tunnel_current_client_connections_tls_forward;
    break;
  case SNIRoutingType::PARTIAL_BLIND:
    t = net_rsb.tunnel_total_client_connections_tls_partial_blind;
    c = net_rsb.tunnel_current_client_connections_tls_partial_blind;
    break;
  default:
    t = net_rsb.tunnel_total_client_connections_tls_http;
    c = net_rsb.tunnel_current_client_connections_tls_http;
    break;
  }
  Metrics::Counter::increment(t);
  Metrics::Gauge::increment(c);
}

void
SSLNetVConnection::_out_context_tunnel()
{
  ink_assert(get_context() == NET_VCONNECTION_OUT);

  // Never a tunnel type for out (to server) context.
  ink_assert(get_tunnel_type() == SNIRoutingType::NONE);

  Metrics::Counter::increment(net_rsb.tunnel_total_server_connections_tls);
  Metrics::Gauge::increment(net_rsb.tunnel_current_server_connections_tls);
}

void
SSLNetVConnection::increment_ssl_version_metric(int version) const
{
  switch (version) {
  case SSL3_VERSION:
    Metrics::Counter::increment(ssl_rsb.total_sslv3);
    break;
  case TLS1_VERSION:
    Metrics::Counter::increment(ssl_rsb.total_tlsv1);
    break;
  case TLS1_1_VERSION:
    Metrics::Counter::increment(ssl_rsb.total_tlsv11);
    break;
  case TLS1_2_VERSION:
    Metrics::Counter::increment(ssl_rsb.total_tlsv12);
    break;
#ifdef TLS1_3_VERSION
  case TLS1_3_VERSION:
    Metrics::Counter::increment(ssl_rsb.total_tlsv13);
    break;
#endif
  default:
    Dbg(dbg_ctl_ssl, "Unrecognized SSL version %d", version);
    break;
  }
}

std::string_view
SSLNetVConnection::map_tls_protocol_to_tag(const char *proto_string) const
{
  std::string_view retval{"tls/?.?"sv}; // return this if the protocol lookup doesn't work.

  if (proto_string) {
    // openSSL guarantees the case of the protocol string.
    if (proto_string[0] == 'T' && proto_string[1] == 'L' && proto_string[2] == 'S' && proto_string[3] == 'v' &&
        proto_string[4] == '1') {
      if (proto_string[5] == 0) {
        retval = IP_PROTO_TAG_TLS_1_0;
      } else if (proto_string[5] == '.' && proto_string[7] == 0) {
        switch (proto_string[6]) {
        case '1':
          retval = IP_PROTO_TAG_TLS_1_1;
          break;
        case '2':
          retval = IP_PROTO_TAG_TLS_1_2;
          break;
        case '3':
          retval = IP_PROTO_TAG_TLS_1_3;
          break;
        default:
          break;
        }
      }
    }
  }
  return retval;
}

int
SSLNetVConnection::populate_protocol(std::string_view *results, int n) const
{
  int retval = 0;
  if (n > retval) {
    results[retval] = map_tls_protocol_to_tag(this->get_tls_protocol_name());
    if (!results[retval].empty()) {
      ++retval;
    }
    if (n > retval) {
      retval += _unvc->populate_protocol(results + retval, n - retval);
    }
  }
  return retval;
}

const char *
SSLNetVConnection::protocol_contains(std::string_view prefix) const
{
  const char      *retval = nullptr;
  std::string_view tag    = map_tls_protocol_to_tag(this->get_tls_protocol_name());
  if (prefix.size() <= tag.size() && strncmp(tag.data(), prefix.data(), prefix.size()) == 0) {
    retval = tag.data();
  } else {
    retval = _unvc->protocol_contains(prefix);
  }
  return retval;
}

in_port_t
SSLNetVConnection::_get_local_port()
{
  return this->get_local_port();
}

bool
SSLNetVConnection::_isTryingRenegotiation() const
{
  if (SSLConfigParams::ssl_allow_client_renegotiation == false && this->getSSLHandShakeComplete()) {
    return true;
  } else {
    return false;
  }
}

shared_SSL_CTX
SSLNetVConnection::_lookupContextByName(const std::string &servername, SSLCertContextType ctxType)
{
  shared_SSL_CTX                      ctx = nullptr;
  SSLCertificateConfig::scoped_config lookup;
  SSLCertContext                     *cc = lookup->find(servername, ctxType);

  if (cc) {
    ctx = cc->getCtx();
  }

  if (cc && ctx && SSLCertContextOption::OPT_TUNNEL == cc->opt && this->get_is_transparent()) {
    this->attributes = HttpProxyPort::TRANSPORT_BLIND_TUNNEL;
    _sslState        = SslState::HANDSHAKE_DONE;
    return nullptr;
  } else {
    return ctx;
  }
}

shared_SSL_CTX
SSLNetVConnection::_lookupContextByIP()
{
  shared_SSL_CTX                      ctx = nullptr;
  SSLCertificateConfig::scoped_config lookup;
  IpEndpoint                          ip;
  int                                 namelen = sizeof(ip);

  // Return null if this vc is already configured as a tunnel
  if (this->attributes == HttpProxyPort::TRANSPORT_BLIND_TUNNEL) {
    return nullptr;
  }

  SSLCertContext *cc = nullptr;
  if (this->get_is_proxy_protocol() && this->get_proxy_protocol_version() != ProxyProtocolVersion::UNDEFINED) {
    ip.sa = *(this->get_proxy_protocol_dst_addr());
    ip_port_text_buffer ipb1;
    ats_ip_nptop(&ip, ipb1, sizeof(ipb1));
    cc = lookup->find(ip);
    if (dbg_ctl_proxyprotocol.on()) {
      IpEndpoint          src;
      ip_port_text_buffer ipb2;
      int                 ip_len = sizeof(src);

      if (0 != safe_getpeername(this->get_socket(), &src.sa, &ip_len)) {
        DbgPrint(dbg_ctl_proxyprotocol, "Failed to get src ip, errno = [%d]", errno);
        return nullptr;
      }
      ats_ip_nptop(&src, ipb2, sizeof(ipb2));
      DbgPrint(dbg_ctl_proxyprotocol, "IP context is %p for [%s] -> [%s], default context %p", cc, ipb2, ipb1,
               lookup->defaultContext());
    }
  } else if (0 == safe_getsockname(this->get_socket(), &ip.sa, &namelen)) {
    cc = lookup->find(ip);
  }
  if (cc) {
    ctx = cc->getCtx();
  }

  return ctx;
}

void
SSLNetVConnection::set_ca_cert_file(std::string_view file, std::string_view dir)
{
  if (file.size()) {
    char *n = new char[file.size() + 1];
    std::memcpy(n, file.data(), file.size());
    n[file.size()] = '\0';
    _ca_cert_file.reset(n);
  }
  if (dir.size()) {
    char *n = new char[dir.size() + 1];
    std::memcpy(n, dir.data(), dir.size());
    n[dir.size()] = '\0';
    _ca_cert_dir.reset(n);
  }
}
/*
 * Cross-thread reuse from the global server-session pool.
 *
 * If the pooled connection already lives on the acquiring thread, reuse it in
 * place; the acquiring consumer's later do_io_read/do_io_write re-homes the VC's
 * mutex onto that consumer (see _adoptConsumerMutex).
 *
 * Otherwise migrate. The layered TLS VC owns no fd/epoll/NetHandler state of its
 * own -- all of that lives in the inner transport (_unvc) -- so we move the
 * transport with the generic, already-cross-thread-safe machinery and keep this
 * SSLNetVConnection object. The SSL object and both MIOBuffer-backed BIOs are
 * thread-agnostic heap state and travel with us, including any buffered
 * ciphertext; only the transport VIOs (which lived in the now-closed inner VC)
 * must be re-armed, exactly as startEvent does.
 */
NetVConnection *
SSLNetVConnection::migrateToCurrentThread(Continuation * /* cont */, EThread *t)
{
  if (_unvc == nullptr) {
    return nullptr; // nothing to migrate
  }
  if (_unvc->thread == t) {
    return this; // already local
  }

  // Thread-safety invariant: a pooled session's mutex is the pool mutex
  // (ServerSessionPool::releaseSession re-armed the read via do_io_read(pool, ...),
  // which adopted the VC onto the pool mutex), and HttpSessionManager::
  // _acquire_session holds that mutex across this call. So we hold the VC's own
  // lock here -- which both excludes the old thread from dispatching this VC
  // concurrently and satisfies the event-cancellation contract used below.
  ink_assert(this->mutex && this->mutex->thread_holding == this_ethread());

  // Only an idle, post-handshake pooled session should reach a cross-thread
  // acquire. If the VC is mid-operation (handshaking, closing, or pending a
  // tunnel/downgrade handoff) decline rather than risk migrating mid-flight; the
  // caller (HttpSessionManager) then opens a fresh connection.
  // _sslState == HANDSHAKE_DONE already excludes draining/handshaking; also require no armed
  // handoff (which is a mid-handshake decision, so normally implied, but checked explicitly).
  bool const migratable = _sslState == SslState::HANDSHAKE_DONE && recursion == 0 && _pending_handoff == PendingHandoff::NONE;
  if (!migratable) {
    return nullptr;
  }

  // An idle pooled session can still carry a self-scheduled read-drive event
  // (releaseSession's do_io_read schedules one). It must be cancelled before we
  // move threads: otherwise, once the pool mutex is released, the old thread would
  // pop it and run mainEvent on a VC that has migrated -- a cross-thread UAF.
  // Cancelling is safe because we hold the VC's lock (the invariant above), so the
  // old thread cannot be mid-dispatch; it will simply free the cancelled event.
  // The fresh do_io_read below re-arms the transport read.
  if (_deferred_work_event != nullptr) {
    _deferred_work_event->cancel();
    _deferred_work_event = nullptr;
  }
  // Any write-rearm armed for the outgoing thread's net_write_io pass is meaningless on the
  // new thread; the fire-time re-validation in mainEvent would likely reject it anyway (the
  // pool's do_io_write leaves the write VIO disabled), but clear it explicitly rather than
  // relying on that incidentally.
  _write_rearm_pending = false;

  UnixNetVConnection *new_unvc = static_cast<UnixNetVConnection *>(_unvc->migrateToCurrentThread(this, t));
  if (new_unvc == nullptr) {
    // The inner migrate has already torn down the old inner and its fd. Drop the
    // dangling pointer so our own do_io_close does not double-close it, and decline;
    // HttpSessionManager closes the pooled session and opens a fresh connection.
    _unvc = nullptr;
    return nullptr;
  }
  _unvc = new_unvc;

  _transport_read_vio  = _unvc->do_io_read(this, INT64_MAX, _read_buf.get());
  _transport_write_vio = _unvc->do_io_write(this, INT64_MAX, _write_buf_reader.get(), false);
  ink_release_assert(_transport_read_vio != nullptr && _transport_write_vio != nullptr);

  this->thread = t;

  Metrics::Counter::increment(ssl_rsb.origin_session_cross_thread_migration);

  return this;
}

void
SSLNetVConnection::_propagateHandShakeBuffer(UnixNetVConnection *target, EThread *t)
{
  // DOWNGRADE_PLAIN is only ever armed by the allow-plain sniff while the holder is present, and
  // the holder is not released after that (the release gate excludes a pending handoff). If this
  // fires, the sniff/release ordering has been broken and we are about to hand a null reader to
  // the plain successor.
  ink_release_assert(this->handShakeHolder != nullptr);
  Dbg(dbg_ctl_ssl, "allow-plain, handshake buffer ready to read=%" PRId64, this->handShakeHolder->read_avail());
  // Take ownership of the handShake buffer
  _sslState   = SslState::HANDSHAKE_DONE;
  NetState *s = &target->read;
  s->vio.set_writer(this->_read_buf.get());
  s->vio.set_reader(this->handShakeHolder);
  this->handShakeHolder = nullptr;
  // Transfer (do not free) the read MIOBuffer to the target's read VIO. _read_buf is a
  // unique_ptr with the free_MIOBuffer deleter, so assigning nullptr would FREE the buffer
  // we just handed off (the buffered plaintext request would vanish and the reader read 0).
  // release() drops ownership without freeing; the downgraded plain connection owns it now.
  this->_read_buf.release();
  s->vio.vc_server = target;
  s->vio.cont      = this->_user_read_vio.cont;
  s->vio.mutex     = this->_user_read_vio.cont->mutex;

  // The transport's write VIO still names this SSL VC as its continuation (it was
  // driving handshake output). Cancel it so a stale transport write event on the
  // ready list does not signal the soon-to-be-freed SSL VC; the HTTP layer installs
  // its own write VIO when it sends the response.
  target->do_io_write(nullptr, 0, nullptr);

  // Kick things again, so the data that was copied into the
  // vio.read buffer gets processed
  target->readSignalDone(VC_EVENT_READ_COMPLETE, get_NetHandler(t));
}

/*
 * Replaces the current SSLNetVConnection with a UnixNetVConnection
 * Propagates any raw handshake bytes retained by handShakeHolder to be
 * processed by the UnixNetVConnection logic
 */
UnixNetVConnection *
SSLNetVConnection::_downgradeToPlain()
{
  EThread    *t         = this_ethread();
  NetHandler *client_nh = get_NetHandler(t);
  ink_assert(client_nh);

  if (_unvc != nullptr) {
    _unvc->attributes = HttpProxyPort::TRANSPORT_DEFAULT;
    _unvc->set_is_transparent(this->is_transparent);
    // set_context asserts the context is currently UNSET; the inner _unvc may
    // already have it set from accept, so only set it if needed.
    if (_unvc->get_context() == NET_VCONNECTION_UNSET) {
      _unvc->set_context(get_context());
    }
    _unvc->options = this->options;
    Dbg(dbg_ctl_ssl, "Move to unixvc for allow-plain");
    _propagateHandShakeBuffer(_unvc, t);
  }

  // The transport VC was just handed to the HTTP layer by _propagateHandShakeBuffer.
  // Detach it before closing this SSL VC: do_io_close() can free this VC inline, and
  // ~SSLNetVConnection() closes _unvc -- which would tear down the connection we are
  // returning. Null it first so the destructor leaves the handed-off transport alone.
  UnixNetVConnection *transferred = _unvc;
  _unvc                           = nullptr; // caller/HTTP layer owns the returned VC now

  // do_io_close() frees this SSL VC inline. That is safe here only because the caller
  // (sslServerHandShakeEvent) defers us to the out-of-line mainEvent dispatch, which returns
  // EVENT_DONE immediately after this returns -- no frame above re-reads `this`.
  do_io_close();
  return transferred;
}

/*
 * Hand an inbound blind tunnel off to a dedicated raw pass-through VC.
 *
 * The SNI callback selected a blind tunnel_route, so TLS must not be terminated: the
 * buffered ClientHello and all subsequent bytes are forwarded verbatim to the origin so
 * the client completes its handshake against the origin's certificate. This SSL VC only
 * has-a transport, so we transfer the transport (_unvc), the read buffer holding the
 * ClientHello (_read_buf) and its reader (handShakeHolder) to a TunnelNetVConnection,
 * copy the tunnel route, then hand the new VC up the accept chain and tear this one down.
 *
 * Mirrors the _downgradeToPlain / _propagateHandShakeBuffer ownership discipline:
 * everything transferred is detached from this VC before do_io_close() so teardown does
 * not free the resources the pass-through VC now owns.
 */
void
SSLNetVConnection::_handoffBlindTunnel()
{
  ink_release_assert(_unvc != nullptr);
  ink_release_assert(this->attributes == HttpProxyPort::TRANSPORT_BLIND_TUNNEL);

  EThread      *t           = this_ethread();
  Continuation *accept_cont = _user_read_vio.cont; // the SSLNextProtocolTrampoline
  ink_release_assert(accept_cont != nullptr);

  Dbg(dbg_ctl_ssl, "SSLNetVConnection %p: handing inbound blind tunnel off to a pass-through VC", this);

  TunnelNetVConnection *tvc = tunnelNetVCAllocator.alloc();
  tvc->mutex                = this->mutex; // share the per-connection mutex
  tvc->thread               = t;
  tvc->set_context(NET_VCONNECTION_IN);
  tvc->attributes = HttpProxyPort::TRANSPORT_BLIND_TUNNEL;
  tvc->options    = this->options;
  tvc->set_is_transparent(this->get_is_transparent());
  tvc->copy_tunnel_destination_from(*this);

  // Transfer the transport and the buffered ClientHello bytes. A transparent per-IP OPT_TUNNEL
  // flips to BLIND_TUNNEL before _make_ssl_connection runs, so handShakeHolder was never
  // allocated; give the pass-through VC a reader at the head of _read_buf so it can replay the
  // buffered ClientHello (and forward everything after it) instead of adopting a null reader that
  // forwards nothing.
  if (handShakeHolder == nullptr) {
    handShakeHolder = _read_buf->alloc_reader();
  }
  tvc->adopt(_unvc, _read_buf.get(), handShakeHolder);

  // Addresses are now reachable through the adopted transport.
  tvc->set_remote_addr();
  tvc->set_local_addr();

  // Detach the transferred resources so this VC's teardown leaves them alone:
  //  - release() (not reset) so the read MIOBuffer is not freed (the pass-through VC owns it),
  //  - null handShakeHolder so free_handshake_buffers() does not dealloc the reader,
  //  - null _unvc so the destructor does not close the handed-off transport.
  _read_buf.release();
  handShakeHolder = nullptr;
  _unvc           = nullptr;

  // Route the pass-through VC up the accept chain (trampoline -> HTTP endpoint).
  tvc->hand_off_to(accept_cont);

  // Tear down this SSL VC; the transferred resources are no longer ours.
  do_io_close();
}

ssl_curve_id
SSLNetVConnection::_get_tls_curve() const
{
  // For resumed server side session caching, we have to retrieve the curve/group
  // from our stored data. For non-resumed sessions or from ticket based resumption,
  // simply query the SSL object.
  if (getIsResumedFromSessionCache()) {
    return getSSLCurveNID();
  } else {
    return SSLGetCurveNID(this->_ssl.get());
  }
}

std::string_view
SSLNetVConnection::_get_tls_group() const
{
  // For resumed server side session caching, we have to retrieve the curve/group
  // from our stored data. For non-resumed sessions or from ticket based resumption,
  // simply query the SSL object.
  if (getIsResumedFromSessionCache()) {
    return getSSLGroupName();
  } else {
    return SSLGetGroupName(this->_ssl.get());
  }
}

int
SSLNetVConnection::_verify_certificate(X509_STORE_CTX * /* ctx ATS_UNUSED */)
{
  // Currently, TS_EVENT_SSL_VERIFY_CLIENT/SERVER are invoked only with a NetVC instance.
  // This requires plugins to call TSSslVerifyCTX in their event handler.
  // We could pass a structure that has both a cert to verify and a NetVC.
  // It would allow us to remove confusing TSSslVerifyCTX and its internal implementation that are only available during a very
  // limited time.
  // A verify hook reenabling with TS_EVENT_ERROR is reporting a certificate verdict, not a handshake
  // termination -- enforcement is the verify policy's call, applied by the OpenSSL verify callback's
  // return (!enforce_mode). While _in_verify_hook is set, reenable_with_event routes that error into
  // _verify_hook_failed instead of the terminal _sslState/_fatal_pending, so a PERMISSIVE override
  // still completes the handshake. Report the verdict; enforcement flows through the verify return.
  _verify_hook_failed = false;
  _in_verify_hook     = true;

  if (get_context() == NET_VCONNECTION_IN) {
    this->callHooks(TS_EVENT_SSL_VERIFY_CLIENT /* , ctx */);
  } else {
    this->callHooks(TS_EVENT_SSL_VERIFY_SERVER /* , ctx */);
  }

  _in_verify_hook = false;

  return _verify_hook_failed ? 1 : 0;
}

ssl_error_t
SSLNetVConnection::_ssl_accept()
{
  ERR_clear_error();

  int ret       = 0;
  int ssl_error = SSL_ERROR_NONE;
  // Covers every SSL_accept()/SSL_read()/SSL_read_early_data() call below: any of them may
  // synchronously invoke a registered hook (SNI/cert/client-hello), which may itself call back
  // into us (see the recursion comment in P_SSLNetVConnection.h).
  RecursionGuard openssl_guard(recursion);

#if TS_HAS_TLS_EARLY_DATA
  if (!this->_early_data_finish) {
#if HAVE_SSL_READ_EARLY_DATA
    size_t nread = 0;
#else
    ssize_t nread = 0;
#endif

    while (true) {
      bool           had_error_on_reading_early_data = false;
      bool           finished_reading_early_data     = false;
      IOBufferBlock *block                           = new_IOBufferBlock();
      block->alloc(BUFFER_SIZE_INDEX_16K);

#if HAVE_SSL_READ_EARLY_DATA
      ret = SSL_read_early_data(this->_ssl.get(), block->buf(), index_to_buffer_size(BUFFER_SIZE_INDEX_16K), &nread);
      if (ret == SSL_READ_EARLY_DATA_ERROR) {
        had_error_on_reading_early_data = true;
      } else if (ret == SSL_READ_EARLY_DATA_FINISH) {
        finished_reading_early_data = true;
      }
#else
      // If SSL_read_early_data is unavailable, it's probably BoringSSL,
      // and SSL_in_early_data should be available.
      ret = SSL_accept(this->_ssl.get());
      if (ret <= 0) {
        had_error_on_reading_early_data = true;
      } else {
        if (SSL_in_early_data(this->_ssl.get())) {
          ret                         = SSL_read(this->_ssl.get(), block->buf(), index_to_buffer_size(BUFFER_SIZE_INDEX_16K));
          finished_reading_early_data = !SSL_in_early_data(this->_ssl.get());
          if (ret < 0) {
            nread = 0;
            if (finished_reading_early_data) {
              ret = 2; // SSL_READ_EARLY_DATA_FINISH
            } else {
              // Don't override ret here.
              // Keeping the original retrurn value let ATS allow to check the value by SSL_get_error.
              // That gives a chance to progress handshake process, or shutdown a connection if the error is serious.
              had_error_on_reading_early_data = true;
            }
          } else {
            nread = ret;
            if (finished_reading_early_data) {
              ret = 2; // SSL_READ_EARLY_DATA_FINISH
            } else {
              ret = 1; // SSL_READ_EARLY_DATA_SUCCESS
            }
          }
        } else {
          nread                       = 0;
          ret                         = 2; // SSL_READ_EARLY_DATA_FINISH
          finished_reading_early_data = true;
        }
      }
#endif

      if (had_error_on_reading_early_data) {
        Dbg(dbg_ctl_ssl_early_data, "Error on reading early data: %d", ret);
        block->free();
        break;
      } else {
        if (nread > 0) {
          if (this->_early_data_buf == nullptr) {
            this->_early_data_buf    = new_MIOBuffer(BUFFER_SIZE_INDEX_16K);
            this->_early_data_reader = this->_early_data_buf->alloc_reader();
          }
          block->fill(nread);
          this->_early_data_buf->append_block(block);
          this->_increment_early_data_len(nread);
          Metrics::Counter::increment(ssl_rsb.early_data_received_count);

          if (dbg_ctl_ssl_early_data_show_received.on()) {
            std::string early_data_str(reinterpret_cast<char *>(block->buf()), nread);
            DbgPrint(dbg_ctl_ssl_early_data_show_received, "Early data buffer: \n%s", early_data_str.c_str());
          }
        } else {
          block->free();
        }

        if (finished_reading_early_data) {
          this->_early_data_finish = true;
          Dbg(dbg_ctl_ssl_early_data, "SSL_READ_EARLY_DATA_FINISH: size = %lu", nread);

          if (this->_early_data_reader == nullptr || this->_early_data_reader->read_avail() == 0) {
            Dbg(dbg_ctl_ssl_early_data, "no data in early data buffer");
            ERR_clear_error();
            ret = SSL_accept(this->_ssl.get());
          }
          break;
        }
        Dbg(dbg_ctl_ssl_early_data, "SSL_READ_EARLY_DATA_SUCCESS: size = %lu", nread);
      }
    }
  } else {
    ret = SSL_accept(this->_ssl.get());
  }
#else
  ret = SSL_accept(this->_ssl.get());
#endif

  if (ret > 0) {
    return SSL_ERROR_NONE;
  }
  ssl_error = SSL_get_error(this->_ssl.get(), ret);
  if (ssl_error == SSL_ERROR_SSL && dbg_ctl_ssl_error_accept.on()) {
    char          buf[512];
    unsigned long e = ERR_peek_last_error();
    ERR_error_string_n(e, buf, sizeof(buf));
    DbgPrint(dbg_ctl_ssl_error_accept, "SSL accept returned %d, ssl_error=%d, ERR_get_error=%ld (%s)", ret, ssl_error, e, buf);
  }

  return ssl_error;
}

ssl_error_t
SSLNetVConnection::_ssl_connect()
{
  ERR_clear_error();

  SSL_SESSION *sess = SSL_get_session(this->_ssl.get());
  if (first_ssl_connect) {
    first_ssl_connect = false;
    if (!sess && SSLConfigParams::origin_session_cache == 1 && SSLConfigParams::origin_session_cache_size > 0) {
      std::string sni_addr = get_sni_addr(this->_ssl.get());
      if (!sni_addr.empty()) {
        std::string lookup_key;
        swoc::bwprint(lookup_key, "{}:{}:{}", sni_addr.c_str(), SSL_get_SSL_CTX(this->_ssl.get()),
                      get_verify_str(this->_ssl.get()));

        Dbg(dbg_ctl_ssl_origin_session_cache, "origin session cache lookup key = %s", lookup_key.c_str());

        std::shared_ptr<SSL_SESSION> shared_sess = this->getOriginSession(lookup_key);

        if (shared_sess && SSL_set_session(this->_ssl.get(), shared_sess.get())) {
          // Keep a reference of this shared pointer in the connection
          this->client_sess = shared_sess;
        }
      }
    }
  }

  int ret;
  {
    // May synchronously invoke a registered hook (verify), which may itself call back into us.
    RecursionGuard openssl_guard(recursion);
    ret = SSL_connect(this->_ssl.get());
  }

  if (ret > 0) {
    if (SSL_session_reused(this->_ssl.get())) {
      Metrics::Counter::increment(ssl_rsb.origin_session_reused_count);
      Dbg(dbg_ctl_ssl_origin_session_cache, "reused session to origin server");
    } else {
      Dbg(dbg_ctl_ssl_origin_session_cache, "new session to origin server");
    }
    return SSL_ERROR_NONE;
  }
  int ssl_error = SSL_get_error(this->_ssl.get(), ret);
  if (ssl_error == SSL_ERROR_SSL && dbg_ctl_ssl_error_connect.on()) {
    char          buf[512];
    unsigned long e = ERR_peek_last_error();
    ERR_error_string_n(e, buf, sizeof(buf));
    DbgPrint(dbg_ctl_ssl_error_connect, "SSL connect returned %d, ssl_error=%d, ERR_get_error=%ld (%s)", ret, ssl_error, e, buf);
  }

  return ssl_error;
}

ssl_error_t
SSLNetVConnection::_ssl_write_buffer(const void *buf, int64_t nbytes, int64_t &nwritten)
{
  nwritten = 0;

  if (unlikely(nbytes == 0)) {
    return SSL_ERROR_NONE;
  }

  int ret;
  // Covers every SSL_write()/SSL_write_early_data() call below: either may synchronously
  // invoke a registered hook, which may itself call back into us.
  RecursionGuard openssl_guard(recursion);
  // If SSL_write_early_data is available, it's probably OpenSSL,
  // and SSL_is_init_finished should be available.
  // If SSL_write_early_data is unavailable, its' probably BoringSSL,
  // and we can use SSL_write to send early data.
#if TS_HAS_TLS_EARLY_DATA
  if (SSL_version(this->_ssl.get()) >= TLS1_3_VERSION) {
#ifdef HAVE_SSL_WRITE_EARLY_DATA
    if (SSL_is_init_finished(this->_ssl.get())) {
#endif
      ret = SSL_write(this->_ssl.get(), buf, static_cast<int>(nbytes));
#ifdef HAVE_SSL_WRITE_EARLY_DATA
    } else {
      size_t nwrite;
      ret = SSL_write_early_data(this->_ssl.get(), buf, static_cast<size_t>(nbytes), &nwrite);
      if (ret == 1) {
        ret = nwrite;
      }
    }
#endif
  } else {
    ret = SSL_write(this->_ssl.get(), buf, static_cast<int>(nbytes));
  }
#else
  ret = SSL_write(this->_ssl.get(), buf, static_cast<int>(nbytes));
#endif

  if (ret > 0) {
    nwritten = ret;
    return SSL_ERROR_NONE;
  }
  int ssl_error = SSL_get_error(this->_ssl.get(), ret);
  if (ssl_error == SSL_ERROR_SSL && dbg_ctl_ssl_error_write.on()) {
    char          tempbuf[512];
    unsigned long e = ERR_peek_last_error();
    ERR_error_string_n(e, tempbuf, sizeof(tempbuf));
    DbgPrint(dbg_ctl_ssl_error_write, "SSL write returned %d, ssl_error=%d, ERR_get_error=%ld (%s)", ret, ssl_error, e, tempbuf);
  }
  return ssl_error;
}

ssl_error_t
SSLNetVConnection::_ssl_read_buffer(void *buf, int64_t nbytes, int64_t &nread)
{
  nread = 0;

  if (unlikely(nbytes == 0)) {
    return SSL_ERROR_NONE;
  }
  ERR_clear_error();
  // Covers every SSL_read()/SSL_read_early_data() call below (both the early-data branch and
  // the final read at the bottom of this function): any of them may synchronously invoke a
  // registered hook, which may itself call back into us. RAII so it's released on every exit
  // path, including the early data branch's own early return.
  RecursionGuard openssl_guard(recursion);

#if TS_HAS_TLS_EARLY_DATA
  if (SSL_version(this->_ssl.get()) >= TLS1_3_VERSION) {
    int64_t early_data_len = 0;
    if (this->_early_data_reader != nullptr) {
      early_data_len = this->_early_data_reader->read_avail();
    }

    if (early_data_len > 0) {
      Dbg(dbg_ctl_ssl_early_data, "Reading from early data buffer.");
      this->_increment_early_data_len(this->_early_data_reader->read(buf, nbytes < early_data_len ? nbytes : early_data_len));

      if (nbytes < early_data_len) {
        nread = nbytes;
      } else {
        nread = early_data_len;
      }

      return SSL_ERROR_NONE;
    }

    bool early_data_enabled = this->hints_from_sni.server_max_early_data.has_value() ?
                                this->hints_from_sni.server_max_early_data.value() > 0 :
                                SSLConfigParams::server_max_early_data > 0;
    if (early_data_enabled && !this->_early_data_finish) {
      bool had_error_on_reading_early_data = false;
      bool finished_reading_early_data     = false;
      Dbg(dbg_ctl_ssl_early_data, "More early data to read.");
      ssl_error_t ssl_error = SSL_ERROR_NONE;
      int         ret;
#if HAVE_SSL_READ_EARLY_DATA
      size_t read_bytes = 0;
#else
      ssize_t read_bytes = 0;
#endif

#if HAVE_SSL_READ_EARLY_DATA
      ret = SSL_read_early_data(this->_ssl.get(), buf, static_cast<size_t>(nbytes), &read_bytes);
      if (ret == SSL_READ_EARLY_DATA_ERROR) {
        had_error_on_reading_early_data = true;
        ssl_error                       = SSL_get_error(this->_ssl.get(), ret);
      } else if (ret == SSL_READ_EARLY_DATA_FINISH) {
        finished_reading_early_data = true;
      }
#else
      // If SSL_read_early_data is unavailable, it's probably OpenSSL,
      // and SSL_in_early_data should be available.
      if (SSL_in_early_data(this->_ssl.get())) {
        ret                         = SSL_read(this->_ssl.get(), buf, nbytes);
        finished_reading_early_data = !SSL_in_early_data(this->_ssl.get());
        if (ret < 0) {
          if (!finished_reading_early_data) {
            had_error_on_reading_early_data = true;
            ssl_error                       = SSL_get_error(this->_ssl.get(), ret);
          }
          read_bytes = 0;
        } else {
          read_bytes = ret;
        }
      } else {
        finished_reading_early_data = true;
        read_bytes                  = 0;
      }
#endif

      if (had_error_on_reading_early_data) {
        Dbg(dbg_ctl_ssl_early_data, "Error reading early data: %s", ERR_error_string(ERR_get_error(), nullptr));
      } else {
        if ((nread = read_bytes) > 0) {
          this->_increment_early_data_len(read_bytes);
          Metrics::Counter::increment(ssl_rsb.early_data_received_count);
          if (dbg_ctl_ssl_early_data_show_received.on()) {
            std::string early_data_str(reinterpret_cast<char *>(buf), nread);
            DbgPrint(dbg_ctl_ssl_early_data_show_received, "Early data buffer: \n%s", early_data_str.c_str());
          }
        }

        if (finished_reading_early_data) {
          this->_early_data_finish = true;
          Dbg(dbg_ctl_ssl_early_data, "SSL_READ_EARLY_DATA_FINISH: size = %" PRId64, nread);
        } else {
          Dbg(dbg_ctl_ssl_early_data, "SSL_READ_EARLY_DATA_SUCCESS: size = %" PRId64, nread);
        }
      }
      return ssl_error;
    }
  }
#endif

  int ret = SSL_read(this->_ssl.get(), buf, static_cast<int>(nbytes));
  if (ret > 0) {
    nread = ret;
    return SSL_ERROR_NONE;
  }
  int ssl_error = SSL_get_error(this->_ssl.get(), ret);
  if (ssl_error == SSL_ERROR_SSL && dbg_ctl_ssl_error_read.on()) {
    char          tempbuf[512];
    unsigned long e = ERR_peek_last_error();
    ERR_error_string_n(e, tempbuf, sizeof(tempbuf));
    DbgPrint(dbg_ctl_ssl_error_read, "SSL read returned %d, ssl_error=%d, ERR_get_error=%ld (%s)", ret, ssl_error, e, tempbuf);
  }

  return ssl_error;
}

void
SSLNetVConnection::mark_as_tunnel_endpoint()
{
  Dbg(dbg_ctl_ssl, "Entering SSLNetVConnection::mark_as_tunnel_endpoint()");

  ink_assert(!_is_tunnel_endpoint);

  _is_tunnel_endpoint = true;

  switch (get_context()) {
  case NET_VCONNECTION_IN:
    _in_context_tunnel();
    break;
  case NET_VCONNECTION_OUT:
    _out_context_tunnel();
    break;
  default:
    ink_release_assert(false);
  }
}

int
SSLNetVConnection::_handle_transport_read_ready(VIO *vio) // vio is from _unvc
{
  Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: Handling transport read ready/complete (VIO: %p)", this, vio);

  ink_release_assert(vio == _transport_read_vio);

  // mainEvent owns the terminated/draining gate (it early-returns on _sslState == SslState::TERMINATED,
  // and short-circuits reads while _isDraining(), before dispatching here), so no redundant entry
  // check is needed.
  if (isTerminated(_transport_state)) {
    Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: transport closed, but we have data to read", this);
  }

  if (_pending_handoff == PendingHandoff::BLIND_TUNNEL) {
    // The blind-tunnel decision is made; the deferred handoff will re-drive the transport
    // from the pass-through VC. Do not run any more SSL-side reads here.
    return EVENT_CONT;
  }

  if (_transport_read_vio->is_disabled()) {
    Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: transport read VIO is disabled", this);
    return EVENT_CONT;
  }

  _trigger_ssl_read();
  // _trigger_ssl_read() may have freed this VC on a terminal signal's recursion-0 unwind (e.g. a
  // hook-flagged handshake error), so do not read any member -- reading _sslState here was a
  // use-after-free. The transport read path (read_signal_and_update) ignores this return value
  // and drives the inner VC's teardown from its own state.
  return EVENT_CONT;
}

int
SSLNetVConnection::_handle_transport_write_ready(VIO *vio)
{
  ink_assert(vio == _transport_write_vio);
  ink_assert(vio->mutex->thread_holding == this_ethread());
  ink_assert(vio->buffer.reader() == _write_buf_reader.get());

  Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: Handling transport write ready (VIO: %p)", this, vio);
  _releaseHandshakeReader();

  if (_isDraining()) {
    // Lingering close: flush the remaining ciphertext (response + close-notify), then
    // tear down. read_avail()==0 means it has all been handed to the socket.
    if (!_write_buf_reader || _write_buf_reader->read_avail() == 0) {
      Dbg(dbg_ctl_ssl, "SSLNetVConnection %p: close drain complete, tearing down", this);
      // Free out of line, not here: this runs from the inner transport's net_write_io
      // (via its WRITE_READY signal). write_signal_and_update ignores our return value and
      // keeps net_write_io going to its tail, where it dereferences _write_buf's reader.
      // Freeing this VC now would deallocate that reader underneath the live net_write_io
      // (the FORWARD-tunnel crash). A scheduled dispatch frees it on a clean stack.
      if (!_deferred_work_pending()) {
        _deferred_work_event = this_ethread()->schedule_imm(this);
      }
      return EVENT_DONE;
    }
    _transport_write_vio->reenable();
    return EVENT_CONT;
  }

  if (!this->getSSLHandShakeComplete()) {
    this->_trackFirstHandshake();

    int err = 0, ret;

    if (this->get_context() == NET_VCONNECTION_OUT) {
      ret = this->sslStartHandShake(SSL_EVENT_CLIENT, err);
    } else {
      ret = this->sslStartHandShake(SSL_EVENT_SERVER, err);
    }

    // If the handshake flipped to a blind tunnel, hand the transport off rather than falling
    // through to WRITE_COMPLETE: a transparent per-IP OPT_TUNNEL returns EVENT_DONE from
    // sslStartHandShake before _make_ssl_connection, and the first transport event may be this
    // WRITE_READY (a fresh accept is writable before the ClientHello). Without arming the handoff
    // here, the later read drive hits the TRANSPORT_BLIND_TUNNEL assert in _trigger_ssl_read.
    // Mirrors the read-face arming; check for a non-error return first (a failed ClientHello has
    // no tunnel to establish) and defer the handoff out of line, since it frees this VC.
    if (ret != EVENT_ERROR && this->attributes == HttpProxyPort::TRANSPORT_BLIND_TUNNEL) {
      _pending_handoff = PendingHandoff::BLIND_TUNNEL;
      if (_transport_read_vio != nullptr) {
        _transport_read_vio->disable();
      }
      if (!_deferred_work_pending()) {
        _deferred_work_event = this_ethread()->schedule_imm(this);
      }
      return EVENT_CONT;
    }

    if (ret == EVENT_ERROR) {
      lerrno = err;
      // Set the state before signalling: the paired reclaim may free this VC, so the
      // member write must happen first (and the terminated state also lets
      // _reclaimIfClosed free us).
      _sslState = SslState::TERMINATED;
      _signal_user(_handshake_fail_side(), VC_EVENT_ERROR);
      _reclaimIfClosed();
      return EVENT_DONE;
    } else if (_sslState == SslState::TERMINATED) {
      // A hook may have synchronously flagged an error mid SSL_accept()/SSL_connect() without
      // the handshake call itself returning EVENT_ERROR this round (e.g. SSL_HANDSHAKE_WANT_READ).
      // sslStartHandShake() has already returned, so we're unconditionally outside any OpenSSL
      // frame here -- always safe to deliver synchronously. See the read-side twin of this
      // check in _trigger_ssl_read for the full rationale.
      _signal_user(_handshake_fail_side(), VC_EVENT_ERROR);
      _reclaimIfClosed();
      return EVENT_DONE;
    } else if (ret == SSL_HANDSHAKE_WANT_READ || ret == SSL_HANDSHAKE_WANT_ACCEPT) {
      _transport_read_vio->reenable();
    } else if (ret == SSL_HANDSHAKE_WANT_CONNECT || ret == SSL_HANDSHAKE_WANT_WRITE) {
      _transport_write_vio->reenable();
    } else if (ret == SSL_WAIT_FOR_ASYNC) {
      // Handshake suspended on the server private-key async op. The async wait-fd resume
      // (handle_async_tls_ready -> mainEvent -> _trigger_ssl_read) re-drives the handshake.
      // Flush any handshake ciphertext already produced into _write_buf -- a true
      // reenable-with-bytes, so it respects the write-backpressure invariant -- but do not
      // reenable on an empty buffer, which would spin. Symmetric with the read-side path.
      if (_write_buf_reader->read_avail() > 0) {
        _transport_write_vio->reenable();
      }
    } else if (ret == SSL_WAIT_FOR_HOOK) {
      // A handshake hook parked on this write-face drive. Latch the parked-hook hold so a
      // consumer-driven close cannot free the VC before the plugin reenables (the read-face
      // driver's SSL_WAIT_FOR_HOOK case does the same). Key on is_invoked_state(): the outbound
      // PROXY-preamble also returns SSL_WAIT_FOR_HOOK here but is NOT a hook park -- it is flushed
      // and re-driven -- so it must not falsely latch.
      if (is_invoked_state()) {
        _hook_parked = true;
      }
      // Flush any handshake ciphertext already produced (the PROXY preamble, or a partial flight)
      // so the transport drains it and re-drives; do not reenable on an empty buffer, which spins.
      if (_write_buf_reader->read_avail() > 0) {
        _transport_write_vio->reenable();
      }
    } else if (ret == EVENT_DONE) {
      // If this was driven by a zero length read, signal complete when
      // the handshake is complete. Otherwise set up for continuing read
      // operations.
      if (_user_write_vio.ntodo() <= 0) {
        // Read side is on purpose
        _signal_user(SignalSide::READ, VC_EVENT_WRITE_COMPLETE);
        _reclaimIfClosed();
      }
    } else {
      _transport_write_vio->reenable();
    }

    return EVENT_CONT;
  }

  // The handshake is complete, but the consumer may not have issued a
  // do_io_write() yet (e.g. a transport write-ready fired to flush the final
  // handshake records before the endpoint set up the response write). In that
  // case _user_write_vio is not initialized and its mutex is null. There is
  // nothing to encrypt; the transport drains _write_buf on its own, so wait for
  // the consumer to start writing rather than dereferencing a null mutex.
  if (_user_write_vio.op != VIO::WRITE || _user_write_vio.mutex == nullptr) {
    return EVENT_CONT;
  }

  MUTEX_TRY_LOCK(lock, _user_write_vio.mutex, this_ethread());
  if (!lock.is_locked()) {
    _transport_write_vio->reenable(); // Retry later
    return EVENT_CONT;
  }

  // Only a broken transport (TRANSPORT_ERROR) blocks the write here. TRANSPORT_CLOSED
  // means the peer half-closed its write side (FIN); its read side is still open and
  // waiting for our response, so we must keep encrypting and flushing it.
  if (_sslState == SslState::TERMINATED || _transport_state == TransportState::TRANSPORT_ERROR) {
    Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: terminated, ignoring write ready", this);
    _transport_write_vio->disable();
    return EVENT_DONE;
  }

  Continuation *user_cont = _user_write_vio.cont; // Save original continuation for reentrancy check
  if (_user_write_vio.op != VIO::WRITE || _user_write_vio.is_disabled()) {
    Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: User write VIO not active or disabled.", this);
    return EVENT_DONE;
  }

  int64_t ntodo   = _user_write_vio.ntodo();
  int64_t towrite = _write_buf_reader->read_avail();
  if (towrite > ntodo) {
    towrite = ntodo;
  }

  // Give user a chance to fill buffer
  // No high_water check here.  The user should do its own flow control for sending.  Only give backpressure when the
  // SSL transport is unable to send.
  if (towrite != ntodo && !_write_buf->high_water()) {
    _signal_user(SignalSide::WRITE, VC_EVENT_WRITE_READY);
    if (_reclaimIfClosed()) {
      // User closed connection in the handler
      return EVENT_DONE;
    }

    // The user may have stopped a do_io_write, or even started a new one
    if (_user_write_vio.cont != user_cont || _user_write_vio.op != VIO::WRITE || _user_write_vio.is_disabled()) {
      Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: User VIO changed during WRITE_READY signal.", this);
      // User changed the VIO, stop processing for this event.
      // The next event or reenable call will handle the new state.
      return EVENT_CONT;
    }
    ntodo = _user_write_vio.ntodo(); // Update ntodo after potential user action
  }

  // User has no more plaintext to write.
  if (ntodo <= 0) {
    Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: User write VIO ntodo <= 0, read_avail=%" PRId64, this,
        _write_buf_reader->read_avail());
    // Do not signal WRITE_COMPLETE until the encrypted bytes have actually drained to the
    // transport. The consumer (HttpSM/HttpTunnel) closes the connection from its
    // WRITE_COMPLETE handler; if ciphertext is still buffered in _write_buf, that close
    // races the flush and truncates the response on the wire. Keep the transport write
    // enabled and re-enter here once it drains.
    if (_write_buf_reader->read_avail() > 0) {
      _transport_write_vio->reenable();
      return EVENT_CONT;
    }
    // Plaintext done and ciphertext fully drained: deliver WRITE_COMPLETE now.
    return _deliverWriteComplete();
  }

  int64_t total_plaintext_written = 0; // Bytes of *plaintext* consumed from user buffer
  int     needs                   = 0; // Flags for transport read/write needed by SSL layer/BIOs
  int64_t ret                     = _encrypt_data_for_transport(ntodo, _user_write_vio.buffer, total_plaintext_written, needs);

  if (total_plaintext_written > 0) {
    _user_write_vio.ndone += total_plaintext_written;
  }

  if (ret == -EAGAIN) {
    // _encrypt_data_for_transport maps SSL_write's WANT_READ / WANT_X509_LOOKUP /
    // WANT_CLIENT_HELLO_CB to -EAGAIN. On this post-handshake write path that return is
    // unreachable under ATS's configuration:
    //   * We only reach _encrypt_data_for_transport once getSSLHandShakeComplete() is true (the
    //     gate at the top of this method). The certificate / ClientHello callback suspensions
    //     (WANT_X509_LOOKUP / WANT_CLIENT_HELLO_CB) are raised by SSL only while it processes the
    //     ClientHello, and the handshake driver (sslServerHandShakeEvent) is their sole consumer
    //     -- they cannot surface from SSL_write.
    //   * SSL_write only needs to read (WANT_READ) when SSL_in_init() is true again, i.e. during a
    //     TLS1.2 renegotiation (aborted by default -- ssl_allow_client_renegotiation=false drives
    //     sslClientRenegotiationAbort -- and absent from TLS1.3) or post-handshake auth (never
    //     enabled by ATS). TLS1.3 post-handshake messages that do require a read (KeyUpdate,
    //     NewSessionTicket) are consumed by the separate read drive (_trigger_ssl_read ->
    //     SSL_read on the rbio), never by SSL_write -- verified with a client issuing KeyUpdate
    //     mid-download (no WANT_READ, full body delivered).
    // The only residual opening is an operator opting into client renegotiation on a pre-3.0
    // OpenSSL build: 3.x refuses a client renegotiation inside SSL_read with a no_renegotiation
    // alert (ATS never sets SSL_OP_ALLOW_CLIENT_RENEGOTIATION), so SSL never re-enters init and
    // SSL_write cannot want a read -- verified against the master oracle, which fails the same
    // way. The layered BIO model has no path to service an in-write renegotiation read, and
    // ATS's policy is to abort renegotiation anyway, so close this one connection cleanly. (A
    // release-assert would be wrong here: unlike the WANT_WRITE case this is operator-reachable,
    // and crashing the whole server on it would be a DoS.)
    Dbg(dbg_ctl_ssl_error,
        "SSLNetVConnection %p: SSL_write wants a transport read (needs=%d); the layered BIO model cannot "
        "service an in-write renegotiation/post-handshake read, closing",
        this, needs);
    this->lerrno = EIO;
    _signal_user(SignalSide::WRITE, VC_EVENT_ERROR);
    _reclaimIfClosed();
    return EVENT_DONE;
  }

  if (ret < 0) {
    // A genuinely fatal SSL/transport error: -EPIPE for SSL_ERROR_SSL / SSL_ERROR_SYSCALL, or
    // -errno for SSL_ERROR_ZERO_RETURN. The benign retry return (-EAGAIN) is handled above, so
    // everything reaching here is unrecoverable.
    Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: _encrypt_data_for_transport failed: %" PRId64, this, ret);
    // NOTE: lerrno is set to a generic EIO; a more specific mapping from ret / the SSL error would
    // propagate to HttpSM::set_connect_fail() but is not currently distinguished.
    this->lerrno = EIO;
    _signal_user(SignalSide::WRITE, VC_EVENT_ERROR);
    _reclaimIfClosed();
    return EVENT_DONE;
  }

  // Even if user is complete, the write MIOBuffer might still contain data that needs to be sent by the transport. Check 'needs'.
  // Test for ALL bits of the mask: under USE_EDGE_TRIGGER, EVENTIO_READ and EVENTIO_WRITE
  // share the EPOLLET bit, so a plain `needs & EVENTIO_READ` is true whenever
  // EVENTIO_WRITE was set (and vice versa) and would re-arm the other face spuriously.
  if ((needs & EVENTIO_WRITE) == EVENTIO_WRITE) {
    // Write buffer may have be previously emptied by the transport, which causes the transport to disable the write vio.
    Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: Re-enabling transport write to flush BIO after user complete.", this);
    _transport_write_vio->reenable();
  }

  // _encrypt_data_for_transport only sets EVENTIO_READ together with a -EAGAIN return, which is
  // intercepted above, so EVENTIO_READ can never be set on this post-handshake write path.
  ink_assert((needs & EVENTIO_READ) != EVENTIO_READ);

  if (_user_write_vio.ntodo() <= 0) {
    Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: all plaintext encrypted, read_avail=%" PRId64, this,
        _write_buf_reader->read_avail());
    // All plaintext has been encrypted, but the ciphertext may still be buffered in
    // _write_buf. Defer WRITE_COMPLETE until it has drained to the transport: the consumer
    // closes the connection from its WRITE_COMPLETE handler, and signalling before the
    // bytes are on the wire lets that close truncate the response. Returning EVENT_CONT
    // keeps the inner transport's write_to_net flushing _write_buf in this same pass; we
    // re-enter once it drains and then signal completion.
    if (_write_buf_reader->read_avail() > 0) {
      _transport_write_vio->reenable();
      return EVENT_CONT;
    }
    // Plaintext done and ciphertext fully drained: deliver WRITE_COMPLETE now.
    return _deliverWriteComplete();
  } else {
    return EVENT_CONT;
  }
}

// Deliver the user-facing WRITE_COMPLETE synchronously -- deferring it (as earlier revisions
// of this code did) reopens exactly the receiver-liveness window this design closes: a
// scheduled delivery can outlive the consumer it targets (pool release, cross-thread
// migration, or a plain do_io_write/do_io_read reattachment can all retarget or tear down the
// consumer between when the delivery was armed and when it fires).
//
// That leaves one hazard to handle here instead: this runs nested inside the inner
// transport's net_write_io (reached from its WRITE_READY signal). If the consumer's
// WRITE_COMPLETE handler reentrantly calls do_io_write()+reenable() to queue a new write,
// that reenable() (see reenable()'s write-VIO branch) deliberately does not eagerly encrypt
// -- doing so would sever backpressure. So net_write_io's own still-executing tail finds
// _write_buf empty and calls write_disable(), undoing the reentrant reenable()'s
// write_ready_list enqueue before it can take effect (confirmed at both of net_write_io's ask
// sites, UnixNetVConnection.cc:707-710 and :775-778). Rather than deferring the *signal*
// again to dodge that, re-issue just the doomed reenable() from a clean, self-targeted
// dispatch once this net_write_io pass has fully unwound -- self-targeted, so it carries none
// of the receiver-liveness risk deferring the signal would.
int
SSLNetVConnection::_deliverWriteComplete()
{
  _signal_user(SignalSide::WRITE, VC_EVENT_WRITE_COMPLETE);
  if (_reclaimIfClosed()) {
    return EVENT_DONE; // consumer closed/freed us from its handler
  }
  if (_sslState != SslState::TERMINATED && _transport_state != TransportState::TRANSPORT_ERROR &&
      _user_write_vio.op == VIO::WRITE && !_user_write_vio.is_disabled() && _user_write_vio.ntodo() > 0) {
    _scheduleWriteRearm();
  }
  return EVENT_DONE;
}

void
SSLNetVConnection::_scheduleWriteRearm()
{
  _write_rearm_pending = true;
  if (!_deferred_work_pending()) {
    _deferred_work_event = this_ethread()->schedule_imm(this);
  }
}

int
SSLNetVConnection::_handle_transport_eos(VIO *vio)
{
  ink_release_assert(vio == _transport_read_vio);
  _transport_state = TransportState::TRANSPORT_CLOSED;
  // The peer FIN'd. Schedule an out-of-line read drive so any remaining decrypted
  // bytes are delivered and EOS is propagated to a waiting reader; the MIOBuffer
  // rbio cannot surface EOF itself. Out of line so we don't free this VC while the
  // inner transport's read path is still on the stack. Skip while closing: the
  // consumer is gone and we are only flushing our write side (the peer may have
  // half-closed its write while still reading our response).
  if (!_isDraining() && _sslState != SslState::TERMINATED && !_deferred_work_pending()) {
    _deferred_work_event = this_ethread()->schedule_imm(this);
  }
  return EVENT_DONE;
}

int
SSLNetVConnection::_handle_transport_error(VIO *vio, int err)
{
  ink_release_assert(vio == _transport_read_vio || vio == _transport_write_vio);
  Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: Handling transport error (VIO: %p, err: %d)", this, vio, err);

  // Mark the connection as broken and remember the transport errno so a waiting
  // reader can be told VC_EVENT_ERROR (vs a clean VC_EVENT_EOS) and propagate the
  // failure as a connection error rather than a closed connection.
  _transport_state = TransportState::TRANSPORT_ERROR;
  lerrno           = err;
  // If we were lingering to flush a response, the transport is now broken; abandon
  // the drain and tear down -- unless a hook is still parked (_freeBlocked), in which case the
  // plugin holds a live ref and will reenable; defer the free to that reenable's read-drive
  // rather than freeing the VC out from under it.
  if (_isDraining()) {
    if (!_freeBlocked()) {
      _sslState = SslState::TERMINATED;
      this->free_thread(this_ethread());
    }
    return EVENT_DONE;
  }
  // During the handshake deliver the error inline rather than via the scheduled read
  // drive: there is no decrypted data to flush, and the consumer (ConnectingEntry /
  // HttpSM waiting on the connect) issues its retry connect from this callback --
  // master signals inline from net_read_io, and the extra dispatch costs the retry a
  // couple of milliseconds, long enough to change which socket error a dying origin
  // hands the next attempt. Safe on this stack: the consumer's mutex is the one the
  // transport event was delivered under, a close from the handler takes the deferred
  // close-drain (no inline free of a VC the transport still references), and the
  // transport's error paths return straight after signalling without touching buffers.
  if (_sslState != SslState::TERMINATED && !getSSLHandShakeComplete()) {
    if (lerrno == 0) {
      lerrno = EPIPE;
    }
    _signal_user(_handshake_fail_side(), VC_EVENT_ERROR);
    _reclaimIfClosed();
    return EVENT_DONE;
  }
  // Surface the failure to an active write face directly. The read drive below only reaches a
  // reader whose read VIO is enabled; a consumer that disabled its read VIO while a body write is
  // still in flight (HttpSM disables origin reads after an early response) would otherwise get
  // neither ERROR nor completion -- the read drive bails at _trigger_ssl_read's disabled-read gate
  // and signals nobody, stranding the write to the inactivity timeout. Mirror master's
  // write_signal_and_update on a write error. Safe on this stack (see the handshake exit above): a
  // close from the handler takes the deferred close-drain, so this does not free a VC the transport
  // still references. The paired reclaim only frees a severed/absent consumer, so return if it did.
  if (_sslState != SslState::TERMINATED && _user_write_vio.op == VIO::WRITE && !_user_write_vio.is_disabled() &&
      _user_write_vio.ntodo() > 0) {
    if (lerrno == 0) {
      lerrno = EPIPE;
    }
    _signal_user(SignalSide::WRITE, VC_EVENT_ERROR);
    if (_reclaimIfClosed()) {
      return EVENT_DONE;
    }
  }
  // Schedule an out-of-line read drive so any decrypted bytes still buffered are
  // delivered and the error is surfaced to a waiting reader; the MIOBuffer rbio
  // cannot surface a transport error itself. Out of line so we do not free this VC
  // while the inner transport's read/write path is still on the stack (mirrors
  // _handle_transport_eos).
  if (_sslState != SslState::TERMINATED && !_deferred_work_pending()) {
    _deferred_work_event = this_ethread()->schedule_imm(this);
  }
  return EVENT_DONE;
}

int
SSLNetVConnection::startEvent(int event, void *data)
{
  this->thread = this_ethread();

  switch (event) {
  case NET_EVENT_OPEN:
  case NET_EVENT_ACCEPT: {
    // On a successful open/accept, data is the underlying transport VConnection.
    UnixNetVConnection *unvc = static_cast<UnixNetVConnection *>(data);
    ink_release_assert(unvc != nullptr);
    if (_connect_action.cancelled) {
      // The outbound consumer cancelled after the transport opened. Close the transport -- inline
      // under its NetHandler mutex when we can take it, so the fd closes now rather than on the
      // InactivityCop's next sweep (connectUp already started the cop, so a merely-marked-closed VC
      // is still reaped, just ~1s later) -- and discard this VC. (_connect_action is unused, never
      // cancelled, on the accept path.) Mirrors the destructor's _unvc close.
      if (unvc->nh != nullptr && unvc->nh->thread == this_ethread()) {
        MUTEX_TRY_LOCK(lock, unvc->nh->mutex, this_ethread());
        unvc->do_io_close();
      } else {
        unvc->do_io_close();
      }
      this->free_thread(thread);
      return EVENT_DONE;
    }
    ink_release_assert(this->_unvc == nullptr); // not wired up yet
    this->_unvc = unvc;
    SET_HANDLER(&SSLNetVConnection::mainEvent);
    // Once the handshake starts, we will need to be ready to write
    _transport_read_vio  = _unvc->do_io_read(this, INT64_MAX, _read_buf.get());
    _transport_write_vio = _unvc->do_io_write(this, INT64_MAX, _write_buf_reader.get(), false);
    // do_io_read/do_io_write only return nullptr when the VC is already closed, but the inner
    // unvc was just delivered synchronously via NET_EVENT_OPEN/ACCEPT on this stack and cannot be
    // closed yet (the reenable() paths make the same calls without a null check).
    ink_release_assert(_transport_read_vio != nullptr && _transport_write_vio != nullptr);
    // This should already be held by whoever requested the connect, so no blocking.
    // Use a scoped lock: it releases on scope exit (the prior MUTEX_TAKE_LOCK had no
    // matching MUTEX_UNTAKE_LOCK, permanently leaking a lock level on the shared
    // connection mutex and aborting in ink_mutex_destroy at teardown) and holds a
    // ref so the mutex survives if the continuation frees this VC.
    // The only writer of the SSL VC's open continuation is the outbound connect (SSLNetProcessor::
    // connect_re), which always supplies a continuation whose mutex is non-null (it sets
    // ssl_netvc->mutex = cont->mutex), so the null-mutex fallback is unreachable.
    if (Continuation *open_cont = _connect_action.continuation; open_cont != nullptr) {
      SCOPED_MUTEX_LOCK(lock, open_cont->mutex, this_ethread());
      open_cont->handleEvent(event, this);
    }
  } break;
  case NET_EVENT_OPEN_FAILED: {
    // Failed to establish TCP connection; data is the errno, not a VConnection.
    int res = reinterpret_cast<intptr_t>(data);
    lerrno  = -res;
    // Skip the notify if the consumer already cancelled -- it does not want the callback.
    if (!_connect_action.cancelled) {
      _connect_action.continuation->handleEvent(NET_EVENT_OPEN_FAILED, reinterpret_cast<void *>(res));
    }
    this->free_thread(thread);
  } break;
  default:
    Warning("SSLNetVConnection %p: Unexpected event %d in startEvent", this, event);
    ink_assert(false);
    break;
  }

  return EVENT_CONT;
}

int
SSLNetVConnection::mainEvent(int event, void *data)
{
  // A scheduled wakeup (schedule_imm from do_io_read / _handle_transport_eos to
  // drive a read after the transport already closed) arrives with an Event*, not
  // one of our transport VIOs. Handle it out of line, where freeing this VC is safe.
  if (data != _transport_read_vio && data != _transport_write_vio) {
    _deferred_work_event = nullptr; // this event is now firing

    // Consumer-driven teardown outranks everything: if the consumer closed us (or a close-drain
    // is finishing), complete the free -- never signal, never hand off.
    if (_isDraining()) {
      // Close-drain teardown deferred out of the inner transport's net_write_io. If the buffer
      // has drained, free on this clean stack; otherwise the drain is still in flight (the
      // transport reschedules itself), so wait for the next dispatch. A parked hook still holds a
      // live ref (_freeBlocked): hold off and let its reenable's read-drive complete the free.
      if ((!_write_buf_reader || _write_buf_reader->read_avail() == 0) && !_freeBlocked()) {
        _sslState = SslState::TERMINATED;
        this->free_thread(this_ethread());
      }
      return EVENT_DONE;
    }
    if (_close_requested) {
      _reclaimIfClosed();
      return EVENT_DONE;
    }

    // An armed fatal error (a handshake hook's reenable_with_event(TS_EVENT_ERROR), e.g. an
    // SNI/rate-limit reject) has no handshake driver on the stack to deliver it -- only this
    // scheduled dispatch. Deliver it to the waiter EXACTLY ONCE (the consumer's do_io_close then
    // drives the free); a severed/absent consumer hits _signal_user's null-cont owner-close. This
    // outranks a pending handoff so a tunnel_route action cannot swallow a later reject.
    if (_fatal_pending) {
      _fatal_pending = false;
      _signal_user(_handshake_fail_side(), VC_EVENT_ERROR);
      _reclaimIfClosed();
      return EVENT_DONE;
    }

    if (_pending_handoff == PendingHandoff::BLIND_TUNNEL) {
      // Safe place to free this VC inline: we return EVENT_DONE immediately after.
      _pending_handoff = PendingHandoff::NONE;
      _handoffBlindTunnel();
      return EVENT_DONE;
    }
    if (_pending_handoff == PendingHandoff::DOWNGRADE_PLAIN) {
      // Safe place to free this VC inline (see sslServerHandShakeEvent): we return EVENT_DONE
      // immediately after, so _downgradeToPlain()'s inline do_io_close() cannot pull `this` out
      // from under a caller still on the handshake read stack.
      _pending_handoff = PendingHandoff::NONE;
      _downgradeToPlain();
      return EVENT_DONE;
    }
    if (_write_rearm_pending) {
      // Re-issue the transport-write reenable() that a reentrant do_io_write() (from inside
      // _deliverWriteComplete's synchronous WRITE_COMPLETE handler) made while nested inside
      // net_write_io -- that reenable() was doomed there (see _deliverWriteComplete). We are
      // now on a clean stack, off net_write_io, so this reenable() actually takes effect.
      // Re-validate the write VIO here rather than trusting it's still what it was when this
      // was armed: the consumer may have closed, redirected, or disabled it in the interim.
      _write_rearm_pending = false;
      if (_sslState != SslState::TERMINATED && _transport_state != TransportState::TRANSPORT_ERROR &&
          _user_write_vio.op == VIO::WRITE && !_user_write_vio.is_disabled() && _user_write_vio.ntodo() > 0) {
        ink_assert(_transport_write_vio != nullptr && _transport_write_vio->op == VIO::WRITE);
        _transport_write_vio->reenable();
      }
      // The write-rearm and the rbio read-drive share the single _deferred_work_event slot
      // (both dispatch through this scheduled-event branch). On a keep-alive origin VC the
      // request-body write-rearm can fire while the response is already buffered as ciphertext
      // in the rbio; servicing the rearm above consumed the shared slot, so a co-pending
      // read drive would be dropped and the buffered response would strand -- the transport read
      // does not re-signal for data already in the rbio (INV-2/INV-4). Re-schedule the read drive.
      if (!_deferred_work_pending() && this->_ssl != nullptr && _user_read_vio.op == VIO::READ && !_user_read_vio.is_disabled() &&
          _user_read_vio.ntodo() > 0 &&
          (miobuffer_has_read_avail(SSL_get_rbio(this->_ssl.get())) || SSL_pending(this->_ssl.get()) > 0 || _early_data_pending() ||
           isTerminated(_transport_state))) {
        _deferred_work_event = this_ethread()->schedule_imm(this);
      }
      return EVENT_DONE;
    }
    _trigger_ssl_read();
    return EVENT_DONE;
  }

  VIO *transport_vio = static_cast<VIO *>(data);
  ink_release_assert(transport_vio == _transport_read_vio || transport_vio == _transport_write_vio);

  Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: handle_event received event %d from transport VIO %p", this, event, transport_vio);

  if (_sslState == SslState::TERMINATED) {
    // A transport event reached us already in a terminal state. If a fatal error is still armed
    // (an async reenable_with_event(TS_EVENT_ERROR) raced this event ahead of the scheduled
    // dispatch), deliver it to the waiter EXACTLY ONCE so the consumer can close us; otherwise the
    // error was already delivered and the consumer owns the teardown -- do not re-signal. Either
    // way, reap if the consumer has since closed (_reclaimIfClosed is a no-op until it has).
    if (_fatal_pending) {
      _fatal_pending = false;
      _signal_user(_handshake_fail_side(), VC_EVENT_ERROR);
    }
    _reclaimIfClosed();
    return EVENT_DONE;
  }

  // do_io_close() may have started a deferred close-drain (_sslState == SHUTDOWN_IN_PROGRESS,
  // which is not yet "terminated"). Once the consumer has closed us it has detached and may
  // already be freed, so a transport event arriving mid-drain must NOT be routed to its (now
  // dangling) continuation in _user_*_vio. The write path keeps flushing the drain and EOS/ERROR
  // tear down in their helpers (they all check _isDraining()), but an idle timeout and a
  // consumer-less read would otherwise reach _signal_user -- handle them here.
  if (_isDraining()) {
    switch (event) {
    case VC_EVENT_INACTIVITY_TIMEOUT:
    case VC_EVENT_ACTIVE_TIMEOUT:
      // The drain is stuck (idle); abandon it and tear down, mirroring _handle_transport_error --
      // unless a hook is still parked (_freeBlocked), where the plugin holds a live ref and will
      // reenable; defer the free to that reenable rather than freeing under the plugin.
      if (!_freeBlocked()) {
        _sslState = SslState::TERMINATED;
        this->free_thread(this_ethread());
        return EVENT_DONE;
      }
      return EVENT_CONT;
    case VC_EVENT_READ_READY:
    case VC_EVENT_READ_COMPLETE:
      // No consumer for inbound bytes during the drain; ignore and keep flushing the write side.
      return EVENT_CONT;
    default:
      break; // WRITE_*/EOS/ERROR fall through; their helpers handle the drain.
    }
  }

  switch (event) {
  case VC_EVENT_READ_READY:
  case VC_EVENT_READ_COMPLETE:
    return _handle_transport_read_ready(transport_vio); // Call helper
  case VC_EVENT_WRITE_READY:
  case VC_EVENT_WRITE_COMPLETE:
    return _handle_transport_write_ready(transport_vio); // Call helper
  case VC_EVENT_EOS:
    return _handle_transport_eos(transport_vio); // Call helper
  case VC_EVENT_ERROR:
    return _handle_transport_error(transport_vio, _unvc->lerrno); // Call helper
  case VC_EVENT_INACTIVITY_TIMEOUT:
  case VC_EVENT_ACTIVE_TIMEOUT:
    if (!getSSLHandShakeComplete()) {
      // A timeout before the handshake completes is the handshake timeout expiring (installed in
      // _trackFirstHandshake). The inner transport always times out on its read VIO, but the
      // waiter may be write-side -- a direct outbound connect installs only a do_io_write -- so
      // route to the waiter (_handshake_fail_side), not the transport face; otherwise the write
      // waiter is never told and HttpSM is left dangling (#5). Master tries read then write
      // (UnixNetVConnection.cc timeout dispatch).
      Dbg(dbg_ctl_ssl, "ssl handshake for vc %p expired, release the connection", this);
      _signal_user(_handshake_fail_side(), event);
      return _reclaimIfClosed() ? EVENT_DONE : EVENT_CONT;
    }
    // Propagate a post-handshake (idle/active) timeout to the consumer so it tears the connection
    // down, routed to whichever side's transport VIO timed out. Without this the SSL VC would
    // ignore transport timeouts (idle connections would never close) and log a spurious
    // "Unexpected event" warning.
    _signal_user(transport_vio == _transport_write_vio ? SignalSide::WRITE : SignalSide::READ, event);
    return _reclaimIfClosed() ? EVENT_DONE : EVENT_CONT;
  default:
    Warning("SSLNetVConnection %p: Unexpected event %d in handle_event", this, event);
    return EVENT_CONT;
  }
}

// A consumer (e.g. HttpSM) is (re)attaching to this VC to start I/O. On server-session reuse
// the new consumer runs under a different ProxyMutex than the one this VC adopted when it was
// first connected/pooled -- for a multiplexed origin, the establishing ConnectingEntry's mutex
// (HttpSM.cc set new_entry->mutex = this->mutex, then SSLNetProcessor::connect_re copied it onto
// the VC). The layered VC sits between the consumer and the transport: the transport VIOs name
// THIS VC as their continuation, so their mutex must equal this->mutex (write/read_signal_and_update
// only deliver when vio.mutex == vio.cont->mutex); and the consumer reenables those transport VIOs
// from its own stack, so set_enabled() requires that mutex be the consumer's. Both invariants hold
// only if the whole VC adopts the consumer's mutex. (Master never hits this: its transport VIO's
// continuation IS the consumer.) Cross-thread reuse is handled earlier by migration, so this is a
// same-thread mutex adoption; it is a no-op once the mutexes already coincide.
void
SSLNetVConnection::_adoptConsumerMutex(Continuation *c)
{
  if (c == nullptr || c->mutex == nullptr || c->mutex == this->mutex) {
    return;
  }
  ink_release_assert(_unvc == nullptr || _unvc->thread == nullptr || _unvc->thread == this_ethread());
  this->mutex = c->mutex;
  if (_unvc != nullptr) {
    _unvc->mutex = c->mutex;
  }
  if (_transport_read_vio != nullptr) {
    _transport_read_vio->mutex = c->mutex;
  }
  if (_transport_write_vio != nullptr) {
    _transport_write_vio->mutex = c->mutex;
  }
  // Any out-of-line read drive was scheduled under the old mutex; reschedule it under the new one
  // so it does not dispatch this VC's mainEvent holding the wrong lock.
  if (_deferred_work_event != nullptr) {
    _deferred_work_event->cancel();
    _deferred_work_event = this_ethread()->schedule_imm(this);
  }
}

VIO *
SSLNetVConnection::do_io_read(Continuation *c, int64_t nbytes, MIOBuffer *buf)
{
  if (_sslState == SslState::TERMINATED && !(c == nullptr && nbytes == 0 && buf == nullptr)) {
    Error("do_io_read invoked on closed vc %p, cont %p, nbytes %" PRId64 ", buf %p", this, c, nbytes, buf);
    return nullptr;
  }

  _user_read_vio.op        = VIO::READ;
  _user_read_vio.mutex     = c ? c->mutex : this->mutex;
  _user_read_vio.cont      = c;
  _user_read_vio.nbytes    = nbytes;
  _user_read_vio.ndone     = 0;
  _user_read_vio.vc_server = this;
  if (buf) {
    // User wants to start a read
    _user_read_vio.set_writer(buf);
    _adoptConsumerMutex(c);
    if (!isTerminated(_transport_state)) {
      // Ask the transport for more socket data.
      _user_read_vio.reenable();
    }
    // For a real (non-zero) read, also drive an SSL read out of line. The
    // ciphertext for this read may already be buffered in the rbio (e.g. a request
    // body that arrived in the same TLS record(s) as the headers), in which case no
    // further transport read event will arrive to drive it. This also surfaces EOS
    // when the transport is already closed. Out of line so we don't re-enter the
    // caller and free this VC underneath it.
    if (nbytes != 0 && !_deferred_work_pending()) {
      _deferred_work_event = this_ethread()->schedule_imm(this);
    }
  } else {
    // User wants to stop reading
    _user_read_vio.disable();
    _user_read_vio.buffer.clear();
    _transport_read_vio->disable();
  }
  return &_user_read_vio;
}

VIO *
SSLNetVConnection::do_io_write(Continuation *c, int64_t nbytes, IOBufferReader *reader, bool owner)
{
  if (_sslState == SslState::TERMINATED && !(c == nullptr && nbytes == 0 && reader == nullptr)) {
    Error("do_io_write invoked on closed vc %p, cont %p, nbytes %" PRId64 ", reader %p", this, c, nbytes, reader);
    return nullptr;
  }
  _user_write_vio.op        = VIO::WRITE;
  _user_write_vio.mutex     = c ? c->mutex : this->mutex;
  _user_write_vio.cont      = c;
  _user_write_vio.nbytes    = nbytes;
  _user_write_vio.ndone     = 0;
  _user_write_vio.vc_server = this;
  if (reader) {
    ink_assert(!owner);
    _user_write_vio.set_reader(reader);
    _adoptConsumerMutex(c);
    _user_write_vio.reenable();
  } else {
    _user_write_vio.disable();
  }
  return &_user_write_vio;
}

void
SSLNetVConnection::set_open_continuation(Continuation *a)
{
  _connect_action = a;
}

Continuation *
SSLNetVConnection::get_open_continuation() const
{
  return _connect_action.continuation;
}

void
SSLNetVConnection::do_io_shutdown(ShutdownHowTo_t howto)
{
  ink_assert(_unvc != nullptr);

  // A blind tunnel is forwarded raw -- there is no TLS layer here to shut down, so a
  // half-close is a plain transport half-close. (In the layered model a pure BLIND tunnel
  // is handed to a dedicated pass-through VC and normally never reaches this SSL VC;
  // FORWARD/PARTIAL_BLIND terminate TLS and take the TLS-aware path below.)
  if (get_tunnel_type() == SNIRoutingType::BLIND) {
    _unvc->do_io_shutdown(howto);
    return;
  }

  bool const shutdown_read  = howto == IO_SHUTDOWN_READ || howto == IO_SHUTDOWN_READWRITE;
  bool const shutdown_write = howto == IO_SHUTDOWN_WRITE || howto == IO_SHUTDOWN_READWRITE;

  if (shutdown_read) {
    // A TLS read half-close means "stop delivering application data to the consumer", not a
    // raw shutdown(SHUT_RD) on the socket: the peer closes the read direction with its own
    // close-notify and we may still owe it a response on the write side. Quiesce the
    // consumer- and transport-facing reads only (mirrors the do_io_read(nullptr) stop path).
    _user_read_vio.disable();
    _user_read_vio.buffer.clear();
    if (_transport_read_vio != nullptr) {
      _transport_read_vio->disable();
    }
  }

  if (shutdown_write) {
    // A TLS write half-close means "send a close-notify and stop writing application data" --
    // NOT a raw TCP FIN (which truncates still-buffered ciphertext and skips the close-notify)
    // and NOT clearing the transport write VIO out from under the still-live SSL VC. Queue the
    // close-notify into _write_buf (the wbio) via SSL_shutdown and let the transport drain it.
    // Keep the VC alive: the consumer half-closes to flush the response and wait for the peer
    // to close (avoiding a truncating RST); teardown happens later in do_io_close.
    if (getSSLHandShakeComplete() && _ssl.get() != nullptr && _sslState != SslState::TERMINATED &&
        _transport_state != TransportState::TRANSPORT_ERROR) {
      if (!(SSL_get_shutdown(_ssl.get()) & SSL_SENT_SHUTDOWN)) {
        // May synchronously invoke a registered hook (session-ticket), which may itself call
        // back into us.
        int ret;
        {
          RecursionGuard openssl_guard(recursion);
          ret = SSL_shutdown(_ssl.get());
        }
        Dbg(dbg_ctl_ssl_shutdown, "do_io_shutdown(WRITE): SSL_shutdown %s vc %p", (ret ? "success" : "queued"), this);
      }
    }
    // Stop accepting plaintext from the consumer so a transport write-ready during the drain
    // no-ops instead of re-signalling WRITE_COMPLETE.
    _user_write_vio.disable();
    // Re-arm the (now disabled) transport write so net_write_io flushes the close-notify.
    // _write_buf is non-empty here, so net_write_io reschedules itself until it drains and is
    // not subject to the empty-buffer write_disable race that forces off-stack WRITE_COMPLETE.
    if (_write_buf_reader && _write_buf_reader->read_avail() > 0 && _transport_write_vio != nullptr &&
        _transport_state != TransportState::TRANSPORT_ERROR) {
      _transport_write_vio->reenable();
    }
  }
}

void
SSLNetVConnection::set_active_timeout(ink_hrtime timeout_in)
{
  ink_assert(_unvc != nullptr);
  _unvc->set_active_timeout(timeout_in);
}

void
SSLNetVConnection::set_inactivity_timeout(ink_hrtime timeout_in)
{
  ink_assert(_unvc != nullptr);
  _unvc->set_inactivity_timeout(timeout_in);
}

void
SSLNetVConnection::set_default_inactivity_timeout(ink_hrtime timeout_in)
{
  ink_assert(_unvc != nullptr);
  _unvc->set_default_inactivity_timeout(timeout_in);
}

bool
SSLNetVConnection::is_default_inactivity_timeout()
{
  ink_assert(_unvc != nullptr);
  return _unvc->is_default_inactivity_timeout();
}

void
SSLNetVConnection::cancel_active_timeout()
{
  ink_assert(_unvc != nullptr);
  _unvc->cancel_active_timeout();
}
void
SSLNetVConnection::cancel_inactivity_timeout()
{
  ink_assert(_unvc != nullptr);
  _unvc->cancel_inactivity_timeout();
}

void
SSLNetVConnection::add_to_keep_alive_queue()
{
  ink_assert(_unvc != nullptr);
  _unvc->add_to_keep_alive_queue();
}

void
SSLNetVConnection::remove_from_keep_alive_queue()
{
  ink_assert(_unvc != nullptr);
  _unvc->remove_from_keep_alive_queue();
}

bool
SSLNetVConnection::add_to_active_queue()
{
  ink_assert(_unvc != nullptr);
  return _unvc->add_to_active_queue();
}

ink_hrtime
SSLNetVConnection::get_active_timeout()
{
  ink_assert(_unvc != nullptr);
  return _unvc->get_active_timeout();
}

ink_hrtime
SSLNetVConnection::get_inactivity_timeout()
{
  ink_assert(_unvc != nullptr);
  return _unvc->get_inactivity_timeout();
}

void
SSLNetVConnection::apply_options()
{
  ink_assert(_unvc != nullptr);
  // Mirror the SSL VC's options to the inner transport before applying. Plugins or hook handlers may
  // have mutated the SSL VC's options struct after the unvc was constructed, so the unvc's view can be stale.
  _unvc->options = this->options;
  _unvc->apply_options();
}

void
SSLNetVConnection::reenable(VIO *vio)
{
  ink_assert(_unvc != nullptr);
  if (vio == &_user_read_vio) {
    // Reenable read
    // startEvent (NET_EVENT_OPEN/ACCEPT) creates both transport VIOs up front and aborts on
    // failure before any consumer can obtain this VC, so a live VC always has a non-null
    // transport read VIO -- the lazy-initiate arm is unreachable.
    ink_assert(_transport_read_vio != nullptr && _transport_read_vio->op == VIO::READ);
    _transport_read_vio->reenable();
    // The rbio may already hold ciphertext that arrived while the consumer's read was
    // disabled -- e.g. an H2 response body buffered in the same socket read as the response
    // headers, where the consumer (H2 session) disables its read while dispatching the header
    // frame and re-enables only after setting up the body tunnel. Re-arming the transport read
    // just asks the kernel for MORE bytes; under edge-triggered epoll no fresh readiness event
    // fires for data already drained into the rbio, so that buffered record would sit
    // undelivered until an unrelated socket event kicks the loop. Drive an SSL read out of line
    // to deliver it now (mirrors do_io_read's buffered-ciphertext drive). Out of line so we do
    // not re-enter the consumer that is reenabling us. A terminated transport needs the same
    // drive: EOS/ERROR is a persistent state and the closed transport will never re-signal, so
    // a consumer re-enabling its read must observe it from the drive.
    if (this->_ssl != nullptr && !_deferred_work_pending() && !_user_read_vio.is_disabled() &&
        (miobuffer_has_read_avail(SSL_get_rbio(this->_ssl.get())) || SSL_pending(this->_ssl.get()) > 0 || _early_data_pending() ||
         isTerminated(_transport_state))) {
      _deferred_work_event = this_ethread()->schedule_imm(this);
    }
  } else if (vio == &_user_write_vio) {
    // Reenable write.
    //
    // We have the option here to eagerly encrypt the consumer's plaintext into
    // _write_buf right now. We deliberately do NOT: encrypting ahead of the
    // socket's ability to send would bloat _write_buf (up to the full response)
    // and sever end-to-end backpressure (the consumer's write "completes" at
    // memory speed, so it keeps producing). Instead we stay demand-driven -- we
    // just re-arm the transport write and wait for the socket to tell us it has
    // room (a transport WRITE_READY), and only then encrypt, in
    // _handle_transport_write_ready. That keeps _write_buf to ~one TLS record and
    // lets backpressure propagate up to the origin/cache.
    //
    // The catch: reenable()ing the transport with an empty _write_buf is a false
    // "I have bytes" promise -- net_write_io will find it empty and write_disable.
    // That is fine *only* on a clean stack: when this reenable runs nested inside
    // the transport's net_write_io (e.g. a consumer issuing a follow-up write from
    // its synchronously-delivered WRITE_COMPLETE handler), that same net_write_io's
    // tail disables the write before the demand-driven WRITE_READY can fire, and the
    // write stalls. _deliverWriteComplete handles that case by re-issuing this same
    // reenable() from a clean, self-targeted dispatch (_scheduleWriteRearm) once
    // net_write_io's current pass has unwound -- see its definition for the full
    // trace. This reenable() itself doesn't need to know which case it's in.
    // Symmetric with the read side: both transport VIOs are created atomically in startEvent
    // before any consumer can reach this VC, so the lazy-initiate arm is unreachable.
    ink_assert(_transport_write_vio != nullptr && _transport_write_vio->op == VIO::WRITE);
    _transport_write_vio->reenable();
  } else {
    ink_assert(false); // Unknown VIO
  }
}

void
SSLNetVConnection::reenable_re(VIO *vio)
{
  ink_assert(_unvc != nullptr);
  // Do not forward the outer user VIO straight to the inner transport: this VIO is embedded in
  // the SSL VC, not in _unvc's NetState, and UnixNetVConnection::reenable_re -> set_enabled()
  // derives the inner NetState from the VIO address with STATE_FROM_VIO pointer arithmetic
  // (UnixNetVConnection.cc:39) -- a wild write when handed a foreign VIO, and the read/write
  // classification would be wrong too. Delegate to reenable(), which does the correct
  // user->transport translation. Mirror of TunnelNetVConnection::reenable_re.
  reenable(vio);
}

bool
SSLNetVConnection::get_data(int id, void *data)
{
  union {
    TSVIO *vio;
    void  *data;
    int   *n;
  } ptr;

  ptr.data = data;

  // Expose the consumer-facing (outer) VIOs and logical closed state, not the inner transport's;
  // without this override the base VConnection::get_data returns false and TSVConnReadVIOGet /
  // TSVConnWriteVIOGet / TSVConnClosedGet silently fail for a TLS-terminated connection.
  switch (id) {
  case TS_API_DATA_READ_VIO:
    *ptr.vio = reinterpret_cast<TSVIO>(&this->_user_read_vio);
    return true;
  case TS_API_DATA_WRITE_VIO:
    *ptr.vio = reinterpret_cast<TSVIO>(&this->_user_write_vio);
    return true;
  case TS_API_DATA_CLOSED:
    // "Closed" means the consumer requested the close (or a drain is finishing it), matching
    // master's separate `closed` state -- not merely that the SSL state went terminal, which under
    // consumer-driven teardown can hold on a still-open, not-yet-closed VC (e.g. H2 with active
    // streams after an error).
    *ptr.n = (_close_requested || _isDraining()) ? 1 : 0;
    return true;
  default:
    return false;
  }
}

SOCKET
SSLNetVConnection::get_socket()
{
  ink_assert(_unvc != nullptr);
  return _unvc->get_socket();
}

int
SSLNetVConnection::set_tcp_congestion_control(NetVConnection::tcp_congestion_control_side side)
{
  ink_assert(_unvc != nullptr);
  return _unvc->set_tcp_congestion_control(side);
}

void
SSLNetVConnection::set_local_addr()
{
  ink_assert(_unvc != nullptr);
  _unvc->set_local_addr();
  ats_ip_copy(&local_addr, _unvc->get_local_addr());
}

void
SSLNetVConnection::set_remote_addr()
{
  ink_assert(_unvc != nullptr);
  _unvc->set_remote_addr();
  ats_ip_copy(&remote_addr, _unvc->get_remote_addr());
}

void
SSLNetVConnection::set_remote_addr(const sockaddr *addr)
{
  ats_ip_copy(&remote_addr, addr);
}

void
SSLNetVConnection::set_mptcp_state()
{
  ink_assert(_unvc != nullptr);
  _unvc->set_mptcp_state();
}

#if TS_USE_TLS_ASYNC
void
SSLNetVConnection::handle_async_tls_ready()
{
  // The async-job wait fd (registered with epoll via async_ep) is read-ready: the
  // engine's deferred private-key operation has completed. As in the hook-resume path
  // (reenable_with_event), the peer's handshake bytes were already consumed into the SSL
  // read BIO, so reenabling the transport read VIO alone would not re-drive
  // SSL_do_handshake(). Schedule an out-of-line read-drive to re-enter the handshake
  // (mainEvent -> _trigger_ssl_read -> _ssl_accept), which resumes the suspended job.
  if (!getSSLHandShakeComplete() && !_deferred_work_pending()) {
    _deferred_work_event = this->thread->schedule_imm(this);
  }
}
#endif

void
SSLNetVConnection::_trackFirstHandshake()
{
  bool is_first = this->get_tls_handshake_begin_time() == 0;
  if (is_first) {
    this->_record_tls_handshake_begin_time();
    // Install the handshake inactivity timeout atomically with recording the begin time, but only
    // for inbound handshakes. net_activity is not triggered until the handshake completes, so an
    // idle inbound partial handshake is otherwise bounded only by the looser default inactivity
    // timeout (recording the timestamp separately from installing the timer left the install
    // gated on a timestamp this call had already set, so ssl.handshake_timeout_in never took
    // effect). An outbound origin handshake is bounded by connect_attempts_timeout (HttpSM);
    // overwriting the VC inactivity timeout here would defeat it (see tls_conn_timeout).
    if (get_context() == NET_VCONNECTION_IN) {
      set_inactivity_timeout(HRTIME_SECONDS(SSLConfigParams::ssl_handshake_timeout_in));
    }
  }
}
