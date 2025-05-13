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

  // Only set up the bio stuff for the server side
  this->initialize_handshake_buffers();

  std::unique_ptr<BIO, decltype(&BIO_vfree)> rbio = make_resource(BIO_new(BIO_s_miobuffer()), BIO_vfree);
  if (rbio == nullptr) {
    return;
  }

  if (miobuffer_set_buffer(rbio.get(), _read_buf.get()) == 0) {
    return;
  }

  std::unique_ptr<BIO, decltype(&BIO_vfree)> wbio = make_resource(BIO_new(BIO_s_miobuffer()), BIO_vfree);
  if (wbio == nullptr) {
    return;
  }

  if (miobuffer_set_buffer(wbio.get(), _write_buf.get()) == 0) {
    return;
  }
  SSL_set_bio(temp_ssl.get(), rbio.get(), wbio.get());

#if TS_HAS_TLS_EARLY_DATA
  update_early_data_config(temp_ssl.get(), SSLConfigParams::server_max_early_data, SSLConfigParams::server_recv_max_early_data);
#endif

  this->_wbio = std::move(wbio);
  this->_rbio = std::move(rbio);
  this->_ssl  = std::move(temp_ssl);

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

void
SSLNetVConnection::_unbindSSLObject()
{
  SSLNetVCDetach(this->_ssl.get());
  TLSBasicSupport::unbind(this->_ssl.get());
  TLSEventSupport::unbind(this->_ssl.get());
  ALPNSupport::unbind(this->_ssl.get());
  TLSSessionResumptionSupport::unbind(this->_ssl.get());
  TLSSNISupport::unbind(this->_ssl.get());
  TLSEarlyDataSupport::unbind(this->_ssl.get());
  TLSTunnelSupport::unbind(this->_ssl.get());
  TLSCertSwitchSupport::unbind(this->_ssl.get());
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
 * @param reader MIOBuffer with read data.  This buffer will be advanced to consume the header.
 * @return > 0: A proxy protocol header was successfully parsed.
 * @return 0: No header found.
 * @return -ENOTCONN: Source IP is not in the allowlist.
 * @return -EAGAIN: Not enough data to determine if the header is present.
 */
int
SSLNetVConnection::_parse_proxy_protocol(IOBufferReader *reader)
{
  swoc::IPRangeSet *pp_ipmap;
  pp_ipmap = SSLConfigParams::proxy_protocol_ip_addrs;

  if (this->get_is_proxy_protocol() && this->get_proxy_protocol_version() == ProxyProtocolVersion::UNDEFINED) {
    Dbg(dbg_ctl_proxyprotocol, "proxy protocol is enabled on this port");
    if (pp_ipmap != nullptr && pp_ipmap->count() > 0) {
      Dbg(dbg_ctl_proxyprotocol, "proxy protocol has a configured allowlist of trusted IPs - checking");
      if (!pp_ipmap->contains(swoc::IPAddr(get_remote_addr()))) {
        Dbg(dbg_ctl_proxyprotocol, "Source IP is NOT in the configured allowlist of trusted IPs - closing connection");
        return -ENOTCONN; // Need a quick close/exit here to refuse the connection!!!!!!!!!
      } else {
        char new_host[INET6_ADDRSTRLEN];
        Dbg(dbg_ctl_proxyprotocol, "Source IP [%s] is in the trusted allowlist for proxy protocol",
            ats_ip_ntop(this->get_remote_addr(), new_host, sizeof(new_host)));
      }
    } else {
      Dbg(dbg_ctl_proxyprotocol, "proxy protocol DOES NOT have a configured allowlist of trusted IPs but "
                                 "proxy protocol is enabled on this port - processing all connections");
    }

    // FIXME: if there isn't enough data to determine if the header is present, we should return -EAGAIN.
    // This will require refactoring has_proxy_protocol.
    if (has_proxy_protocol(reader)) {
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
      Dbg(dbg_ctl_proxyprotocol, "proxy protocol was enabled, but Proxy Protocol header was not present");
    }
  }
  return 0;
}

//
// Signal an event
//
int
SSLNetVConnection::_signal_user(SignalSide side, int event)
{
  bool closed = false;
  recursion++;
  VIO        &vio      = side == SignalSide::READ ? _user_read_vio : _user_write_vio;
  const char *side_str = side == SignalSide::READ ? "read" : "write";
  if (vio.cont && _user_read_vio.mutex == vio.cont->mutex) {
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
      Dbg(dbg_ctl_inactivity_cop, "%s event %d: null vio cont, closing vc %p", side_str, event, this);
      closed = true;
      break;
    default:
      Error("Unexpected %s event %d for vc %p", side_str, event, this);
      ink_release_assert(0);
      break;
    }
  }
  if (!--recursion && closed) {
    /* BZ  31932 */
    ink_assert(thread == this_ethread());
    // FIXME: delete this
    return EVENT_DONE;
  } else {
    return EVENT_CONT;
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

  MUTEX_TRY_LOCK(lock, _user_read_vio.mutex, this_ethread());
  // vio.mutex should be the same as the UnixNetVConnection's vio.mutex, so it should always be locked
  ink_release_assert(lock.is_locked());

  // If the key renegotiation failed it's over, just signal the error and finish.
  if (sslClientRenegotiationAbort == true) {
    _signal_user(SignalSide::READ, -ENET_SSL_FAILED);
    Dbg(dbg_ctl_ssl, "client renegotiation setting read signal error");
    return;
  }

  // If it is not enabled, lower its priority.  This allows
  // a fast connection to speed match a slower connection by
  // shifting down in priority even if it could read.
  if (_user_read_vio.op != VIO::READ || _user_read_vio.is_disabled()) {
    _transport_read_vio->disable();
    return;
  }

  MIOBufferAccessor &buf   = _user_read_vio.buffer;
  int64_t            ntodo = _user_read_vio.ntodo();
  ink_assert(buf.writer());

  // Continue on if we are still in the handshake
  if (!getSSLHandShakeComplete()) {
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
      // Now in blind tunnel. Set things up to read what is in the buffer
      // Must send the READ_COMPLETE here before considering
      // forwarding on the handshake buffer, so the
      // SSLNextProtocolTrampoline has a chance to do its
      // thing before forwarding the buffers.
      _signal_user(SignalSide::READ, VC_EVENT_READ_COMPLETE);

      // If the handshake isn't set yet, this means the tunnel
      // decision was make in the SNI callback.  We must move
      // the client hello message back into the standard read_vio
      // so it will get forwarded onto the origin server

      // TODO: Need to do something for tunneling.  Maybe give the transport VIO to our user and peace out?
      ink_release_assert(false);
#if 0
      if (!this->getSSLHandShakeComplete()) {
        this->ssl.get()HandshakeStatus = SSLHandshakeStatus::SSL_HANDSHAKE_DONE;

        // Copy over all data already read in during the SSL_accept
        // (the client hello message)
        NetState          *s    = &this->read;
        MIOBufferAccessor &buf  = s->vio.buffer;
        int64_t            r    = buf.writer()->write(this->handShakeHolder);
        s->vio.nbytes          += r;
        s->vio.ndone           += r;

        // Clean up the handshake buffers
        this->free_handshake_buffers();

        if (r > 0) {
          // Kick things again, so the data that was copied into the
          // vio.read buffer gets processed
          this->readSignalDone(VC_EVENT_READ_COMPLETE, nh);
        }
      }
#endif
      return; // Leave if we are tunneling
    }
    switch (ret) {
    case EVENT_ERROR:
      lerrno = err;
      _signal_user(SignalSide::READ, VC_EVENT_ERROR);
      break;
    case SSL_HANDSHAKE_WANT_READ:
    case SSL_HANDSHAKE_WANT_ACCEPT:
      if (SSLConfigParams::ssl_handshake_timeout_in > 0) {
        double handshake_time = (static_cast<double>(ink_get_hrtime() - this->get_tls_handshake_begin_time()) / 1000000000);
        Dbg(dbg_ctl_ssl, "ssl handshake for vc %p, took %.3f seconds, configured handshake_timer: %d", this, handshake_time,
            SSLConfigParams::ssl_handshake_timeout_in);
        if (handshake_time > SSLConfigParams::ssl_handshake_timeout_in) {
          Dbg(dbg_ctl_ssl, "ssl handshake for vc %p, expired, release the connection", this);
          lerrno = ETIMEDOUT;
          _signal_user(SignalSide::READ, VC_EVENT_ERROR);
          return;
        }
      }
      break;
    case SSL_HANDSHAKE_WANT_CONNECT:
      Dbg(dbg_ctl_ssl, "ssl wants to connect for vc %p", this);
      break;
    case SSL_HANDSHAKE_WANT_WRITE:
      Dbg(dbg_ctl_ssl, "ssl wants to write for vc %p", this);
      break;
    case EVENT_DONE:
      Dbg(dbg_ctl_ssl, "ssl handshake EVENT_DONE vc %p ntodo=%" PRId64, this, ntodo);
      // If this was driven by a zero length read, signal complete when
      // the handshake is complete.
      if (ntodo <= 0) {
        _signal_user(SignalSide::READ, VC_EVENT_READ_COMPLETE);
      }
      break;
    case SSL_WAIT_FOR_HOOK:
      Dbg(dbg_ctl_ssl, "ssl wait for hook for vc %p", this);
    case SSL_WAIT_FOR_ASYNC:
      Dbg(dbg_ctl_ssl, "ssl wait for async for vc %p", this);
      break;
    default:
      break;
    }
    return;
  }

  // If there is nothing to do or no space available, disable connection
  if (ntodo <= 0 || !buf.writer()->write_avail() || _user_read_vio.is_disabled()) {
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

  if (bytes > 0) {
    if (ret == SSL_READ_WOULD_BLOCK || ret == SSL_READ_READY) {
      if (_signal_user(SignalSide::READ, VC_EVENT_READ_READY) != EVENT_CONT) {
        Dbg(dbg_ctl_ssl, "readSignal != EVENT_CONT");
        return;
      }
    }
  }

  int wants = SSL_want(this->_ssl.get());
  Dbg(dbg_ctl_ssl, "SSL_want=%d", wants);
  switch (ret) {
  case SSL_READ_READY:
    _transport_read_vio->reenable();
    return;
    break;
  case SSL_WRITE_WOULD_BLOCK:
    _transport_write_vio->reenable();
    Dbg(dbg_ctl_ssl, "read finished - would block - need write");
  case SSL_READ_WOULD_BLOCK:
    _transport_read_vio->reenable();
    Dbg(dbg_ctl_ssl, "read finished - would block - need read");
    break;

  case SSL_READ_EOS:
    ink_release_assert(!"Shouldn't get EOS from our buffer.");
    break;
  case SSL_READ_COMPLETE:
    Dbg(dbg_ctl_ssl, "read finished - signal done");
    _signal_user(SignalSide::READ, VC_EVENT_READ_COMPLETE);
    break;
  case SSL_READ_ERROR:
    Dbg(dbg_ctl_ssl, "read finished - read error");
    _signal_user(SignalSide::READ, VC_EVENT_ERROR);
    _unvc->do_io_close(ssl_read_errno);
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
    //
    // TS-4424: Don't mess with record size if last SSL_write failed with
    // needs write
    if (redoWriteSize) {
      l             = redoWriteSize;
      redoWriteSize = 0;
    } else {
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
  } while (num_really_written == try_to_write && total_written < towrite);

  if (total_written > 0) {
    sslLastWriteTime   = now;
    sslTotalBytesSent += total_written;
  }
  redoWriteSize = 0;
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
#ifdef SSL_ERROR_WANT_CLIENT_HELLO_CB
    case SSL_ERROR_WANT_CLIENT_HELLO_CB:
#endif
    case SSL_ERROR_WANT_X509_LOOKUP: {
      if (SSL_ERROR_WANT_WRITE == err) {
        redoWriteSize = l;
      }
      needs              |= EVENTIO_WRITE;
      num_really_written  = -EAGAIN;
      Dbg(dbg_ctl_ssl_error, "SSL_write-SSL_ERROR_WANT_WRITE");
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

SSLNetVConnection::SSLNetVConnection(UnixNetVConnection *unvc)
  : _ssl{nullptr, SSL_free},
    _read_buf{make_resource(new_MIOBuffer(SSLConfigParams::ssl_misc_max_iobuffer_size_index), free_MIOBuffer)},
    _write_buf{make_resource(new_MIOBuffer(SSLConfigParams::ssl_misc_max_iobuffer_size_index), free_MIOBuffer)},
    _write_buf_reader{make_resource(_write_buf->alloc_reader(), [](IOBufferReader *r) { r->dealloc(); })},
    _rbio{nullptr, BIO_vfree},
    _wbio{nullptr, BIO_vfree}
{
  this->_set_service(static_cast<ALPNSupport *>(this));
  this->_set_service(static_cast<TLSBasicSupport *>(this));
  this->_set_service(static_cast<TLSEventSupport *>(this));
  this->_set_service(static_cast<TLSCertSwitchSupport *>(this));
  this->_set_service(static_cast<TLSEarlyDataSupport *>(this));
  this->_set_service(static_cast<TLSSNISupport *>(this));
  this->_set_service(static_cast<TLSSessionResumptionSupport *>(this));
  this->_set_service(static_cast<TLSTunnelSupport *>(this));
  this->_unvc = unvc;
  SET_HANDLER(&SSLNetVConnection::startEvent);
}

void
SSLNetVConnection::do_io_close([[maybe_unused]] int lerrno)
{
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

      // Check if the peer has already sent a FIN
      // Do this by checking if our read buffer has data
      // TODO: is this possible after the refactor?
      bool do_shutdown = true;

      if (do_shutdown) {
        // Send the close-notify
        int ret = SSL_shutdown(this->_ssl.get());
        Dbg(dbg_ctl_ssl_shutdown, "SSL_shutdown %s", (ret) ? "success" : "failed");
      } else {
        // Request a quiet shutdown to OpenSSL
        SSL_set_quiet_shutdown(this->_ssl.get(), 1);
        SSL_set_shutdown(this->_ssl.get(), SSL_RECEIVED_SHUTDOWN | SSL_SENT_SHUTDOWN);
        Dbg(dbg_ctl_ssl_shutdown, "Enable quiet shutdown");
      }
    }
  }

  // TODO: do_io_read and do_io_write on the remaining bytes
  // do_io_close() on the unvc will happen when SSL data has fully finished
}

void
SSLNetVConnection::clear()
{
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

  clear();
}

int
SSLNetVConnection::sslStartHandShake(int event, int &err)
{
  if (TSSystemState::is_ssl_handshaking_stopped()) {
    Dbg(dbg_ctl_ssl, "Stopping handshake due to server shutting down.");
    return EVENT_ERROR;
  }
  if (this->get_tls_handshake_begin_time() == 0) {
    this->_record_tls_handshake_begin_time();
    // net_activity will not be triggered until after the handshake
    set_inactivity_timeout(HRTIME_SECONDS(SSLConfigParams::ssl_handshake_timeout_in));
  }
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
            caCertFilePath = Layout::get()->relative_to(params->clientCACertPath, options.ssl_client_ca_cert_name);
          }
          Dbg(dbg_ctl_ssl, "Using outbound client cert `%s'", options.ssl_client_cert_name.get());
        } else {
          Dbg(dbg_ctl_ssl, "Clearing outbound client cert");
        }
        sharedCTX =
          params->getCTX(certFilePath, keyFilePath, caCertFilePath.empty() ? params->clientCACertFilename : caCertFilePath.c_str(),
                         params->clientCACertPath);
      } else if (options.ssl_client_ca_cert_name) {
        std::string caCertFilePath = Layout::get()->relative_to(params->clientCACertPath, options.ssl_client_ca_cert_name);
        sharedCTX = params->getCTX(params->clientCertPath, params->clientKeyPath, caCertFilePath.c_str(), params->clientCACertPath);
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

  if (!this->handShakeHolder->is_read_avail_more_than(0)) {
#if TS_USE_TLS_ASYNC
    if (SSLConfigParams::async_handshake_enabled) {
      SSL_set_mode(this->_ssl.get(), SSL_MODE_ASYNC);
    }
#endif
    Dbg(dbg_ctl_ssl, "%p first read\n", this);
    // Read from socket to fill in the BIO buffer with the
    // raw handshake data before calling the ssl accept calls.
    auto reader = make_resource(this->_read_buf->alloc_reader(), [](IOBufferReader *reader) { reader->dealloc(); });
    int  retval = this->_parse_proxy_protocol(reader.get());
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
  }

  _sslState             = SslState::HANDSHAKE_IN_PROGRESS;
  ssl_error_t ssl_error = this->_ssl_accept();
#if TS_USE_TLS_ASYNC
  if (ssl_error == SSL_ERROR_WANT_ASYNC) {
    // Do we need to set up the async eventfd?  Or is it already registered?
    if (async_ep.fd < 0) {
      size_t         numfds;
      OSSL_ASYNC_FD *waitfds;
      // Set up the epoll entry for the signalling
      if (SSL_get_all_async_fds(this->_ssl.get(), nullptr, &numfds) && numfds > 0) {
        // Allocate space for the waitfd on the stack, should only be one most all of the time
        async_fds.reserve(numfds);
        waitfds = async_fds.data();
        if (SSL_get_all_async_fds(this->_ssl.get(), waitfds, &numfds) && numfds > 0) {
          PollDescriptor *pd = get_PollDescriptor(this_ethread());
          this->async_ep.start(pd, {waitfds, numfds});
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

    char *buf = _read_buf->buf();
    if (buf && *buf != SSL_OP_HANDSHAKE) {
      SSLVCDebug(this, "SSL hanshake error with bad HS buffer");
      if (getAllowPlain()) {
        SSLVCDebug(this, "Try plain");
        // If this doesn't look like a ClientHello, convert this connection to a UnixNetVC and send the
        // packet for Http Processing
        this->_downgradeToPlain();
        return SSL_RESTART;
      } else if (getTransparentPassThrough()) {
        // start a blind tunnel if tr-pass is set and data does not look like ClientHello
        SSLVCDebug(this, "Data does not look like SSL handshake, starting blind tunnel");
        this->attributes = HttpProxyPort::TRANSPORT_BLIND_TUNNEL;
        _sslState        = SslState::HANDSHAKE_IN_PROGRESS;
        return EVENT_CONT;
      } else {
        SSLVCDebug(this, "Give up");
      }
    }
  }

  switch (ssl_error) {
  case SSL_ERROR_NONE:
    if (dbg_ctl_ssl.on()) {
#ifdef OPENSSL_IS_OPENSSL3
      X509 *cert = SSL_get1_peer_certificate(this->_ssl.get());
#else
      X509 *cert = SSL_get_peer_certificate(this->ssl.get());
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
      _sslState        = SslState::HANDSHAKE_IN_PROGRESS;
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
      // Outbound PROXY Protocol
      VIO    &vio     = this->_user_write_vio;
      int64_t ntodo   = vio.ntodo();
      int64_t towrite = vio.get_reader()->read_avail();

      if (ntodo > 0 && towrite > 0) {
        MIOBufferAccessor &buf           = vio.buffer;
        int                needs         = 0;
        int64_t            total_written = 0;
        int64_t            r             = _encrypt_data_for_transport(towrite, buf, total_written, needs);

        if (total_written > 0) {
          vio.ndone += total_written;
          if (vio.ntodo() != 0) {
            return SSL_WAIT_FOR_HOOK;
          }
        }

        if (r < 0) {
          if (r == -EAGAIN || r == -ENOTCONN || -r == EINPROGRESS) {
            return SSL_WAIT_FOR_HOOK;
          } else {
            return EVENT_ERROR;
          }
        }
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
      X509 *cert = SSL_get_peer_certificate(this->ssl.get());
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
    // TODO: if we ever turn off transport write, turn it on here

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
    _sslState = SslState::ERROR;
  }

  resume_tls_event();

  if (invoke_tls_event() == 2) {
    _transport_write_vio->reenable();
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
  return Ptr<ProxyMutex>{nullptr};
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
 * Close down the current netVC.  Save aside the socket and SSL information
 * and create new netVC in the current thread/netVC
 */
NetVConnection *
SSLNetVConnection::migrateToCurrentThread(Continuation *, EThread *)
{
  /*
  SSL *save_ssl = this->ssl.get();

  this->_unbindSSLObject();
  this->ssl.get() = nullptr;
  */

  // FIXME
  ink_release_assert(false);
  return nullptr;
}

void
SSLNetVConnection::_propagateHandShakeBuffer(UnixNetVConnection *target, EThread *t)
{
  Dbg(dbg_ctl_ssl, "allow-plain, handshake buffer ready to read=%" PRId64, this->handShakeHolder->read_avail());
  // Take ownership of the handShake buffer
  _sslState   = SslState::HANDSHAKE_DONE;
  NetState *s = &target->read;
  s->vio.set_writer(this->_read_buf.get());
  s->vio.set_reader(this->handShakeHolder);
  this->handShakeHolder = nullptr;
  this->_read_buf       = nullptr;
  s->vio.vc_server      = target;
  s->vio.cont           = this->_user_read_vio.cont;
  s->vio.mutex          = this->_user_read_vio.cont->mutex;

  // Kick things again, so the data that was copied into the
  // vio.read buffer gets processed
  target->readSignalDone(VC_EVENT_READ_COMPLETE, get_NetHandler(t));
}

/*
 * Replaces the current SSLNetVConnection with a UnixNetVConnection
 * Propagates any data in the SSL handShakeBuffer to be processed
 * by the UnixNetVConnection logic
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
    _unvc->set_context(get_context());
    _unvc->options = this->options;
    Dbg(dbg_ctl_ssl, "Move to unixvc for allow-plain");
    _propagateHandShakeBuffer(_unvc, t);
  }

  // Do not mark this closed until the end so it does not get freed by the other thread too soon
  do_io_close();
  return _unvc;
}

ssl_curve_id
SSLNetVConnection::_get_tls_curve() const
{
  if (getSSLSessionCacheHit()) {
    return getSSLCurveNID();
  } else {
    return SSLGetCurveNID(this->_ssl.get());
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
  if (get_context() == NET_VCONNECTION_IN) {
    this->callHooks(TS_EVENT_SSL_VERIFY_CLIENT /* , ctx */);
  } else {
    this->callHooks(TS_EVENT_SSL_VERIFY_SERVER /* , ctx */);
  }

  if (_sslState == SslState::ERROR) {
    return 1;
  }

  return 0;
}

ssl_error_t
SSLNetVConnection::_ssl_accept()
{
  ERR_clear_error();

  int ret       = 0;
  int ssl_error = SSL_ERROR_NONE;

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
      ret = SSL_accept(this->ssl.get());
      if (ret <= 0) {
        had_error_on_reading_early_data = true;
      } else {
        if (SSL_in_early_data(this->ssl.get())) {
          ret                         = SSL_read(this->ssl.get(), block->buf(), index_to_buffer_size(BUFFER_SIZE_INDEX_16K));
          finished_reading_early_data = !SSL_in_early_data(this->ssl.get());
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
  ret = SSL_accept(this->ssl.get());
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

  int ret = SSL_connect(this->_ssl.get());

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
  // If SSL_write_early_data is available, it's probably OpenSSL,
  // and SSL_is_init_finished should be available.
  // If SSL_write_early_data is unavailable, its' probably BoringSSL,
  // and we can use SSL_write to send early data.
#if TS_HAS_TLS_EARLY_DATA
  if (SSL_version(this->_ssl.get()) >= TLS1_3_VERSION) {
#ifdef HAVE_SSL_WRITE_EARLY_DATA
    if (SSL_is_init_finished(this->ssl.get())) {
#endif
      ret = SSL_write(this->_ssl.get(), buf, static_cast<int>(nbytes));
#ifdef HAVE_SSL_WRITE_EARLY_DATA
    } else {
      size_t nwrite;
      ret = SSL_write_early_data(this->ssl.get(), buf, static_cast<size_t>(nbytes), &nwrite);
      if (ret == 1) {
        ret = nwrite;
      }
    }
#endif
  } else {
    ret = SSL_write(this->_ssl.get(), buf, static_cast<int>(nbytes));
  }
#else
  ret = SSL_write(this->ssl.get(), buf, static_cast<int>(nbytes));
#endif

  if (ret > 0) {
    nwritten = ret;
    BIO *bio = SSL_get_wbio(this->_ssl.get());
    if (bio != nullptr) {
      (void)BIO_flush(bio);
    }
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
      if (SSL_in_early_data(this->ssl.get())) {
        ret                         = SSL_read(this->ssl.get(), buf, nbytes);
        finished_reading_early_data = !SSL_in_early_data(this->ssl.get());
        if (ret < 0) {
          if (!finished_reading_early_data) {
            had_error_on_reading_early_data = true;
            ssl_error                       = SSL_get_error(this->ssl.get(), ret);
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

  if (isTerminated(_sslState)) {
    Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: terminated, ignoring read ready", this);
    return EVENT_DONE;
  }

  if (isTerminated(_transport_state)) {
    Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: transport closed, but we have data to read", this);
  }

  if (_transport_read_vio->is_disabled()) {
    Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: transport read VIO is disabled", this);
    return EVENT_CONT;
  }

  _trigger_ssl_read();

  if (isTerminated(_sslState)) {
    Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: Closed during _trigger_ssl_read", this);
    return EVENT_DONE;
  } else {
    return EVENT_CONT;
  }
}

int
SSLNetVConnection::_handle_transport_write_ready(VIO *vio)
{
  ink_release_assert(vio == _transport_write_vio);
  Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: Handling transport write ready (VIO: %p)", this, vio);

  if (_sslState == SslState::HANDSHAKE_IN_PROGRESS) {
    // FIXME: continue handshake
    return EVENT_CONT;
  }

  MUTEX_TRY_LOCK(lock, _user_write_vio.mutex, this_ethread());
  if (!lock.is_locked()) {
    _transport_write_vio->reenable(); // Retry later
    return EVENT_CONT;
  }

  if (isTerminated(_sslState) || isTerminated(_transport_state)) {
    Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: terminated, ignoring write ready", this);
    _transport_write_vio->disable();
    return EVENT_DONE;
  }

  Continuation *user_cont = _user_write_vio.cont; // Save original continuation for reentrancy check
  if (_user_write_vio.op != VIO::WRITE || _user_write_vio.is_disabled()) {
    Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: User write VIO not active or disabled.", this);
    return EVENT_DONE;
  }

  int64_t ntodo = _user_write_vio.ntodo();

  // Give user a chance to fill buffer
  bool signalled_ready = false;
  // No high_water check here.  The user should do its own flow control for sending.  Only give backpressure when the
  // SSL transport is unable to send.
  if (ntodo > 0) {
    if (_signal_user(SignalSide::WRITE, VC_EVENT_WRITE_READY) == EVENT_DONE) {
      // User closed connection in the handler
      return EVENT_DONE;
    }
    signalled_ready = true;

    // The user may have stopped a do_io_write, or even started a new one
    if (_user_write_vio.cont != user_cont || _user_write_vio.op != VIO::WRITE || _user_write_vio.is_disabled()) {
      Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: User VIO changed during WRITE_READY signal.", this);
      // User changed the VIO, stop processing for this event.
      // The next event or reenable call will handle the new state.
      return EVENT_CONT;
    }
    ntodo = _user_write_vio.ntodo(); // Update ntodo after potential user action
  }

  // User reduced amount of data to write.
  if (ntodo <= 0) {
    Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: User write VIO ntodo <= 0.", this);
    // If we signalled ready but now there's nothing to do, signal complete.
    if (signalled_ready) {
      if (_signal_user(SignalSide::WRITE, VC_EVENT_WRITE_COMPLETE) == EVENT_DONE) {
        return EVENT_DONE;
      }
    }
    // There might be data left in _write_buf.  Don't disable the transport write.
    return EVENT_DONE;
  }

  int64_t total_plaintext_written = 0; // Bytes of *plaintext* consumed from user buffer
  int     needs                   = 0; // Flags for transport read/write needed by SSL layer/BIOs
  int64_t ret                     = _encrypt_data_for_transport(ntodo, _user_write_vio.buffer, total_plaintext_written, needs);

  if (total_plaintext_written > 0) {
    _user_write_vio.ndone += total_plaintext_written;
  }

  if (ret < 0) {
    // ret < 0 from _encrypt_data_for_transport indicates an SSL error (not WANT_READ/WRITE)
    Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: _encrypt_data_for_transport failed: %" PRId64, this, ret);
    // TODO: Map 'ret' or internal SSL error code to lerrno if possible
    this->lerrno = EIO; // Generic I/O error for now
    _signal_user(SignalSide::WRITE, VC_EVENT_ERROR);
    return EVENT_DONE;
  }

  // Even if user is complete, the write MIOBuffer might still contain data that needs to be sent by the transport. Check 'needs'.
  if (needs & EVENTIO_WRITE) {
    // Write buffer may have be previously emptied by the transport, which causes the transport to disable the write vio.
    Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: Re-enabling transport write to flush BIO after user complete.", this);
    // _unvc->trapWriteBufferEmpty();
    _transport_write_vio->reenable();
  }

  // Even if the user has disabled read, we still need to read in order to complete the write.
  if (needs & EVENTIO_READ) {
    Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: Re-enabling transport read (WANT_READ) after user complete.", this);
    _transport_read_vio->reenable(); // Signal transport to read
  }

  if (_user_write_vio.ntodo() <= 0) {
    Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: User write VIO complete after encryption.", this);
    _signal_user(SignalSide::WRITE, VC_EVENT_WRITE_COMPLETE);
    return EVENT_DONE;
  } else {
    return EVENT_CONT;
  }
}

int
SSLNetVConnection::_handle_transport_eos(VIO *vio)
{
  ink_release_assert(vio == _transport_read_vio);
  _transport_state = TransportState::TRANSPORT_CLOSED;
  return EVENT_DONE;
}

int
SSLNetVConnection::_handle_transport_error(VIO *vio, int err)
{
  ink_release_assert(vio == _transport_read_vio || vio == _transport_write_vio);
  Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: Handling transport error (VIO: %p, err: %d)", this, vio, err);

  // Mark the connection as closed.
  _transport_state = TransportState::TRANSPORT_ERROR;
  return EVENT_DONE;
}

int
SSLNetVConnection::acceptEvent(int event, void *data)
{
  MUTEX_TRY_LOCK(trylock, this->mutex, this_ethread());
  if (!trylock.is_locked()) {
    this_ethread()->schedule_in(this, net_retry_delay);
  }
  SET_HANDLER(&SSLNetVConnection::startEvent);

  return handleEvent(event, data);
}

int
SSLNetVConnection::startEvent(int event, void *data)
{
  UnixNetVConnection *unvc = static_cast<UnixNetVConnection *>(data);
  thread                   = this_ethread();
  switch (event) {
  case NET_EVENT_OPEN:
  case NET_EVENT_ACCEPT:
    // Successful establishment of TCP connection
    // This is where we would set up the SSL context and start the handshake.
    _transport_state = TransportState::TRANSPORT_CONNECTED;
    ink_release_assert(unvc != nullptr);
    ink_release_assert(_unvc == unvc);
    SET_HANDLER(&SSLNetVConnection::mainEvent);
    ink_release_assert(_sslState == SslState::INIT);
    _sslState = SslState::HANDSHAKE_WANTED;
    // Once the handshake starts, we will need to be ready to write
    // _unvc->trapWriteBufferEmpty();
    _transport_write_vio = _unvc->do_io_write(this, INT64_MAX, _write_buf_reader.get(), false);
    if (_transport_write_vio == nullptr) {
      // Failed to create transport write VIO
      Error("SSLNetVConnection %p: Failed to start writing", this);
      _sslState        = SslState::ERROR;
      _transport_state = TransportState::TRANSPORT_ERROR;
      return EVENT_DONE;
    }
    break;
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
  VIO *transport_vio = static_cast<VIO *>(data);
  ink_release_assert(transport_vio == _transport_read_vio || transport_vio == _transport_write_vio);

  Dbg(dbg_ctl_ssl_io, "SSLNetVConnection %p: handle_event received event %d from transport VIO %p", this, event, transport_vio);

  if (isTerminated(_sslState)) {
    return EVENT_DONE;
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
  default:
    Warning("SSLNetVConnection %p: Unexpected event %d in handle_event", this, event);
    return EVENT_CONT;
  }
}

VIO *
SSLNetVConnection::do_io_read(Continuation *c, int64_t nbytes, MIOBuffer *buf)
{
  if (isTerminated(_sslState) && !(c == nullptr && nbytes == 0 && buf == nullptr)) {
    Error("do_io_read invoked on closed vc %p, cont %p, nbytes %" PRId64 ", buf %p", this, c, nbytes, buf);
    return nullptr;
  }

  ink_assert(_transport_state == TransportState::TRANSPORT_CONNECTED);

  _user_read_vio.op        = VIO::READ;
  _user_read_vio.mutex     = c ? c->mutex : this->mutex;
  _user_read_vio.cont      = c;
  _user_read_vio.nbytes    = nbytes;
  _user_read_vio.ndone     = 0;
  _user_read_vio.vc_server = this;
  if (buf) {
    // User wants to start a read
    _user_read_vio.set_writer(buf);
    _user_read_vio.reenable();
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
  if (isTerminated(_sslState) && !(c == nullptr && nbytes == 0 && reader == nullptr)) {
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
    _user_write_vio.reenable();
  } else {
    _user_write_vio.disable();
  }
  return &_user_write_vio;
}

void
SSLNetVConnection::set_action(Continuation *a)
{
  _action = a;
}

void
SSLNetVConnection::do_io_shutdown(ShutdownHowTo_t howto)
{
  ink_assert(_unvc != nullptr);
  _unvc->do_io_shutdown(howto);
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
  // TODO
}

void
SSLNetVConnection::reenable(VIO *vio)
{
  ink_assert(_unvc != nullptr);
  if (vio == &_user_read_vio) {
    // Reenable read
    if (!_transport_read_vio) {
      // Initiate transport read
      ink_assert(_read_buf != nullptr);
      _transport_read_vio = _unvc->do_io_read(this, INT64_MAX, this->_read_buf.get());
    } else {
      // Reenable existing transport read
      ink_assert(_transport_read_vio->op == VIO::READ);
      _transport_read_vio->reenable();
    }
  } else if (vio == &_user_write_vio) {
    // Reenable write
    if (!_transport_write_vio) {
      // Initiate transport write
      ink_assert(_write_buf_reader != nullptr);
      _transport_write_vio = _unvc->do_io_write(this, INT64_MAX, this->_write_buf_reader.get(), false);
    } else {
      // Reenable existing transport write
      ink_assert(_transport_write_vio->op == VIO::WRITE);
      _transport_write_vio->reenable();
    }
  } else {
    ink_assert(false); // Unknown VIO
  }

  _unvc->reenable(vio);
}

void
SSLNetVConnection::reenable_re(VIO *vio)
{
  ink_assert(_unvc != nullptr);
  _unvc->reenable_re(vio);
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

void
SSLNetVConnection::handle_async_tls_ready()
{
}
