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
#include "P_SSLConfig.h"

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
                          public TLSBasicSupport,
                          public AsyncTLSEventCallback
{
private:
  // SSL state management
  enum class SslState {
    INIT                  = 0, // SSL object not created or initialized
    HANDSHAKE_WANTED      = 1, // Ready to start or continue the SSL handshake
    HANDSHAKE_IN_PROGRESS = 2, // SSL_connect or SSL_accept called, waiting for IO
    HANDSHAKE_DONE        = 3, // Handshake complete, ready for application data
    SHUTDOWN_WANTED       = 4, // Application requested close, SSL_shutdown needs to run
    SHUTDOWN_IN_PROGRESS  = 5, // SSL_shutdown called, waiting for IO or peer close_notify
    CLOSED                = 6, // Clean SSL shutdown complete (close_notify sent/received)
    ERROR                 = 7  // An SSL error occurred (handshake, read/write, or shutdown)
  };
  enum SslState _sslState = SslState::INIT;
  static bool
  isTerminated(SslState state)
  {
    return state == SslState::CLOSED || state == SslState::ERROR;
  }

public:
  int  sslStartHandShake(int event, int &err);
  void clear();
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

  int sslServerHandShakeEvent(int &err);
  int sslClientHandShakeEvent(int &err);

  // NetVConnection
  VIO       *do_io_read(Continuation *c, int64_t nbytes, MIOBuffer *buf) override;
  VIO       *do_io_write(Continuation *c, int64_t nbytes, IOBufferReader *reader, bool owner) override;
  void       do_io_close(int lerrno = -1) override;
  void       do_io_shutdown(ShutdownHowTo_t howto) override;
  void       set_active_timeout(ink_hrtime timeout_in) override;
  void       set_inactivity_timeout(ink_hrtime timeout_in) override;
  void       set_default_inactivity_timeout(ink_hrtime timeout_in) override;
  bool       is_default_inactivity_timeout() override;
  void       cancel_active_timeout() override;
  void       cancel_inactivity_timeout() override;
  void       set_action(Continuation *c) override;
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

  // AsyncTLSEventCallback
  void handle_async_tls_ready() override;

  ////////////////////////////////////////////////////////////
  // Instances of NetVConnection should be allocated        //
  // only from the free list using NetVConnection::alloc(). //
  // The constructor is public just to avoid compile errors.//
  ////////////////////////////////////////////////////////////
  explicit SSLNetVConnection(UnixNetVConnection *unvc);
  SSLNetVConnection() = delete;
  ~SSLNetVConnection() override {}

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

  int64_t read_raw_data();

  void
  initialize_handshake_buffers()
  {
    this->handShakeHolder    = this->_read_buf->alloc_reader();
    this->handShakeBioStored = 0;
  }

  void
  free_handshake_buffers()
  {
    if (this->handShakeHolder) {
      this->handShakeHolder->dealloc();
    }
    this->handShakeHolder    = nullptr;
    this->handShakeBioStored = 0;
  }

  int         populate_protocol(std::string_view *results, int n) const override;
  const char *protocol_contains(std::string_view tag) const override;

  SSL       *ssl               = nullptr;
  ink_hrtime sslLastWriteTime  = 0;
  int64_t    sslTotalBytesSent = 0;

  std::shared_ptr<SSL_SESSION> client_sess = nullptr;

  /// Set by asynchronous hooks to request a specific operation.
  SslVConnOp hookOpRequested = SslVConnOp::SSL_HOOK_OP_DEFAULT;

  // noncopyable
  SSLNetVConnection(const SSLNetVConnection &)            = delete;
  SSLNetVConnection &operator=(const SSLNetVConnection &) = delete;

  NetVConnection *migrateToCurrentThread(Continuation *cont, EThread *t) override;

  bool          protocol_mask_set = false;
  unsigned long protocol_mask     = 0;

  bool
  peer_provided_cert() const override
  {
#ifdef OPENSSL_IS_OPENSSL3
    X509 *cert = SSL_get1_peer_certificate(this->ssl);
#else
    X509 *cert = SSL_get_peer_certificate(this->ssl);
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
    return this->ssl;
  }
  ssl_curve_id _get_tls_curve() const override;
  int          _verify_certificate(X509_STORE_CTX *ctx) override;

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
  int              handShakeBioStored          = 0;

  bool transparentPassThrough = false;
  bool allowPlain             = false;

  int sent_cert = 0;

  int64_t redoWriteSize = 0;

  // Null-terminated string, or nullptr if there is no SNI server name.
  std::unique_ptr<char[]> _ca_cert_file;
  std::unique_ptr<char[]> _ca_cert_dir;

  // Async TLS related
#if TS_USE_TLS_ASYNC
  AsyncTLSEventIO            async_ep{*this};
  std::vector<OSSL_ASYNC_FD> async_fds{};
#endif

  // early data related stuff
#if TS_HAS_TLS_EARLY_DATA
  bool            _early_data_finish = false;
  MIOBuffer      *_early_data_buf    = nullptr;
  IOBufferReader *_early_data_reader = nullptr;
#endif

  void                _trigger_ssl_read();
  int64_t             _encrypt_data_for_transport(int64_t towrite, MIOBufferAccessor &buf, int64_t &total_written, int &needs);
  void                _make_ssl_connection(SSL_CTX *ctx);
  void                _bindSSLObject();
  void                _unbindSSLObject();
  UnixNetVConnection *_downgradeToPlain();
  void                _propagateHandShakeBuffer(UnixNetVConnection *target, EThread *t);

  int         _ssl_read_from_net(int64_t &ret);
  ssl_error_t _ssl_read_buffer(void *buf, int64_t nbytes, int64_t &nread);
  ssl_error_t _ssl_write_buffer(const void *buf, int64_t nbytes, int64_t &nwritten);
  ssl_error_t _ssl_connect();
  ssl_error_t _ssl_accept();

  bool _is_tunnel_endpoint{false};
  void _in_context_tunnel();
  void _out_context_tunnel();

  UnixNetVConnection *_unvc = nullptr; // underlying TCP connection
  // We give these VIOs to our consumer
  VIO _user_read_vio;
  VIO _user_write_vio;
  // The transport protocol (usually TCP) gives these to us
  VIO *_transport_read_vio;
  VIO *_transport_write_vio;
  enum class SignalSide { READ, WRITE };
  int _signal_user(SignalSide side, int event);

  // TODO: is this actually needed?
  int recursion = 0;

  MIOBuffer      *_read_buf         = nullptr;
  MIOBuffer      *_write_buf        = nullptr;
  IOBufferReader *_write_buf_reader = nullptr;
  BIO            *_rbio             = nullptr;
  BIO            *_wbio             = nullptr;

public:
  void mark_as_tunnel_endpoint() override;
  bool from_accept_thread{false};

  // initial connect or accept event handler
  int startEvent(int event, void *data);
  // transport events handling function
  int mainEvent(int event, void *data);

private:
  enum class TransportState {
    TRANSPORT_INIT,       // Initial state, not connected
    TRANSPORT_CONNECTING, // TCP connection requested
    TRANSPORT_CONNECTED,  // TCP connection established
    TRANSPORT_CLOSED,     // TCP connection received EOS or normal close initiated
    TRANSPORT_ERROR       // TCP connection encountered an error
  };
  TransportState _transport_state = TransportState::TRANSPORT_INIT;
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

  Action _action;
};

extern ClassAllocator<SSLNetVConnection> sslNetVCAllocator;
