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

#include "ssl_reducer_harness.h"

#include <cerrno>

#include "../SSLStats.h"
#include "../P_SSLConfig.h"
#include "../P_SSLCertLookup.h"

#include "api/LifecycleAPIHooks.h"
#include "iocore/eventsystem/EThread.h"
#include "iocore/net/SSLAPIHooks.h"
#include "iocore/net/SSLSNIConfig.h"
#include "records/RecCore.h"
#include "tscore/Layout.h"
#include "tscore/ink_platform.h"
#include "ts/InkAPIPrivateIOCore.h"

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

#include <fstream>
#include <filesystem>
#include <mutex>
#include <unistd.h>

namespace
{
// Bring up the SSL runtime the SUT's handshake needs but unit_test_main does not install:
//   * SSLInitializeLibrary() reserves the per-SSL ex_data indices (ssl_vc_index and every
//     TLS*Support index). Without it _bind_ssl_object binds to index -1 and getInstance(_ssl)
//     returns null, tripping sslClientHandShakeEvent's identity assert. Idempotent.
//   * SNIConfig::startup() loads the SNI config the outbound handshake driver always consults
//     (_setup_client_ssl). A missing sni.yaml loads an empty, no-op config.
//   * SSLInitializeStatistics() registers the ssl_rsb counters the handshake increments; without
//     it Metrics::Counter::increment aborts on an unregistered id. It skips its cert-dependent
//     cipher/group enumeration when no certificate config is loaded, so it is safe here.
//   * init_global_lifecycle_hooks() allocates g_lifecycle_hooks, which the inbound cert loader
//     dereferences unconditionally (SSLSecret::loadSecret consults TS_LIFECYCLE_SSL_SECRET_HOOK).
//     Production allocates it in api_init(); the unit_test_main does not.
// Production pairs these in SSLNetProcessor::start; do the same once, before any fixture runs.
void
ensure_ssl_runtime()
{
  static std::once_flag once;
  std::call_once(once, [] {
    SSLInitializeLibrary();
    SNIConfig::startup();
    SSLInitializeStatistics();
    if (g_lifecycle_hooks == nullptr) {
      init_global_lifecycle_hooks();
    }
  });
}

bool               g_hook_fired = false;
bool               g_hook_armed = false;
SSLNetVConnection *g_hook_vc    = nullptr;
INKContInternal   *g_hook_cont  = nullptr; // process-global parking hook; held here so it stays reachable

// One-shot cert hook. The chain is process-global and append-only, so once registered this callback
// fires for every inbound handshake -- including those of unrelated tests. To avoid polluting them,
// it parks only the single armed handshake (records the VC and returns without reenabling, so
// callHooks() reports "not reenabled" and SSL_accept pauses), then disarms itself. Every other
// handshake takes the pass-through branch and reenables synchronously (the ordinary way a
// synchronous plugin lets a handshake proceed), so it completes as if no hook were present.
int
reducer_cert_hook_cb(TSCont /* contp */, TSEvent /* event */, void *edata)
{
  auto *vc = static_cast<SSLNetVConnection *>(edata);
  if (g_hook_armed) {
    g_hook_armed = false; // one-shot: park this handshake only
    g_hook_fired = true;
    g_hook_vc    = vc;
    return 0; // park: do not reenable
  }
  vc->reenable_with_event(TS_EVENT_CONTINUE); // disarmed: pass through so unrelated handshakes finish
  return 0;
}

bool             g_verify_close_armed  = false;
bool             g_verify_close_fired  = false;
int              g_verify_close_lerrno = -1;      // -1 = graceful close (drain); anything else = abort
INKContInternal *g_verify_close_cont   = nullptr; // process-global closing verify hook; held so it stays reachable

// One-shot verify-server hook (see the header). Runs nested inside the failing SSL_connect frame:
// the in-hook do_io_close severs the user VIOs and arms the graceful close-drain (lerrno -1) or
// authorizes the reclaim (an abort lerrno), and the ERROR reenable records the verify verdict
// (_verify_hook_failed) that makes the ENFORCED policy fail SSL_connect on this very round.
int
reducer_closing_verify_hook_cb(TSCont /* contp */, TSEvent /* event */, void *edata)
{
  auto *vc = static_cast<SSLNetVConnection *>(edata);
  if (g_verify_close_armed) {
    g_verify_close_armed = false; // one-shot: close only the armed handshake
    g_verify_close_fired = true;
    vc->do_io_close(g_verify_close_lerrno);
    vc->reenable_with_event(TS_EVENT_ERROR);
    return 0;
  }
  vc->reenable_with_event(TS_EVENT_CONTINUE); // disarmed: pass through so unrelated handshakes finish
  return 0;
}
} // namespace

void
reducer_install_parking_cert_hook()
{
  g_hook_fired = false;
  g_hook_vc    = nullptr;
  g_hook_armed = true; // arm the next inbound handshake to park
  if (g_hook_cont == nullptr) {
    // Register the cert hook once for the whole process: the hook chain is global, so re-appending
    // would stack duplicate parks. Construct the continuation directly rather than via
    // TSContCreate()/TSMutexCreate() -- those live in libtsapi.so, which test_net does not link
    // (only INKContInternal, from libtsapibackend.a, is available); this mirrors what TSContCreate
    // does internally. The cont is a deliberate never-freed registration (as a real plugin's hook
    // is); holding it in g_hook_cont keeps it reachable so LSan does not flag it.
    g_hook_cont = new INKContInternal(reducer_cert_hook_cb, reinterpret_cast<TSMutex>(new_ProxyMutex()));
    SSLAPIHooks::instance()->append(TSSslHookInternalID{TS_SSL_CERT_HOOK}, g_hook_cont);
  }
}

void
reducer_install_closing_verify_hook(int lerrno)
{
  g_verify_close_fired  = false;
  g_verify_close_lerrno = lerrno;
  g_verify_close_armed  = true; // arm the next outbound verify to close in-hook
  if (g_verify_close_cont == nullptr) {
    // Register once for the whole process (same rationale and construction as the parking cert
    // hook above: the hook chain is global and append-only, and TSContCreate lives in a library
    // test_net does not link).
    g_verify_close_cont = new INKContInternal(reducer_closing_verify_hook_cb, reinterpret_cast<TSMutex>(new_ProxyMutex()));
    SSLAPIHooks::instance()->append(TSSslHookInternalID{TS_SSL_VERIFY_SERVER_HOOK}, g_verify_close_cont);
  }
}

bool
reducer_closing_verify_hook_fired()
{
  return g_verify_close_fired;
}

bool
reducer_hook_fired()
{
  return g_hook_fired;
}

SSLNetVConnection *
reducer_hook_vc()
{
  return g_hook_vc;
}

void
reducer_make_self_signed(std::string &cert_pem, std::string &key_pem)
{
  EVP_PKEY     *pkey = nullptr;
  EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
  EVP_PKEY_keygen_init(pctx);
  EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048);
  EVP_PKEY_keygen(pctx, &pkey);
  EVP_PKEY_CTX_free(pctx);

  X509 *x = X509_new();
  X509_set_version(x, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(x), 1);
  X509_gmtime_adj(X509_getm_notBefore(x), 0);
  X509_gmtime_adj(X509_getm_notAfter(x), 60 * 60 * 24 * 365);
  X509_set_pubkey(x, pkey);
  X509_NAME *name = X509_get_subject_name(x);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("reducer.test"), -1, -1, 0);
  X509_set_issuer_name(x, name);
  X509_sign(x, pkey, EVP_sha256());

  BIO *cbio = BIO_new(BIO_s_mem());
  PEM_write_bio_X509(cbio, x);
  BIO *kbio = BIO_new(BIO_s_mem());
  PEM_write_bio_PrivateKey(kbio, pkey, nullptr, nullptr, 0, nullptr, nullptr);

  char *data = nullptr;
  long  len  = BIO_get_mem_data(cbio, &data);
  cert_pem.assign(data, len);
  len = BIO_get_mem_data(kbio, &data);
  key_pem.assign(data, len);

  BIO_free(cbio);
  BIO_free(kbio);
  X509_free(x);
  EVP_PKEY_free(pkey);
}

void
reducer_install_server_cert(const std::string &cert_pem, const std::string &key_pem, const std::string &dir)
{
  ensure_ssl_runtime(); // the cert loader dereferences g_lifecycle_hooks; make this callable standalone

  std::filesystem::create_directories(dir);

  const std::string cert_path      = dir + "/server.pem";
  const std::string key_path       = dir + "/server.key";
  const std::string multicert_path = dir + "/ssl_multicert.config";
  {
    std::ofstream(cert_path) << cert_pem;
    std::ofstream(key_path) << key_pem;
    std::ofstream(multicert_path) << "dest_ip=* ssl_cert_name=server.pem ssl_key_name=server.key\n";
  }

  // Don't let a load hiccup abort the process; point the loader at our files.
  RecSetRecordInt("proxy.config.ssl.server.multicert.exit_on_load_fail", 0, REC_SOURCE_EXPLICIT);
  RecSetRecordString("proxy.config.ssl.server.multicert.filename", const_cast<char *>(multicert_path.c_str()), REC_SOURCE_EXPLICIT);
  RecSetRecordString("proxy.config.ssl.server.cert.path", const_cast<char *>(dir.c_str()), REC_SOURCE_EXPLICIT);
  RecSetRecordString("proxy.config.ssl.server.private_key.path", const_cast<char *>(dir.c_str()), REC_SOURCE_EXPLICIT);

  SSLConfig::reconfigure();            // republish params with the new paths
  SSLCertificateConfig::reconfigure(); // load the cert and publish the default context (sets configid)

  // Publish a ticket-key config (a random default keyblock, since no ticket_key file is set). The
  // server's session-ticket callback dereferences SSLTicketKeyConfig::scoped_config during SSL_accept.
  SSLTicketKeyConfig::reconfigure();

  // With the default context now published, re-run stats init so it can enumerate the ciphers into
  // cipher_map. The first pass (in ensure_ssl_runtime, before any cert) bailed out with an empty map,
  // which would trip ssl_callback_info's `it != cipher_map.end()` assert when the inbound handshake
  // completes. Metric and cipher registration are both idempotent, so a second pass is safe.
  SSLInitializeStatistics();
}

BarePeer::BarePeer(bool server, const std::string &cert_pem, const std::string &key_pem)
{
  _ctx = SSL_CTX_new(server ? TLS_server_method() : TLS_client_method());

  BIO  *cbio = BIO_new_mem_buf(cert_pem.data(), static_cast<int>(cert_pem.size()));
  X509 *x    = PEM_read_bio_X509(cbio, nullptr, nullptr, nullptr);
  SSL_CTX_use_certificate(_ctx, x);
  X509_free(x);
  BIO_free(cbio);

  BIO      *kbio = BIO_new_mem_buf(key_pem.data(), static_cast<int>(key_pem.size()));
  EVP_PKEY *k    = PEM_read_bio_PrivateKey(kbio, nullptr, nullptr, nullptr);
  SSL_CTX_use_PrivateKey(_ctx, k);
  EVP_PKEY_free(k);
  BIO_free(kbio);

  _ssl  = SSL_new(_ctx);
  _rbio = BIO_new(BIO_s_mem());
  _wbio = BIO_new(BIO_s_mem());
  SSL_set_bio(_ssl, _rbio, _wbio); // SSL takes ownership of both BIOs
  if (server) {
    SSL_set_accept_state(_ssl);
  } else {
    SSL_set_connect_state(_ssl);
  }
}

BarePeer::~BarePeer()
{
  SSL_free(_ssl); // frees _rbio/_wbio too
  SSL_CTX_free(_ctx);
}

int
BarePeer::do_handshake()
{
  int rc = SSL_do_handshake(_ssl);
  return rc == 1 ? 0 : SSL_get_error(_ssl, rc);
}

MockTransportVC::MockTransportVC() : UnixNetVConnection()
{
  // nh stays nullptr: the SUT's teardown selects the plain do_io_close() branch for a null nh.
}

VIO *
MockTransportVC::do_io_read(Continuation *c, int64_t nbytes, MIOBuffer *buf)
{
  _sut_read_buf       = buf; // SUT's _read_buf: ciphertext-in lands here
  _read_vio.op        = VIO::READ;
  _read_vio.cont      = c;
  _read_vio.mutex     = c->mutex;
  _read_vio.vc_server = this;
  _read_vio.nbytes    = nbytes;
  _read_vio.ndone     = 0;
  _read_vio.set_writer(buf);
  return &_read_vio;
}

VIO *
MockTransportVC::do_io_write(Continuation *c, int64_t nbytes, IOBufferReader *buf, bool /* owner */)
{
  _sut_write_reader    = buf; // SUT's _write_buf_reader: ciphertext-out is read from here
  _write_vio.op        = VIO::WRITE;
  _write_vio.cont      = c;
  _write_vio.mutex     = c->mutex;
  _write_vio.vc_server = this;
  _write_vio.nbytes    = nbytes;
  _write_vio.ndone     = 0;
  _write_vio.set_reader(buf);
  return &_write_vio;
}

void
MockTransportVC::do_io_close(int lerrno)
{
  _closed      = true;
  _close_errno = lerrno;
}

void
MockTransportVC::do_io_shutdown(ShutdownHowTo_t /* howto */)
{
}

void
MockTransportVC::reenable(VIO *vio)
{
  // No auto-pump: the fixture drives ciphertext movement explicitly for determinism. Record
  // write-side reenables so tests can assert the SUT requested a flush at all.
  if (vio == &_write_vio) {
    ++_write_reenables;
  }
}

void
MockTransportVC::reenable_re(VIO *vio)
{
  reenable(vio);
}

ScriptableConsumer::ScriptableConsumer(Ptr<ProxyMutex> m) : Continuation(m)
{
  SET_HANDLER(&ScriptableConsumer::handle);
  read_buf    = new_MIOBuffer(BUFFER_SIZE_INDEX_8K);
  read_reader = read_buf->alloc_reader();
}

ScriptableConsumer::~ScriptableConsumer()
{
  if (read_buf) {
    free_MIOBuffer(read_buf);
  }
}

int
ScriptableConsumer::handle(int event, void *data)
{
  if (event == NET_EVENT_OPEN) {
    got_open = true;
    return EVENT_CONT;
  }
  if (event == NET_EVENT_OPEN_FAILED) {
    // data is the (negative) errno, not a VIO -- must not fall through to the VIO branches.
    got_open_failed = true;
    return EVENT_CONT;
  }
  VIO *vio = static_cast<VIO *>(data);
  if (vio && vio->op == VIO::WRITE) {
    write_signals.push_back(event);
  } else {
    read_signals.push_back(event);
  }
  // Consumer-driven teardown: close the VC on a terminal event, like the real consumers (HttpSM,
  // Http2ClientSession, the accept trampoline). h2_mode models an H2 session with active streams:
  // it marks the close pending (master defers _vc->do_io_close() to destroy() when the last stream
  // releases) so the test can drive that ordering explicitly via release().
  if (event == VC_EVENT_ERROR || event == VC_EVENT_EOS || event == VC_EVENT_ACTIVE_TIMEOUT ||
      event == VC_EVENT_INACTIVITY_TIMEOUT) {
    if (h2_mode) {
      pending_close = true;
    } else if (vc != nullptr) {
      NetVConnection *v = vc;
      vc                = nullptr; // a session nulls its netvc after closing it; also blocks a double close
      v->do_io_close();
    }
  }
  return EVENT_CONT;
}

void
ScriptableConsumer::release()
{
  if (pending_close && vc != nullptr) {
    NetVConnection *v = vc;
    vc                = nullptr;
    v->do_io_close();
  }
  pending_close = false;
}

ReducerFixture::ReducerFixture(bool inbound) : _inbound(inbound)
{
  ensure_ssl_runtime();
  reducer_make_self_signed(_cert, _key);
  _mutex    = new_ProxyMutex();
  _consumer = new ScriptableConsumer(_mutex);
  // Peer is the opposite role: server when the SUT is an outbound client.
  _peer = new BarePeer(/* server */ !_inbound, _cert, _key);
}

// Drop every event still queued on this thread, undelivered. Used at fixture teardown for
// cross-test isolation; the only scheduler in these tests is the fixture's own SUT.
static void
discard_pending_events()
{
  EThread *t = this_ethread();
  t->EventQueueExternal.dequeue_external();
  while (Event *e = t->EventQueueExternal.dequeue_local()) {
    t->free_event(e);
  }
}

ReducerFixture::~ReducerFixture()
{
  // Free (without dispatching) any event this test left in the thread's queue: the queue is
  // shared across tests, and a straggler delivered by a later test's pump() would fire into
  // this test's freed mock/consumer.
  discard_pending_events();
  delete _peer;
  delete _consumer;
  delete _mock;
  // _vc is returned to its allocator by the SUT's own teardown; the fixture never deletes it.
  if (_sock_fd != NO_FD) {
    ::close(_sock_fd);
  }
}

void
ReducerFixture::attach(bool install_read)
{
  _vc        = sslNetVCAllocator.alloc();
  _vc->mutex = _mutex;
  _vc->set_context(_inbound ? NET_VCONNECTION_IN : NET_VCONNECTION_OUT);
  _vc->options.verifyServerPolicy = YamlSNIConfig::Policy::DISABLED;
  _vc->set_open_continuation(_consumer);

  if (_inbound) {
    // The inbound handshake calls safe_getsockname(get_socket()); a bound AF_INET fd keeps it valid.
    _sock_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in sin{};
    sin.sin_family      = AF_INET;
    sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sin.sin_port        = 0;
    ::bind(_sock_fd, reinterpret_cast<sockaddr *>(&sin), sizeof(sin));
  }

  _mock         = new MockTransportVC();
  _mock->mutex  = _mutex;
  _mock->thread = this_ethread();
  _mock->set_test_fd(_sock_fd); // NO_FD for outbound; a real bound fd for inbound

  {
    SCOPED_MUTEX_LOCK(lock, _vc->mutex, this_ethread());
    _vc->startEvent(_inbound ? NET_EVENT_ACCEPT : NET_EVENT_OPEN, _mock);
    if (install_read) {
      // Consumer attaches its user VIOs so decrypted reads have somewhere to land.
      _vc->do_io_read(_consumer, INT64_MAX, _consumer->read_buf);
    }
  }
  // Hand the consumer the VC so it can drive the close on a terminal event (consumer-driven).
  _consumer->vc = _vc;
}

// Deliver the events queued on this thread the way EThread::process_event would; the harness
// thread never runs its own event loop, so anything scheduled on it (the SUT's schedule_imm
// dispatches) sits in its external queue until delivered here. Passing the genuine Event* as
// data matters: mainEvent accepts only the armed _deferred_work_event as scheduled work. Lock
// through e->mutex, not the continuation -- the Ptr keeps the mutex alive even if a prior
// event's dispatch freed the continuation and left this one cancelled.
static void
run_pending_events()
{
  EThread *t = this_ethread();
  t->EventQueueExternal.dequeue_external();
  while (Event *e = t->EventQueueExternal.dequeue_local()) {
    ink_release_assert(e->timeout_at == 0 && e->period == 0); // only schedule_imm is used here
    if (!e->cancelled) {
      SCOPED_MUTEX_LOCK(lock, e->mutex, t);
      if (!e->cancelled) {
        e->continuation->handleEvent(e->callback_event, e);
      }
    }
    t->free_event(e);
  }
}

void
ReducerFixture::pump()
{
  // Drain the SUT's outbound ciphertext (simulate the transport flushing the close-notify), then
  // deliver the SUT's scheduled dispatch so a pending close-drain / reclaim completes on a clean
  // stack. Loop until the VC frees (its destructor closes the mock inner, which mock->closed()
  // witnesses) or we quiesce.
  for (int i = 0; i < 8 && !_mock->closed(); ++i) {
    if (IOBufferReader *r = _mock->sut_write_reader(); r != nullptr) {
      while (r->read_avail() > 0) {
        r->consume(r->read_avail());
      }
    }
    run_pending_events();
  }
}

void
ReducerFixture::attach_cancelled()
{
  _vc        = sslNetVCAllocator.alloc();
  _vc->mutex = _mutex;
  _vc->set_context(NET_VCONNECTION_OUT);
  _vc->set_open_continuation(_consumer);

  _mock         = new MockTransportVC();
  _mock->mutex  = _mutex;
  _mock->thread = this_ethread();

  Action *a = _vc->arm_connect_action(_consumer);
  a->cancel(); // sets _connect_action.cancelled

  SCOPED_MUTEX_LOCK(lock, _vc->mutex, this_ethread());
  _vc->startEvent(NET_EVENT_OPEN, _mock); // hits the cancelled branch: closes mock, frees outer
}

void
ReducerFixture::attach_cancelled_open_failed()
{
  _vc        = sslNetVCAllocator.alloc();
  _vc->mutex = _mutex;
  _vc->set_context(NET_VCONNECTION_OUT);

  Action *a = _vc->arm_connect_action(_consumer);
  a->cancel();

  // A failed transport connect delivers the (negative) errno, not a VConnection. The cancelled
  // consumer must not be notified, and the outer VC must still reclaim itself.
  SCOPED_MUTEX_LOCK(lock, _vc->mutex, this_ethread());
  _vc->startEvent(NET_EVENT_OPEN_FAILED, reinterpret_cast<void *>(static_cast<intptr_t>(-ECONNREFUSED)));
}

void
ReducerFixture::wake_sut(bool write_side)
{
  SCOPED_MUTEX_LOCK(lock, _vc->mutex, this_ethread());
  _vc->handleEvent(write_side ? VC_EVENT_WRITE_READY : VC_EVENT_READ_READY, write_side ? _mock->write_vio() : _mock->read_vio());
}

void
ReducerFixture::pump_sut_to_peer()
{
  IOBufferReader *r = _mock->sut_write_reader();
  char            buf[16384];
  int64_t         avail;
  while ((avail = r->read_avail()) > 0) {
    int64_t n = avail > static_cast<int64_t>(sizeof(buf)) ? static_cast<int64_t>(sizeof(buf)) : avail;
    r->memcpy(buf, n);
    r->consume(n);
    BIO_write(_peer->rbio(), buf, static_cast<int>(n));
  }
}

void
ReducerFixture::pump_peer_to_sut(bool corrupt)
{
  char buf[16384];
  int  n;
  while ((n = BIO_read(_peer->wbio(), buf, sizeof(buf))) > 0) {
    if (corrupt && n > 8) {
      buf[n / 2] ^= 0xFF; // flip a byte mid-record to force an SSL_read error at the SUT
    }
    _mock->sut_read_buf()->write(buf, n);
    SCOPED_MUTEX_LOCK(lock, _vc->mutex, this_ethread());
    _vc->handleEvent(VC_EVENT_READ_READY, _mock->read_vio());
  }
}

void
ReducerFixture::inject(int event, bool write_side)
{
  SCOPED_MUTEX_LOCK(lock, _vc->mutex, this_ethread());
  _vc->handleEvent(event, write_side ? _mock->write_vio() : _mock->read_vio());
}

void
ReducerFixture::resume_hook(bool error)
{
  SCOPED_MUTEX_LOCK(lock, _vc->mutex, this_ethread());
  _vc->reenable_with_event(error ? TS_EVENT_ERROR : TS_EVENT_CONTINUE);
}

void
ReducerFixture::drive_handshake()
{
  // Run until BOTH endpoints are established, not just the SUT. The SUT finishes on the round it
  // reads the peer's flight, but its own final flight (e.g. the TLS 1.3 client Finished) is then
  // still sitting in _write_buf: one more iteration pumps it to the peer so the peer can complete.
  for (int i = 0; i < 20 && !(_vc->getSSLHandShakeComplete() && _peer->handshake_done()); ++i) {
    wake_sut(/* write_side */ true);  // let the SUT emit its next flight into _write_buf
    wake_sut(/* write_side */ false); // and consume anything already pending
    pump_sut_to_peer();
    _peer->do_handshake();
    pump_peer_to_sut();
  }
}
