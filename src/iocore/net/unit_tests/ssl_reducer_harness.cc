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

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/evp.h>

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
MockTransportVC::reenable(VIO * /* vio */)
{
  // No auto-pump: the fixture drives ciphertext movement explicitly for determinism.
}

void
MockTransportVC::reenable_re(VIO *vio)
{
  reenable(vio);
}
