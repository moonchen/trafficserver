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

#pragma once

#include "../P_SSLNetVConnection.h"
#include "../P_UnixNetVConnection.h"
#include "iocore/eventsystem/VIO.h"
#include "iocore/eventsystem/IOBuffer.h"

#include <openssl/ssl.h>
#include <string>
#include <vector>

void reducer_make_self_signed(std::string &cert_pem, std::string &key_pem);

class BarePeer
{
public:
  explicit BarePeer(bool server, const std::string &cert_pem, const std::string &key_pem);
  ~BarePeer();

  BIO *
  rbio() const
  {
    return _rbio;
  }
  BIO *
  wbio() const
  {
    return _wbio;
  }
  SSL *
  ssl() const
  {
    return _ssl;
  }

  int do_handshake();
  bool
  handshake_done() const
  {
    return SSL_is_init_finished(_ssl);
  }
  int
  write_app(const void *buf, int len)
  {
    return SSL_write(_ssl, buf, len);
  }
  int
  read_app(void *buf, int len)
  {
    return SSL_read(_ssl, buf, len);
  }

private:
  SSL_CTX *_ctx  = nullptr;
  SSL     *_ssl  = nullptr;
  BIO     *_rbio = nullptr; // memory BIO the peer reads ciphertext from
  BIO     *_wbio = nullptr; // memory BIO the peer writes ciphertext to
};

// Filled in by later tasks.
