/** @file
 *
 * A minimal TLS 1.3 client that requests a large object and issues
 * KeyUpdate(update_requested) messages while the response is still streaming
 * back, reading slowly so the server is mid-SSL_write when each KeyUpdate
 * arrives. Used to exercise the server's SSL_write WANT_READ handling.
 *
 * Note: a TLS 1.3 server may cap the number of consecutive KeyUpdates it will
 * accept without intervening application data (BoringSSL's kMaxKeyUpdates is
 * 32); since this client sends none, keep -n at or below that limit.
 *
 * Prints "body_bytes=<N>" and exits 0 if the full body was received, or exits
 * non-zero (printing the SSL error) if the connection was torn down early.
 *
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with this
 * work for additional information regarding copyright ownership.  The ASF
 * licenses this file to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.  See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

static void
nap(long usec)
{
  struct timespec ts = {usec / 1000000, (usec % 1000000) * 1000};
  nanosleep(&ts, NULL);
}

int
main(int argc, char **argv)
{
  int         port        = 0;
  const char *sni         = "example.com";
  int         num_updates = 40;

  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-p") && i + 1 < argc) {
      port = atoi(argv[++i]);
    } else if (!strcmp(argv[i], "-s") && i + 1 < argc) {
      sni = argv[++i];
    } else if (!strcmp(argv[i], "-n") && i + 1 < argc) {
      num_updates = atoi(argv[++i]);
    }
  }
  if (port == 0) {
    fprintf(stderr, "usage: %s -p <port> [-s sni] [-n num_updates]\n", argv[0]);
    return 2;
  }

  int                sock = socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in addr;
  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port   = htons(port);
  inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
  if (connect(sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
    perror("connect");
    return 2;
  }

  SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
  SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
  SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);

  SSL *ssl = SSL_new(ctx);
  SSL_set_fd(ssl, sock);
  SSL_set_tlsext_host_name(ssl, sni);
  if (SSL_connect(ssl) != 1) {
    fprintf(stderr, "SSL_connect failed\n");
    ERR_print_errors_fp(stderr);
    return 2;
  }

  char req[256];
  int  reqlen = snprintf(req, sizeof(req), "GET / HTTP/1.1\r\nHost: %s\r\n\r\n", sni);
  if (SSL_write(ssl, req, reqlen) <= 0) {
    fprintf(stderr, "request write failed\n");
    return 2;
  }

  long total      = 0;
  long body_bytes = 0;
  int  saw_header = 0;
  int  updates    = 0;
  char buf[1500];
  int  reads = 0;

  for (;;) {
    int n = SSL_read(ssl, buf, sizeof(buf));
    if (n > 0) {
      total += n;
      if (!saw_header) {
        // Crude: count everything; the test compares against headers+body.
        saw_header = 1;
      }
      body_bytes += n;
      reads++;

      // After the body starts flowing, issue KeyUpdates that request one back,
      // spaced across the slow read so the server is mid-write each time.
      if (reads % 8 == 0 && updates < num_updates) {
        if (SSL_key_update(ssl, SSL_KEY_UPDATE_REQUESTED) == 1) {
          // Flush the KeyUpdate to the server without consuming body data.
          SSL_do_handshake(ssl);
          updates++;
        }
      }
      // Read slowly so the server's write stays in flight while KeyUpdates land.
      nap(500);
      continue;
    }

    int err = SSL_get_error(ssl, n);
    if (err == SSL_ERROR_ZERO_RETURN) {
      break; // clean close_notify
    }
    if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
      nap(1000);
      continue;
    }
    // Any other error mid-stream is the failure we are hunting.
    fprintf(stderr, "SSL_read error=%d after %ld bytes, updates=%d\n", err, total, updates);
    ERR_print_errors_fp(stderr);
    printf("body_bytes=%ld\n", body_bytes);
    return 1;
  }

  printf("body_bytes=%ld\n", body_bytes);
  fprintf(stderr, "done: total=%ld updates=%d\n", total, updates);
  return 0;
}
