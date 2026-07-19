'''
Verify that a TLS 1.3 KeyUpdate during a large response download does not abort
the connection (SSL_write returning WANT_READ must be a retry, not fatal).
'''
#  Licensed to the Apache Software Foundation (ASF) under one
#  or more contributor license agreements.  See the NOTICE file
#  distributed with this work for additional information
#  regarding copyright ownership.  The ASF licenses this file
#  to you under the Apache License, Version 2.0 (the
#  "License"); you may not use this file except in compliance
#  with the License.  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

import os

Test.Summary = '''
A TLS 1.3 client that issues KeyUpdate messages mid-download must continue to
receive the full response; SSL_write returning WANT_READ is a benign retry.
'''

body_size = 8 * 1024 * 1024
body = "x" * body_size

# Number of KeyUpdate(update_requested) messages the client injects mid-download.
# BoringSSL fatally rejects more than 32 *consecutive* KeyUpdates received without any
# intervening application data (kMaxKeyUpdates in ssl/tls13_both.cc, a DoS mitigation).
# This is a pure download, so the client sends no application data after the request and
# that limit applies verbatim; OpenSSL imposes no such cap. Keep the count at/under 32 so
# the single test passes on every supported TLS library -- 30 still issues a steady stream
# of mid-download KeyUpdates, which is all this test needs to exercise the write path.
num_key_updates = 30

# Build the KeyUpdate-capable TLS client (no stock tool can send a KeyUpdate
# mid-stream). Skip the whole test if it cannot be built.
client_src = os.path.join(Test.TestDirectory, 'tls_keyupdate_client.c')
client_bin = os.path.join(Test.RunDirectory, 'tls_keyupdate_client')
build_tr = Test.AddTestRun("build the KeyUpdate client")
build_tr.Processes.Default.Command = f"cc -O2 -o {client_bin} {client_src} -lssl -lcrypto"
build_tr.Processes.Default.ReturnCode = 0

ts = Test.MakeATSProcess("ts", enable_tls=True, enable_cache=False)
server = Test.MakeOriginServer("server")

request_header = {"headers": "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
response_header = {
    "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: {0}\r\n\r\n".format(body_size),
    "timestamp": "1469733493.993",
    "body": body
}
server.addResponse("sessionlog.json", request_header, response_header)

ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_yaml.AddLines(
    """
ssl_multicert:
  - dest_ip: "*"
    ssl_cert_name: server.pem
    ssl_key_name: server.key
""".split("\n"))
ts.Disk.remap_config.AddLine('map / http://127.0.0.1:{0}'.format(server.Variables.Port))

ts.Disk.records_config.update(
    {
        'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.diags.debug.enabled': 1,
        'proxy.config.diags.debug.tags': 'ssl_error|ssl_io',
        # The KeyUpdate exercise completes during the (fast) body transfer; the client then
        # blocks reading until the server closes. Keep the post-response idle wait short so the
        # test finishes promptly instead of lingering on the default keep-alive timeout.
        'proxy.config.http.keep_alive_no_activity_timeout_in': 5,
        'proxy.config.net.default_inactivity_timeout': 10,
    })

ts.Disk.traffic_out.Content = Testers.ExcludesExpression("received signal|failed assertion", "ATS must not crash on a KeyUpdate")
# Direct proof of the unreachability analysis: in the layered-BIO model the separate read
# drive (_drive_ssl_read -> SSL_read) consumes the client's KeyUpdate records, so the write
# path's SSL_write never has to read and never returns WANT_READ. If it ever did,
# _encrypt_data_for_transport would log this (and the connection would be torn down).
ts.Disk.traffic_out.Content += Testers.ExcludesExpression(
    "SSL_write-SSL_ERROR_WANT_READ", "SSL_write must never return WANT_READ on the post-handshake write path")
ts.Disk.traffic_out.Content += Testers.ExcludesExpression(
    "cannot service an in-write renegotiation", "the -EAGAIN write teardown branch must not fire")

tr = Test.AddTestRun("KeyUpdate mid-download does not abort the connection")
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.Command = f"{client_bin} -p {ts.Variables.ssl_port} -s example.com -n {num_key_updates}"
tr.Processes.Default.ReturnCode = 0
# The client reports total bytes read (response headers + body); the body alone is body_size,
# so the full transfer reads body_size + a small, server-dependent header. Match the body_size
# prefix rather than an exact count so added/changed response headers do not break the test.
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "body_bytes=8388[0-9][0-9][0-9]", "the full response body must be received despite KeyUpdates")
# The client only reaches its clean-exit "done:" line after the body is fully read and the server
# sends close_notify; a truncated transfer would instead hit an SSL_read error and exit non-zero.
tr.Processes.Default.Streams.stderr = Testers.ContainsExpression(
    f"done: total=8388[0-9][0-9][0-9] updates={num_key_updates}", "all KeyUpdates sent and the full response received cleanly")
tr.StillRunningAfter = ts
