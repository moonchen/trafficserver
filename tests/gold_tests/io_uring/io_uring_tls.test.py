'''
TLS termination and outbound origin TLS over the io_uring net path.
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

Test.Summary = '''
With proxy.config.net.io_uring.enabled=1, terminate client TLS on a layered
SSLNetVConnection whose inner transport is an IOUringNetVConnection (accepted on
the ring, not epoll), and fetch from both a plain and a TLS origin so the
outbound (SSLNetProcessor::connect_re -> io_uring connectUp) leg is exercised.
'''

Test.SkipUnless(Condition.HasATSFeature('TS_USE_LINUX_IO_URING'))

Test.ContinueOnFail = True

ts = Test.MakeATSProcess("ts", enable_tls=True)
server = Test.MakeOriginServer("server")
tls_server = Test.MakeOriginServer("tls_server", ssl=True)

request_header = {"headers": "GET /plain HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
response_header = {
    "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 5\r\n\r\n",
    "timestamp": "1469733493.993",
    "body": "plain"
}
server.addResponse("sessionfile.log", request_header, response_header)

request_header = {"headers": "GET /tls HTTP/1.1\r\nHost: tls.example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
response_header = {
    "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 3\r\n\r\n",
    "timestamp": "1469733493.993",
    "body": "tls"
}
tls_server.addResponse("sessionfile.log", request_header, response_header)

ts.addSSLfile("ssl/server.pem")
ts.addSSLfile("ssl/server.key")

ts.Disk.records_config.update(
    {
        'proxy.config.net.io_uring.enabled': 1,
        'proxy.config.ssl.server.cert.path': ts.Variables.SSLDir,
        'proxy.config.ssl.server.private_key.path': ts.Variables.SSLDir,
        'proxy.config.ssl.client.verify.server.policy': 'DISABLED',
    })

ts.Disk.ssl_multicert_yaml.AddLines(
    """
ssl_multicert:
  - dest_ip: "*"
    ssl_cert_name: server.pem
    ssl_key_name: server.key
""".split("\n"))

ts.Disk.remap_config.AddLine(
    'map https://www.example.com:{0} http://127.0.0.1:{1}'.format(ts.Variables.ssl_port, server.Variables.Port))
ts.Disk.remap_config.AddLine(
    'map https://tls.example.com:{0} https://127.0.0.1:{1}'.format(ts.Variables.ssl_port, tls_server.Variables.SSL_Port))

# The load-bearing assertion: the TLS port's accept object is the io_uring one.
# Without the SSLNetProcessor::createNetAccept gate this line never appears and
# TLS accepts stay on the epoll SSLNetAccept.
ts.Disk.diags_log.Content = Testers.ContainsExpression(
    "io_uring accept enabled for TLS port", "TLS accepts must arm on the ring, not epoll")

tr = Test.AddTestRun("terminate TLS over io_uring, plain origin")
tr.MakeCurlCommand(
    '-s -o - -k --resolve www.example.com:{0}:127.0.0.1 "https://www.example.com:{0}/plain"'.format(ts.Variables.ssl_port), ts=ts)
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(tls_server)
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("plain", "body proxied back over TLS-terminated io_uring")
tr.StillRunningAfter = ts
tr.StillRunningAfter = server

tr = Test.AddTestRun("terminate TLS over io_uring, TLS origin (outbound leg)")
tr.MakeCurlCommand(
    '-s -o - -k --resolve tls.example.com:{0}:127.0.0.1 "https://tls.example.com:{0}/tls"'.format(ts.Variables.ssl_port), ts=ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("tls", "body proxied from a TLS origin over io_uring both legs")
tr.StillRunningAfter = ts
tr.StillRunningAfter = tls_server
