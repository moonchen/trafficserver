'''
Exercise the io_uring single-shot _read() (recvmsg) path with the provided-buffer
ring FORCED OFF.
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
import sys
from ports import get_port

Test.Summary = '''
Force the io_uring single-shot _read() recvmsg path (proxy.config.net.io_uring.enabled=1 with
proxy.config.net.io_uring.read_provided_buffers=0) and drive its body-read branches:
  1. a tiny proxied GET -> a single-block recv (msg_iovlen == 1, the common case);
  2. a 256 KB cache-miss body -> a multi-block recvmsg plus the full-read drain loop and a tail
     short read (socket drained -> re-arm), reassembled in order;
  3. a no-Content-Length Connection:close body that ends by an origin FIN -> the r==0 clean-EOS arm.

io_uring_read.test.py claims recvmsg coverage but runs with the provided-buffer ring left at its
default (on), so it silently exercises _read_provided() instead. This test pins read_provided_buffers=0
so the single-shot _read() coroutine is the one under test.
'''

Test.ContinueOnFail = False

ts = Test.MakeATSProcess("ts")
server = Test.MakeOriginServer("server")

# (a) tiny body: a single-block recv (msg_iovlen == 1).
small_request = {"headers": "GET /small HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
small_response = {
    "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 20\r\n\r\n",
    "timestamp": "1469733493.993",
    "body": "hello-io-uring-small"
}
server.addResponse("sessionfile.log", small_request, small_response)

# (b) 256 KB cacheable body with a unique end marker: multi-block recvmsg + drain loop + tail short
# read. The marker survives only if every read landed and was reassembled in order.
big_body = ("io_uring_read_payload." * 11650) + "END_OF_BODY_MARKER"  # ~256 KB
big_request = {"headers": "GET /big HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
big_response = {
    "headers":
        "HTTP/1.1 200 OK\r\nConnection: close\r\nCache-Control: max-age=300\r\nContent-Length: {0}\r\n\r\n".format(len(big_body)),
    "timestamp": "1469733493.993",
    "body": big_body
}
server.addResponse("sessionfile.log", big_request, big_response)

# (c) raw origin for the close-delimited (no Content-Length) response -> origin FIN -> r==0 EOS.
close_origin = Test.Processes.Process("close-origin")
close_port = get_port(close_origin, "http_port")
close_origin.Command = "{0} {1} 127.0.0.1 {2}".format(
    sys.executable, os.path.join(Test.TestDirectory, "io_uring_read_singleshot_origin.py"), close_port)
close_origin.Ready = When.PortOpenv4(close_port)

ts.Disk.records_config.update(
    {
        'proxy.config.net.io_uring.enabled': 1,
        # Force the single-shot _read() path; without this the provided-buffer ring
        # (the default) would run _read_provided() instead.
        'proxy.config.net.io_uring.read_provided_buffers': 0,
        # Cache the big object so its first fetch is a clean cache-miss origin read.
        'proxy.config.http.cache.required_headers': 0,
    })

ts.Disk.remap_config.AddLine('map http://www.example.com http://127.0.0.1:{0}'.format(server.Variables.Port))
ts.Disk.remap_config.AddLine('map http://close.example.com http://127.0.0.1:{0}'.format(close_port))

# Prove the io_uring VC path actually engaged (not a silent fallback to epoll, which
# would pass these functional checks for the wrong reason).
ts.Disk.diags_log.Content = Testers.ContainsExpression(
    "io_uring NetVConnection enabled", "the io_uring NetVConnection path must be active")

# Phase 1: tiny body -> single-block recv (msg_iovlen == 1).
tr = Test.AddTestRun("tiny body through the single-shot io_uring read (single-block recv)")
tr.MakeCurlCommand('-s -o - --proxy 127.0.0.1:{0} "http://www.example.com/small"'.format(ts.Variables.port), ts=ts)
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(close_origin)
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "hello-io-uring-small", "the tiny origin body must be proxied back intact")
tr.StillRunningAfter = ts
tr.StillRunningAfter = server

# Phase 2: 256 KB cache-miss body -> multi-block recvmsg + drain loop + tail short read.
tr = Test.AddTestRun("256 KB cache-miss body through the single-shot recvmsg drain loop")
tr.MakeCurlCommand('-s -o - --proxy 127.0.0.1:{0} "http://www.example.com/big"'.format(ts.Variables.port), ts=ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "END_OF_BODY_MARKER", "the full 256 KB body must survive reassembly across the single-shot reads")
tr.StillRunningAfter = ts
tr.StillRunningAfter = server

# Phase 3: close-delimited body (no Content-Length) -> origin FIN -> r==0 clean-EOS arm.
tr = Test.AddTestRun("close-delimited body ends by origin FIN through the single-shot read (r==0 EOS)")
tr.MakeCurlCommand('-s -o - --proxy 127.0.0.1:{0} "http://close.example.com/noclen"'.format(ts.Variables.port), ts=ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.All(
    Testers.ContainsExpression("CLOSE_DELIMITED_START", "the close-delimited body must begin intact"),
    Testers.ContainsExpression("CLOSE_DELIMITED_END", "the whole close-delimited body must arrive before the FIN-signalled EOS"),
)
tr.StillRunningAfter = ts
tr.StillRunningAfter = close_origin
