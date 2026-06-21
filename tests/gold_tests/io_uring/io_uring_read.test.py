'''
Load + large-body test for the io_uring recvmsg read path.
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
Drive the io_uring recvmsg read path hard with proxy.config.net.io_uring.enabled=1:
  1. a large (256 KB) body proxied once, to exercise the read coroutine's drain
     loop (many recvmsg per epoll trigger over edge-triggered epoll);
  2. a wrk load of many concurrent connections and requests against the cached
     object, to stress request reads, connection churn, and the close path under
     load --- expecting zero socket errors and zero non-2xx responses.
'''

Test.SkipUnless(Condition.HasProgram("wrk", "wrk is needed for the load phase"))

Test.ContinueOnFail = False

ts = Test.MakeATSProcess("ts")
server = Test.MakeOriginServer("server")

# 256 KB cacheable body with a unique end marker (only present if every read
# landed and was reassembled in order across the drain loop).
body = ("io_uring_read_payload." * 11650) + "END_OF_BODY_MARKER"  # ~256 KB
response_header = {
    "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nCache-Control: max-age=300\r\nContent-Length: {0}\r\n\r\n".format(
        len(body)),
    "timestamp": "1469733493.993",
    "body": body
}
request_header = {"headers": "GET /big HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
server.addResponse("sessionfile.log", request_header, response_header)

ts.Disk.records_config.update(
    {
        'proxy.config.net.io_uring.enabled': 1,
        # Cache the object so the load phase hammers ATS, not the Python origin.
        'proxy.config.http.cache.required_headers': 0,
    })

ts.Disk.remap_config.AddLine('map http://www.example.com http://127.0.0.1:{0}'.format(server.Variables.Port))

ts.Disk.diags_log.Content = Testers.ContainsExpression(
    "io_uring NetVConnection enabled", "the io_uring NetVConnection path must be active")

# Phase 1: large body, drain-loop correctness (cache miss -> full origin read).
tr = Test.AddTestRun("large body proxied through the io_uring read drain loop")
tr.MakeCurlCommand('-s -o - --proxy 127.0.0.1:{0} "http://www.example.com/big"'.format(ts.Variables.port), ts=ts)
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "END_OF_BODY_MARKER", "the full 256 KB body must survive reassembly across reads")
tr.StillRunningAfter = ts
tr.StillRunningAfter = server

# Phase 2: load. Many connections + requests + bytes through the io_uring read
# path. Reverse-proxy style so wrk can hammer the ATS port directly.
tr = Test.AddTestRun("wrk load against the io_uring read path")
tr.Processes.Default.Command = (
    'wrk -t 4 -c 64 -d 15s --latency -H "Host: www.example.com" '
    'http://127.0.0.1:{0}/big'.format(ts.Variables.port))
tr.Processes.Default.ReturnCode = 0
# wrk only prints "Socket errors" / "Non-2xx" lines when failures occur. Their
# absence, plus a completed run, means every request read+proxied cleanly.
tr.Processes.Default.Streams.stdout = Testers.All(
    Testers.ContainsExpression("requests in", "the load run must complete"),
    Testers.ExcludesExpression("Socket errors", "no socket errors under load"),
    Testers.ExcludesExpression("Non-2xx or 3xx responses", "every response must be 2xx under load"),
)
tr.StillRunningAfter = ts
tr.StillRunningAfter = server
