'''
Load + large-body test for the io_uring single-shot provided-buffer read path.
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
Drive the io_uring provided-buffer read path (proxy.config.net.io_uring.read_provided_buffers=1):
each demand-driven single-shot recv selects a buffer from a shared per-thread provided-buffer
ring (late binding), attaches it to the read MIOBuffer zero-copy, and recycles it on release.
A large body exercises the read + recycle path across many reads; a wrk load stresses small
request reads + connection churn. Expect the full body reassembled and zero socket / non-2xx
errors.

EXPERIMENTAL (read_provided_buffers is off by default). Zero-copy attach pins each provided
buffer until the slowest downstream consumer releases it. The cache-write consumer accumulates
up to proxy.config.cache.target_fragment_size (default 1 MB) before writing a fragment and
releasing, so the ring must hold >= that working set across concurrent cache-miss reads or a
read can park on -ENOBUFS waiting for a buffer the cache will not free until EOS. This test
sizes the ring generously to stay clear of that floor.
'''

Test.SkipUnless(Condition.HasProgram("wrk", "wrk is needed for the load phase"))

Test.ContinueOnFail = False

ts = Test.MakeATSProcess("ts")
server = Test.MakeOriginServer("server")

# 256 KB cacheable body with a unique end marker (only present if every read landed
# and was reassembled in order across the per-recv buffer attaches / recycles).
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
        'proxy.config.net.io_uring.read_provided_buffers': 1,
        # Ring sized well above the cache fragment working set (4096 x 8 KB = 32 MB) so a
        # cache-miss read never parks on -ENOBUFS waiting for a buffer the cache holds until
        # fragment flush.
        'proxy.config.net.io_uring.read_buffer_count': 4096,
        'proxy.config.net.io_uring.read_buffer_size': 8192,
        'proxy.config.io_uring.entries': 8192,
        # Cache the object so the load phase hammers ATS, not the Python origin.
        'proxy.config.http.cache.required_headers': 0,
    })

ts.Disk.remap_config.AddLine('map http://www.example.com http://127.0.0.1:{0}'.format(server.Variables.Port))

ts.Disk.diags_log.Content = Testers.ContainsExpression(
    "io_uring NetVConnection enabled", "the io_uring NetVConnection path must be active")

# Phase 1: large body, zero-copy attach + recycle correctness (cache miss -> full origin read).
tr = Test.AddTestRun("large body proxied through the io_uring provided-buffer read path")
tr.MakeCurlCommand('-s -o - --proxy 127.0.0.1:{0} "http://www.example.com/big"'.format(ts.Variables.port), ts=ts)
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "END_OF_BODY_MARKER", "the full 256 KB body must survive reassembly across the per-recv reads")
tr.StillRunningAfter = ts
tr.StillRunningAfter = server

# Phase 2: load. Many connections + requests through the provided-buffer request-read path.
tr = Test.AddTestRun("wrk load against the io_uring provided-buffer read path")
tr.Processes.Default.Command = (
    'wrk -t 4 -c 64 -d 15s --latency -H "Host: www.example.com" '
    'http://127.0.0.1:{0}/big'.format(ts.Variables.port))
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.All(
    Testers.ContainsExpression("requests in", "the load run must complete"),
    Testers.ExcludesExpression("Socket errors", "no socket errors under load"),
    Testers.ExcludesExpression("Non-2xx or 3xx responses", "every response must be 2xx under load"),
)
tr.StillRunningAfter = ts
tr.StillRunningAfter = server
