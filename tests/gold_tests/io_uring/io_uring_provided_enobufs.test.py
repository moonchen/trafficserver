'''
io_uring provided-buffer ring exhaustion (-ENOBUFS) -> single-shot heap read fallback.
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
Exercise the io_uring provided-buffer read path (proxy.config.net.io_uring.read_provided_buffers=1)
under a deliberately TINY per-thread provided-buffer ring so that recvs routinely fail with -ENOBUFS
and must fall back to the single-shot heap read.

The ring is sized to the power-of-two minimum (read_buffer_count=2) with a small block
(read_buffer_size=2048), so 2 x 2 KiB = 4 KiB of provided-buffer capacity total, per thread. Under
wrk -t4 -c64 there are far more concurrent recvs in flight than the ring can back, so nearly every
recv completes -ENOBUFS. Each -ENOBUFS drive must fall back to _read() -- reading into the consumer's
own growable MIOBuffer (no ring buffer) -- to make progress; net_read_io then re-selects the provided
path on the next drive once the ring recycles buffers. A cacheable body far larger than the whole ring
guarantees the origin response read alone overruns the 2-buffer ring, so the fallback branch runs.

This is the exact fallback branch io_uring_read_provided (a generously sized ring) is tuned to avoid.
Correctness bar: the connection must NOT deadlock (a park-on-ENOBUFS bug would hang to the test
timeout) and must NOT drop bytes -- the full body reassembles and there are zero socket / non-2xx
errors under load. Success under a 2-buffer ring is only possible if the -ENOBUFS -> _read fallback ran.

EXPERIMENTAL (read_provided_buffers is off by default).
'''

Test.SkipUnless(Condition.HasProgram("wrk", "wrk is needed for the load phase"))

Test.ContinueOnFail = False

ts = Test.MakeATSProcess("ts")
server = Test.MakeOriginServer("server")

# ~256 KB cacheable body with a unique end marker (present only if every read landed and was
# reassembled in order). 256 KB >> the 4 KiB (2 x 2 KiB) provided-buffer ring, so the origin
# response read alone exhausts the ring many times over and drives the -ENOBUFS heap fallback.
body = ("io_uring_enobufs_payload." * 10000) + "END_OF_ENOBUFS_BODY_MARKER"  # ~256 KB
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
        # Power-of-two minimum ring (2 buffers) x a small 2 KiB block: 4 KiB of provided capacity
        # per thread. Far too small for 64 concurrent recvs, so nearly every recv -> -ENOBUFS ->
        # single-shot _read heap fallback.
        'proxy.config.net.io_uring.read_buffer_count': 2,
        'proxy.config.net.io_uring.read_buffer_size': 2048,
        'proxy.config.io_uring.entries': 8192,
        # Cache the object so the load phase hammers ATS, not the Python origin.
        'proxy.config.http.cache.required_headers': 0,
    })

ts.Disk.remap_config.AddLine('map http://www.example.com http://127.0.0.1:{0}'.format(server.Variables.Port))

ts.Disk.diags_log.Content = Testers.ContainsExpression(
    "io_uring NetVConnection enabled", "the io_uring NetVConnection path must be active")

# Phase 1: large body proxied through the tiny ring. The cache-miss origin response read (256 KB)
# overruns the 4 KiB ring many times -> -ENOBUFS -> _read heap fallback; the full body must survive.
tr = Test.AddTestRun("large body through a 2-buffer ring: -ENOBUFS heap fallback, full integrity")
tr.MakeCurlCommand('-s -o - --proxy 127.0.0.1:{0} "http://www.example.com/big"'.format(ts.Variables.port), ts=ts)
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "END_OF_ENOBUFS_BODY_MARKER", "the full 256 KB body must survive the -ENOBUFS heap fallback reassembly")
tr.StillRunningAfter = ts
tr.StillRunningAfter = server

# Phase 2: load. 64 concurrent connections against a 2-buffer ring -> ring exhausted -> nearly every
# recv hits -ENOBUFS and must fall back. Must complete (no deadlock) with zero socket / non-2xx errors.
tr = Test.AddTestRun("wrk load against a 2-buffer ring: sustained -ENOBUFS fallback, no deadlock")
tr.Processes.Default.Command = (
    'wrk -t 4 -c 64 -d 15s --latency -H "Host: www.example.com" '
    'http://127.0.0.1:{0}/big'.format(ts.Variables.port))
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.All(
    Testers.ContainsExpression("requests in", "the load run must complete (a park-on-ENOBUFS deadlock would time out)"),
    Testers.ExcludesExpression("Socket errors", "no socket errors under sustained ring exhaustion"),
    Testers.ExcludesExpression("Non-2xx or 3xx responses", "every response must be 2xx despite ring exhaustion"),
)
tr.StillRunningAfter = ts
tr.StillRunningAfter = server
