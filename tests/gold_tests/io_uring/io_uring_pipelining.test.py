'''
HTTP/1.1 request pipelining across a transaction boundary through the io_uring
inbound read path (single-shot and provided-buffer).
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
With proxy.config.net.io_uring.enabled=1, a raw client pipelines TWO HTTP/1.1
requests (GET /a then GET /b) back-to-back in one send() on a single inbound
connection, before reading any response --- true pipelining (curl cannot do
this). ATS reads and dispatches /a while /b's bytes are already in the inbound
socket; on the provided-buffer read path they are already pulled into a
kernel-filled provided buffer that must be HELD across the transaction boundary
and REPLAYED to the re-armed consumer buffer for the next transaction, without
consuming any of /b into /a.

This exercises, on the provided-buffer path (default): the sqe->len want-cap
(want = min(vio.ntodo, ring bufsize)) that stops a content-length recv at the
request boundary and leaves the next pipelined request in the socket; the
_held_pbuf hold+replay of a recv that completed while the inbound read was
paused between transactions; and the net_read_io held-bytes re-route gate
(_held_read_bytes == 0). On the single-shot path (read_provided_buffers=0): the
recvmsg content-length boundary / leftover-in-socket handling. Run over BOTH
read paths (read_provided_buffers 0 and 1).

Pass criterion: both responses come back on the one connection, in order, each
200 with its own distinct body and correct framing (no bytes of /b consumed
into /a). The ASan build must stay memory-safe.
'''

import os

Test.SkipUnless(Condition.HasATSFeature('TS_USE_LINUX_IO_URING'))

Test.ContinueOnFail = False

# Distinct, differently-sized cacheable bodies with distinct markers. Distinct
# sizes make any framing desync (bytes of one request folded into the other)
# fail the strict Content-Length parse in the client.
MARKER_A = "IO_URING_PIPELINE_BODY_A_MARKER"
MARKER_B = "IO_URING_PIPELINE_BODY_B_MARKER"
BODY_A = (MARKER_A + ".") * 41  # ~1.3 KB
BODY_B = (MARKER_B + "..") * 97  # ~3.2 KB, different length than /a

CLIENT = os.path.join(Test.TestDirectory, 'io_uring_pipelining_client.py')


def add_response(server, path, body):
    request_header = {
        "headers": "GET {0} HTTP/1.1\r\nHost: www.example.com\r\n\r\n".format(path),
        "timestamp": "1469733493.993",
        "body": ""
    }
    response_header = {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nCache-Control: max-age=300\r\nContent-Length: {0}\r\n\r\n".format(len(body)),
        "timestamp": "1469733493.993",
        "body": body
    }
    server.addResponse("sessionfile.log", request_header, response_header)


def make_phase(name, provided):
    '''Build one ATS + origin pair driving the given read path, and the pipelining
    client run against it.'''
    ts = Test.MakeATSProcess(name)
    # Disable the ProxyAllocator freelist so ASan can see any VC/buffer free ---
    # the held provided block spans the await, a classic use-after-free risk.
    ts.Command += " -F"
    server = Test.MakeOriginServer(name + "-server")
    add_response(server, "/a", BODY_A)
    add_response(server, "/b", BODY_B)

    ts.Disk.records_config.update(
        {
            'proxy.config.net.io_uring.enabled': 1,
            'proxy.config.net.io_uring.read_provided_buffers': provided,
            # Serve from origin every time; keep both paths on the network read.
            'proxy.config.http.cache.required_headers': 0,
            'proxy.config.diags.debug.enabled': 0,
        })

    ts.Disk.remap_config.AddLine('map http://www.example.com http://127.0.0.1:{0}'.format(server.Variables.Port))

    ts.Disk.diags_log.Content = Testers.ContainsExpression(
        "io_uring NetVConnection enabled", "the io_uring NetVConnection path must be active")

    tr = Test.AddTestRun("pipelined /a + /b on one connection ({0}, read_provided_buffers={1})".format(name, provided))
    tr.Processes.Default.Command = "python3 {0} {1} {2} {3}".format(CLIENT, ts.Variables.port, MARKER_A, MARKER_B)
    tr.Processes.Default.StartBefore(server)
    tr.Processes.Default.StartBefore(ts)
    tr.Processes.Default.ReturnCode = 0
    tr.Processes.Default.Streams.stdout = Testers.All(
        Testers.ContainsExpression(
            "PIPELINE_OK", "both pipelined responses must return in order with correct, non-desynced framing"),
        Testers.ExcludesExpression("FAIL:", "no framing / ordering / body failure"),
    )
    tr.TimeOut = 30  # must not hang
    tr.StillRunningAfter = ts
    tr.StillRunningAfter = server
    return ts, server


# Single-shot recvmsg read path.
make_phase("ts-singleshot", 0)
# Provided-buffer read path (the default).
make_phase("ts-provided", 1)
