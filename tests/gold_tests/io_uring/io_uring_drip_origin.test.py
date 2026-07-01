'''
io_uring short-read / re-arm read path: an origin that trickles the body in
small pieces, so every recv is a short read and the coroutine must re-arm and
block in the kernel for the next piece, with no premature EOS.
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

Test.Summary = '''
With proxy.config.net.io_uring.enabled=1, proxy from an origin that trickles the
full Content-Length body back in 64-byte pieces with a 50ms gap between each. Each
io_uring recv on the origin VC returns far less than it attempted (a short read),
so the read coroutine re-arms and blocks in the kernel for the next piece
(_read short-read re-arm 749-754; _read_provided short-read re-arm 953-957). The
full body must be reassembled in order with no premature EOS. Run over BOTH read
paths: single-shot recvmsg (read_provided_buffers=0) and the default kernel
provided-buffer ring (read_provided_buffers=1).
'''

Test.ContinueOnFail = True

drip_server = os.path.join(Test.TestDirectory, "io_uring_drip_origin_server.py")

# Reserve a port for the drip origin (a single origin serves both read-path phases).
import socket as _socket

_s = _socket.socket()
_s.bind(("127.0.0.1", 0))
drip_port = _s.getsockname()[1]
_s.close()

server = Test.Processes.Process("drip-server", "{0} {1} {2}".format(sys.executable, drip_server, drip_port))
server.Ready = When.PortOpen(drip_port)


def make_ts(name, read_provided_buffers):
    ts = Test.MakeATSProcess(name)
    ts.Disk.records_config.update(
        {
            'proxy.config.net.io_uring.enabled': 1,
            'proxy.config.net.io_uring.read_provided_buffers': read_provided_buffers,
        })
    ts.Disk.remap_config.AddLine('map http://www.example.com http://127.0.0.1:{0}'.format(drip_port))
    ts.Disk.diags_log.Content = Testers.ContainsExpression(
        "io_uring NetVConnection enabled", "the io_uring NetVConnection path must be active")
    return ts


# Two ATS processes, one per read path, sharing the one drip origin.
ts_single = make_ts("ts-single", 0)  # single-shot recvmsg read path
ts_provided = make_ts("ts-provided", 1)  # kernel provided-buffer read path (default)

# Curl must outlast the whole drip (80 chunks x 50ms ~= 4s); give generous headroom.
CURL_TIMEOUT = 60


def add_phase(desc, ts, first):
    tr = Test.AddTestRun(desc)
    tr.MakeCurlCommand(
        '-s -o - --max-time {0} --proxy 127.0.0.1:{1} "http://www.example.com/drip"'.format(CURL_TIMEOUT, ts.Variables.port), ts=ts)
    if first:
        tr.Processes.Default.StartBefore(server)
    tr.Processes.Default.StartBefore(ts)
    tr.Processes.Default.ReturnCode = 0
    # The unique end marker only survives if every short read landed and the body
    # was reassembled in order with no premature EOS.
    tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
        "END_OF_DRIP_BODY_MARKER", "the full trickled body must survive reassembly across the short reads")
    tr.TimeOut = CURL_TIMEOUT + 10
    tr.StillRunningAfter = ts
    tr.StillRunningAfter = server


# Phase 1: single-shot recvmsg short-read / re-arm.
add_phase("trickled body through the single-shot io_uring read path", ts_single, first=True)
# Phase 2: provided-buffer short-read / re-arm.
add_phase("trickled body through the provided-buffer io_uring read path", ts_provided, first=False)
