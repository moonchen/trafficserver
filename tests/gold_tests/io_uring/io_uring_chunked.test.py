'''
Chunked framing + Expect: 100-continue over the io_uring net path.
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
from ports import get_port

Test.Summary = '''
Exercise HTTP framing edge cases over the io_uring net path (proxy.config.net.io_uring.enabled=1),
against a raw-socket origin that gives byte-exact control the stock origin cannot:

  (a) Chunked RESPONSE: origin returns Transfer-Encoding: chunked (several chunks + 0-chunk
      terminator, no Content-Length). ATS reads/dechunks it over the origin-facing io_uring read
      path; the client must get the full reassembled body.
  (b) Chunked REQUEST: the client POSTs an unknown-length (Transfer-Encoding: chunked) body. ATS
      reads it on the inbound io_uring VC and tunnels it to origin. The origin must receive the
      full byte-exact body (verified by echoing it back to the client) with a 200.
  (c) Expect: 100-continue: with proxy.config.http.send_100_continue_response=1 ATS writes a small
      interim "100 Continue" to the client on the inbound VC, then resumes the body read on that
      same VC (the interim-write-interleaved-with-resumed-read path). Both the 100 Continue and the
      final 200 must reach the client, and the full body must reach origin.

Runs the whole matrix twice -- once with the single-shot recvmsg read path
(read_provided_buffers=0) and once with the default provided-buffer read path (read_provided_buffers=1)
-- so both io_uring read paths are covered.
'''

Test.ContinueOnFail = False

# A ~200 KB upload with a unique end marker: only present in the echo if the whole chunked/CL body
# was read on the inbound VC, tunneled, reassembled at origin, and returned intact.
_upload = (b"io_uring_upload_payload." * 8334) + b"END_OF_UPLOAD_MARKER"
UPLOAD_MARKER = "END_OF_UPLOAD_MARKER"
upload_path = os.path.join(Test.RunDirectory, "io_uring_chunked_upload.dat")
with open(upload_path, "wb") as _f:
    _f.write(_upload)

origin_script = os.path.join(Test.TestDirectory, "io_uring_chunked_origin.py")


def make_variant(read_provided):
    '''Build one ATS + one origin and run scenarios (a)/(b)/(c) against them.'''
    tag = "provided" if read_provided else "singleshot"

    ts = Test.MakeATSProcess("ts-{0}".format(tag))
    # Disable the ProxyAllocator freelist so ASan sees VC/buffer frees on the chunked read/write
    # and Expect interim-write paths (freelist recycling would mask a use-after-free).
    ts.Command += " -F"

    server = Test.Processes.Process("origin-{0}".format(tag))
    origin_port = get_port(server, "http_port")
    server.Command = "python3 {0} 127.0.0.1 {1}".format(origin_script, origin_port)
    server.Ready = When.PortOpenv4(origin_port)

    ts.Disk.records_config.update(
        {
            'proxy.config.net.io_uring.enabled': 1,
            'proxy.config.net.io_uring.read_provided_buffers': read_provided,
            # ATS answers Expect: 100-continue itself -> the small interim write then resumed body
            # read on the inbound io_uring VC (scenario c).
            'proxy.config.http.send_100_continue_response': 1,
        })

    # Remap key has no :port (a :port key silently 404s "Not Found on Accelerator").
    ts.Disk.remap_config.AddLine('map http://www.example.com http://127.0.0.1:{0}'.format(origin_port))

    ts.Disk.diags_log.Content = Testers.ContainsExpression(
        "io_uring NetVConnection enabled", "the io_uring NetVConnection path must be active")

    # (a) Chunked RESPONSE dechunked on the io_uring read path.
    tr = Test.AddTestRun("[{0}] (a) chunked response dechunked over io_uring".format(tag))
    tr.MakeCurlCommand(
        '-s -o - -w "\\nRESP_HTTP_%{{http_code}}\\n" --proxy 127.0.0.1:{0} "http://www.example.com/chunked"'.format(
            ts.Variables.port),
        ts=ts)
    tr.Processes.Default.StartBefore(server)
    tr.Processes.Default.StartBefore(ts)
    tr.Processes.Default.ReturnCode = 0
    tr.Processes.Default.Streams.stdout = Testers.All(
        Testers.ContainsExpression("CHUNKED_END_MARKER", "the full dechunked response body must arrive intact"),
        Testers.ContainsExpression("RESP_HTTP_200", "the chunked response must complete with a 200"),
    )
    tr.StillRunningAfter = ts
    tr.StillRunningAfter = server

    # (b) Chunked REQUEST body read on the inbound VC and tunneled to origin (echoed back).
    tr = Test.AddTestRun("[{0}] (b) chunked request body tunneled over io_uring".format(tag))
    tr.MakeCurlCommand(
        '-s -o - -w "\\nUPLOAD_HTTP_%{{http_code}}\\n" '
        '-H "Transfer-Encoding: chunked" --data-binary @{file} '
        '--proxy 127.0.0.1:{port} "http://www.example.com/echo"'.format(file=upload_path, port=ts.Variables.port),
        ts=ts)
    tr.Processes.Default.ReturnCode = 0
    tr.Processes.Default.Streams.stdout = Testers.All(
        Testers.ContainsExpression(UPLOAD_MARKER, "the full chunked request body must reach origin and echo back byte-exact"),
        Testers.ContainsExpression("UPLOAD_HTTP_200", "the tunneled chunked POST must complete with a 200"),
    )
    tr.StillRunningAfter = ts
    tr.StillRunningAfter = server

    # (c) Expect: 100-continue -> interim 100 write interleaved with the resumed body read.
    tr = Test.AddTestRun("[{0}] (c) Expect: 100-continue interim write + resumed read".format(tag))
    tr.MakeCurlCommand(
        '-s -v -o - -w "\\nEXPECT_HTTP_%{{http_code}}\\n" '
        '-H "Expect: 100-continue" --data-binary @{file} '
        '--proxy 127.0.0.1:{port} "http://www.example.com/echo"'.format(file=upload_path, port=ts.Variables.port),
        ts=ts)
    tr.Processes.Default.ReturnCode = 0
    # -v routes the interim/final status lines to stderr; the echoed body + -w code go to stdout.
    tr.Processes.Default.Streams.All = Testers.All(
        Testers.ContainsExpression("100 Continue", "ATS must send the interim 100 Continue to the client"),
        Testers.ContainsExpression("EXPECT_HTTP_200", "the request must complete with a final 200"),
        Testers.ContainsExpression(UPLOAD_MARKER, "the full body must reach origin after the 100 Continue and echo back"),
    )
    tr.StillRunningAfter = ts
    tr.StillRunningAfter = server


for _rp in [0, 1]:
    make_variant(_rp)
