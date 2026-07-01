'''
Empty-body responses (204 / Content-Length: 0 / HEAD) over a reused keep-alive
inbound connection, through the io_uring net path.
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
With proxy.config.net.io_uring.enabled=1, drive empty-body responses (204 No Content,
Content-Length: 0, and HEAD) followed by a normal bodied GET, all on ONE reused inbound
keep-alive connection.

Each empty-body response takes the io_uring inbound read path through the read VIO
ntodo() <= 0 gate (_read / _read_provided read-disable) and a header-only write; the idle
keep-alive VC then holds no read buffer (provided-buffer late binding, buffer.writer() ==
nullptr) and must re-arm cleanly for the next request without a stray read event or a hang.
The trailing bodied GET proves the VC re-armed and reads/writes a real body normally.

Run once per read path: read_provided_buffers=0 (single-shot recvmsg) and =1 (the default
provided-buffer path). A single proxy-verifier session replays all four transactions on one
connection; the verifier reports "(reuse 4)" only if every request -- including the ones
following an empty-body response -- was served on that one reused inbound VC (had ATS
dropped the connection after an empty-body response, the later transactions would fail).
'''

Test.ContinueOnFail = False

replay_file = "io_uring_empty_body.replay.yaml"


def run_phase(read_provided_buffers):
    label = "provided-buffer" if read_provided_buffers else "single-shot"
    suffix = str(read_provided_buffers)

    tr = Test.AddTestRun("empty-body over reused keep-alive: {0} read path".format(label))
    # Test-scoped so the process persists to the run boundary where StillRunningAfter is
    # evaluated (a run-scoped tr.MakeATSProcess is torn down at run end and would fail it).
    ts = Test.MakeATSProcess("ts{0}".format(suffix))
    server = tr.AddVerifierServerProcess("server{0}".format(suffix), replay_file)

    ts.Disk.records_config.update(
        {
            'proxy.config.net.io_uring.enabled': 1,
            'proxy.config.net.io_uring.read_provided_buffers': read_provided_buffers,
            # Keep the inbound connection alive so the four-transaction session is served
            # over one reused VC (this is the default; set explicitly to make the test
            # self-contained and independent of any global default drift).
            'proxy.config.http.keep_alive_enabled_in': 1,
        })

    ts.Disk.remap_config.AddLine('map http://www.example.com http://127.0.0.1:{0}'.format(server.Variables.http_port))

    # Prove the io_uring VC path actually engaged (not a silent fallback to
    # UnixNetVConnection, which would pass this test for the wrong reason).
    ts.Disk.diags_log.Content = Testers.ContainsExpression(
        "io_uring NetVConnection enabled", "the io_uring NetVConnection path must be active")

    tr.Processes.Default.StartBefore(server)
    tr.Processes.Default.StartBefore(ts)
    # The verifier verifies each proxy-response (status + the X-Body-Kind marker, and for the
    # final transaction the Content-Length) against the replay. All four transactions run on
    # one session/connection, so this only passes if the empty-body VC re-armed for each
    # request without a stray read event or a hang.
    client = tr.AddVerifierClientProcess("client{0}".format(suffix), replay_file, http_ports=[ts.Variables.port])

    # Reuse proof: the verifier serves the whole four-transaction session on one connection and
    # reports "(reuse 4)" only if all four -- the three empty-body responses and the trailing
    # bodied GET -- were served on that single reused inbound VC. Per-request reconnects (a VC
    # that failed to re-arm and got torn down) would show a lower reuse count or fail outright.
    client.Streams.stdout = Testers.All(
        Testers.ContainsExpression("4 transactions in 1 session", "all four transactions ran in one session"),
        Testers.ContainsExpression(r"\(reuse 4\)", "all four transactions must reuse one inbound connection"),
    )
    tr.StillRunningAfter = ts


# Exercise BOTH read paths: single-shot recvmsg and the default provided-buffer ring.
run_phase(0)
run_phase(1)
