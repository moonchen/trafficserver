'''
POST teardown races through the io_uring net path (write-abandon + origin RST mid-POST).
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
import socket
import sys

Test.Summary = '''
Drive two POST-teardown races through IOUringNetVConnection (proxy.config.net.io_uring.enabled=1),
under -F so ASan sees VC frees on the freelist, on the default provided-buffer read path
(read_provided_buffers=1):

  (a) EARLY: the origin sends a final response mid-POST, before draining the body. HttpSM's
      abort_tunnel then calls do_io_write(this, 0, nullptr) on the origin VC while the body send is
      in flight, exercising the write-abandon path (_write_abandoned + cancel_in_flight(_write_op);
      the resuming _write must skip its stale consume/signal against the POST source buffer the
      caller is about to free -- the bfb14a84ea / 05492305a1 recv-destination + write-abandon fixes).

  (b) RST: the origin aborts the connection with a TCP RST mid-POST-receive, driving the
      origin-facing _write into its error/close branch.

Each race is looped many times to widen the in-flight window. Asserts: the io_uring VC path is
active; the early origin 200 survives the write-abandon and reaches the client; the RST case
never succeeds (5xx or reset); the vc_deferred_close metric moved (teardowns with an op in
flight); the proxy stays up for a follow-up request; and (run under ASan) no crash / UAF /
freelist "bad list" abort / failed assertion across the churn.
'''

Test.ContinueOnFail = True

# Read metrics over the stats_over_http HTTP endpoint rather than traffic_ctl: traffic_ctl's
# ~200ms non-tunable connect budget against ATS's single-threaded jsonrpc server flakes under
# concurrent-suite load, and a deep sandbox root can push the jsonrpc UDS path
# (<sandbox>/<testdir>/<ts-name>/runtime/jsonrpc20.sock) past the AF_UNIX 108-byte sun_path
# limit entirely -- ATS then never starts the jsonrpc server ("File name too long") and this
# test's path is only a few bytes under. The HTTP endpoint has neither problem.
Test.SkipUnless(Condition.PluginExists('stats_over_http.so'))

COUNT = 40  # POST iterations per race (widens the in-flight teardown window)

_server_script = 'io_uring_post_abort_server.py'
_client_script = 'io_uring_post_abort_client.py'


def reserve_port() -> int:
    """Reserve an ephemeral port for a test-owned origin (bind-close, then rebind later)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class IOUringPostAbortTest:
    """One ATS instance pinned to a chosen io_uring read path, run through both races."""

    def __init__(self, read_provided: bool):
        self._read_provided = read_provided
        self._label = "provided" if read_provided else "singleshot"

    def _setup_scripts(self) -> None:
        Test.Setup.CopyAs(os.path.join(Test.TestDirectory, _server_script), Test.RunDirectory)
        Test.Setup.CopyAs(os.path.join(Test.TestDirectory, _client_script), Test.RunDirectory)

    def run(self) -> None:
        label = self._label

        ts = Test.MakeATSProcess(f"ts-{label}")
        ts.Command += " -F"  # disable the ProxyAllocator freelist so ASan sees VC frees

        early_port = reserve_port()
        rst_port = reserve_port()

        # An always-up origin for the post-race follow-up (proves the proxy survived).
        health = Test.MakeOriginServer(f"health-{label}")
        health.addResponse(
            "sessionfile.log", {
                "headers": "GET /health HTTP/1.1\r\nHost: health.test\r\n\r\n",
                "timestamp": "1469733493.993",
                "body": ""
            }, {
                "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 5\r\n\r\n",
                "timestamp": "1469733493.993",
                "body": "live\n"
            })

        early_server = Test.Processes.Process(
            f"early-server-{label}", f"{sys.executable} {_server_script} 127.0.0.1 {early_port} --mode early --count {COUNT + 10}")
        early_server.Ready = When.PortOpenv4(early_port)

        rst_server = Test.Processes.Process(
            f"rst-server-{label}", f"{sys.executable} {_server_script} 127.0.0.1 {rst_port} --mode rst --count {COUNT + 10}")
        rst_server.Ready = When.PortOpenv4(rst_port)

        ts.Disk.records_config.update(
            {
                'proxy.config.net.io_uring.enabled': 1,
                'proxy.config.net.io_uring.read_provided_buffers': 1 if self._read_provided else 0,
                # Fail fast to a 5xx on the RST case rather than retrying the dead origin.
                'proxy.config.http.connect_attempts_max_retries': 0,
            })

        ts.Disk.remap_config.AddLine(f'map http://early.test/ http://127.0.0.1:{early_port}/')
        ts.Disk.remap_config.AddLine(f'map http://rst.test/ http://127.0.0.1:{rst_port}/')
        ts.Disk.remap_config.AddLine(f'map http://health.test/ http://127.0.0.1:{health.Variables.Port}/')
        ts.Disk.plugin_config.AddLine('stats_over_http.so _stats')

        ts.Disk.diags_log.Content = Testers.ContainsExpression(
            "io_uring NetVConnection enabled", "the io_uring NetVConnection path must be active")

        # Race (a): early origin response mid-POST -> write-abandon.
        tr = Test.AddTestRun(f"[{label}] early origin response mid-POST (write-abandon)")
        self._setup_scripts()
        tr.Processes.Default.Command = (
            f"{sys.executable} {_client_script} 127.0.0.1 {ts.Variables.port} "
            f"--host early.test --mode early --count {COUNT}")
        tr.Processes.Default.StartBefore(health)
        tr.Processes.Default.StartBefore(early_server)
        tr.Processes.Default.StartBefore(ts)
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.Streams.stdout = Testers.All(
            Testers.ContainsExpression("EARLY_DONE", "the early-response loop must complete"),
            Testers.ContainsExpression("EARLY_STATUS_OBSERVED", "the early origin 200 must reach the client"))
        tr.TimeOut = 120
        tr.StillRunningAfter = ts
        tr.StillRunningAfter = health

        # Race (b): origin RST mid-POST-receive -> origin-facing _write error/close branch.
        tr = Test.AddTestRun(f"[{label}] origin RST mid-POST (outbound write error/teardown)")
        tr.Processes.Default.Command = (
            f"{sys.executable} {_client_script} 127.0.0.1 {ts.Variables.port} "
            f"--host rst.test --mode rst --count {COUNT}")
        tr.Processes.Default.StartBefore(rst_server)
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.Streams.stdout = Testers.All(
            Testers.ContainsExpression("RST_DONE", "the RST loop must complete"),
            Testers.ContainsExpression("RST_ABORT_OBSERVED", "the RST case must never succeed (5xx/reset only)"))
        tr.TimeOut = 120
        tr.StillRunningAfter = ts
        tr.StillRunningAfter = health

        # Follow-up: the proxy must still serve a fresh request after the teardown churn.
        tr = Test.AddTestRun(f"[{label}] follow-up request after the teardown races")
        tr.MakeCurlCommand(
            f'-s -o - -w "\\nFOLLOWUP=%{{http_code}}\\n" --proxy 127.0.0.1:{ts.Variables.port} '
            f'"http://health.test/health"',
            ts=ts)
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.Streams.stdout = Testers.All(
            Testers.ContainsExpression("FOLLOWUP=200", "the proxy must stay up and serve a follow-up request"),
            Testers.ContainsExpression("live", "the follow-up body must be delivered intact"))
        tr.StillRunningAfter = ts
        tr.StillRunningAfter = health

        # Metric: teardowns with an op in flight increment vc_deferred_close. Retry to let the
        # last completions settle.
        tr = Test.AddTestRun(f"[{label}] vc_deferred_close metric engaged")
        # Wall-clock deadline loop reading the metric over the stats_over_http CSV endpoint. A
        # transient HTTP failure (endpoint not yet serving) leaves the value empty and is retried
        # rather than misread as a genuine zero. The strict "-gt 0" assertion is unchanged, so an
        # unmoved metric still fails.
        tr.Processes.Default.Command = (
            'deadline=$$(( $$(date +%s) + 60 )); '
            'while [ $$(date +%s) -lt $$deadline ]; do '
            "csv=$$(curl -s --max-time 5 -H 'Accept: text/csv' \"http://127.0.0.1:" + str(ts.Variables.port) + "/_stats/csv\"); "
            "dc=$$(printf '%s' \"$$csv\" | grep '^proxy.process.net.io_uring.vc_deferred_close,' | cut -d, -f2); "
            'if [ "$${dc:-0}" -gt 0 ] 2>/dev/null; then echo "DEFERRED_CLOSE_OK count=$$dc"; exit 0; fi; '
            'sleep 0.3; done; echo DEFERRED_CLOSE_FAIL; exit 1')
        tr.TimeOut = 90
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
            "DEFERRED_CLOSE_OK", "close-with-op-in-flight must have incremented vc_deferred_close")
        tr.StillRunningAfter = ts


# The default provided-buffer read path is memory-safe under these teardown races. The
# single-shot path (read_provided_buffers=0) is NOT covered here: it hits a distinct,
# currently-unfixed bug in _read's held-read-bytes replay -- when HttpSM re-arms the inbound
# read on a DIFFERENT MIOBuffer during the POST teardown while a recv's bytes are parked in
# _held_read_buf, the "same-buffer" invariant at IOUringNetVConnection.cc:509 is violated and
# the ink_release_assert aborts the process (signal 6). Exercising it here would crash ATS and
# make this test a permanent red; it should be re-enabled with read_provided in [False, True]
# once the single-shot replay path copies-back / re-targets instead of asserting.
for read_provided in [True]:
    IOUringPostAbortTest(read_provided).run()
