'''
Keep-alive origin session reuse over the io_uring read path: the do_io_read
re-target copy-back + held-bytes replay branches.
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
Exercise the io_uring read path's do_io_read re-target branches under origin
keep-alive session reuse.

With the cache off and origin session sharing on, ATS forwards every request to
the origin and reuses a single ATS<->origin session across all of them. Between
responses the session returns to the pool and do_io_read is re-armed onto a
DIFFERENT MIOBuffer (the session read_buffer) while the prior body read-ahead
recv may still be in flight. When that recv completes it must deliver the
next response's leading bytes into the re-armed buffer -- the redirect copy-back
(_read) / _held_pbuf hold + delivery (_read_provided) path, and the disabled-in-
flight HOLD + top-of-loop replay guarded by ink_release_assert(writer ==
_held_read_buf). A byte that bled from response k into response k+1 would break
framing or content; each of the 40 sequential responses carries a distinct
marker and a distinct length so the Proxy Verifier client catches any bleed as a
violation.

Run over BOTH read paths: read_provided_buffers=0 (single-shot recvmsg _read)
and =1 (kernel provided-buffer _read_provided, the default).
'''

Test.ContinueOnFail = False

# Read metrics over the stats_over_http HTTP endpoint rather than traffic_ctl, which fails two
# ways here. (a) Deterministic: this test's jsonrpc UDS path (<sandbox>/<testdir>/<ts-name>/
# runtime/jsonrpc20.sock) overflows the AF_UNIX 108-byte sun_path limit under a deep sandbox
# root (e.g. anything at or below this repo's tests/ dir), so ATS never starts the jsonrpc
# server ("JSONRPC server could not be started ... File name too long" in diags.log) and every
# traffic_ctl query fails. (b) Transient: even where the path fits, traffic_ctl's ~200ms
# non-tunable connect budget against ATS's single-threaded RPC server flakes under
# concurrent-suite load. The HTTP endpoint has neither problem.
Test.SkipUnless(Condition.PluginExists('stats_over_http.so'))

REPLAY = "io_uring_keepalive_rearm.replay.yaml"


class KeepAliveRearmTest:
    """Drive keep-alive origin reuse for one read-path configuration."""

    def __init__(self, read_provided_buffers: int):
        self._rpb = read_provided_buffers
        label = "provided" if read_provided_buffers else "singleshot"
        # Keep process names short: ATS's jsonrpc UDS lives at
        # <sandbox>/<testdir>/<ts-name>/runtime/jsonrpc20.sock, and past the
        # AF_UNIX 108-byte sun_path limit ATS refuses to start the jsonrpc
        # server ("File name too long"), breaking every traffic_ctl query.
        slug = "pb" if read_provided_buffers else "ss"
        self._name = f"kar-{slug}"
        tr = Test.AddTestRun(f"keep-alive origin reuse over io_uring read path ({label})")
        self._configure_server(tr)
        self._configure_ts(tr)
        self._configure_client(tr)
        self._verify_reuse()

    def _configure_server(self, tr: 'TestRun') -> 'Process':
        # Proxy Verifier origin. All 40 transactions live in one replay session,
        # so the server serves them keep-alive over a single connection.
        self._server = tr.AddVerifierServerProcess(f"{self._name}-server", REPLAY)
        return self._server

    def _configure_ts(self, tr: 'TestRun') -> 'Process':
        # Cache off => every request is forwarded to origin, so the ATS<->origin
        # session is the one that gets reused (not short-circuited by a hit).
        ts = Test.MakeATSProcess(f"{self._name}-ts", enable_cache=False)
        self._ts = ts
        ts.Disk.records_config.update(
            {
                'proxy.config.net.io_uring.enabled': 1,
                'proxy.config.net.io_uring.read_provided_buffers': self._rpb,
                # Reuse a pooled origin session across transactions so the pool re-arm onto the
                # session read_buffer is exercised. Must be the per-thread pool: io_uring VCs are
                # thread-confined and cannot be migrated across threads, so the global/hybrid pools
                # are rejected at startup with io_uring (see HttpConfig). A keep-alive client keeps
                # its transactions on one net thread, so the thread pool reuses the same session.
                'proxy.config.http.server_session_sharing.pool': 'thread',
                'proxy.config.http.server_session_sharing.match': 'both',
                'proxy.config.http.keep_alive_enabled_out': 1,
            })
        ts.Disk.remap_config.AddLine(
            'map http://keepalive.rearm.test http://127.0.0.1:{0}'.format(self._server.Variables.http_port))
        ts.Disk.plugin_config.AddLine('stats_over_http.so _stats')
        # Prove the io_uring VC actually engaged (not a silent UnixNetVConnection
        # fallback that would pass this test for the wrong reason).
        ts.Disk.diags_log.Content = Testers.ContainsExpression(
            "io_uring NetVConnection enabled", "the io_uring NetVConnection path must be active")
        return ts

    def _configure_client(self, tr: 'TestRun') -> 'Process':
        # One client connection carries all 40 transactions sequentially. The
        # verifier client verifies each response's status, length, X-Resp-Id and
        # byte-exact body against the replay -- so any cross-request byte bleed,
        # framing error, or non-200 fails the run (it already asserts
        # ReturnCode==0 and excludes "Violation|Invalid status").
        self._client = tr.AddVerifierClientProcess(f"{self._name}-client", REPLAY, http_ports=[self._ts.Variables.port])
        self._client.StartBefore(self._server)
        self._client.StartBefore(self._ts)
        # Keep ATS alive past this run so the reuse-check testrun can query the
        # origin.reuse metric over the still-open RPC socket.
        tr.StillRunningAfter = self._ts
        return self._client

    def _verify_reuse(self) -> 'TestRun':
        # Confirm the ATS<->origin session was really reused (the whole point --
        # otherwise the re-arm-onto-session-read_buffer branch never runs). The
        # counter should climb toward the 39 reuses of a 40-transaction session.
        tr = Test.AddTestRun(f"{self._name}: origin session reuse engaged")
        # Wall-clock deadline loop reading the metric over the stats_over_http CSV endpoint. A
        # transient HTTP failure (endpoint not yet serving) leaves the value empty and is retried
        # rather than misread as a genuine zero. The strict "-gt 0" assertion is unchanged, so an
        # unmoved metric still fails.
        port = self._ts.Variables.port
        tr.Processes.Default.Command = (
            'deadline=$$(( $$(date +%s) + 60 )); '
            'while [ $$(date +%s) -lt $$deadline ]; do '
            "csv=$$(curl -s --max-time 5 -H 'Accept: text/csv' \"http://127.0.0.1:" + str(port) + "/_stats/csv\"); "
            "n=$$(printf '%s' \"$$csv\" | grep '^proxy.process.http.origin.reuse,' | cut -d, -f2); "
            'if [ "$${n:-0}" -gt 0 ] 2>/dev/null; then echo "REUSE_OK reuse=$$n"; exit 0; fi; '
            'sleep 0.3; done; echo REUSE_FAIL; exit 1')
        tr.TimeOut = 90
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
            "REUSE_OK", "the ATS<->origin keep-alive session must have been reused")
        tr.StillRunningAfter = self._ts
        return tr


# Single-shot recvmsg read path and the default provided-buffer read path.
KeepAliveRearmTest(read_provided_buffers=0)
KeepAliveRearmTest(read_provided_buffers=1)
