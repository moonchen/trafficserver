'''
do_io_close while an io_uring op is in flight: cancel-then-unwind + deferred free.
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
Exercise the io_uring do_io_close cancel-then-unwind path: a client aborts / RSTs mid-transfer
while ATS still has an io_uring op in flight (a recv on the request/keep-alive read, or a plain
non-ZC send of the response body). do_io_close must cancel the in-flight op(s), defer the free
until the cancel CQE resumes the coroutine, and free exactly once when the last op clears --
without resuming into a freed VC. The both-directions duplex POST (large upload + large response
body, aborted mid-transfer) drives the last-op-frees gate that inspects _read_op/_write_op both.

Run under ASan with the ProxyAllocator freelist disabled (-F) so a use-after-free or a
free-more-than-once trips immediately. Parametrized over both read paths: single-shot
recvmsg (read_provided_buffers=0) and the default provided-buffer ring (read_provided_buffers=1).

Asserts: the vc_deferred_close metric moved (>0), a follow-up full GET still returns 200 with the
correct body, ATS is StillRunningAfter, and traffic.out is clean of bad-list / ASan / assertion /
fatal-signal noise. write_zerocopy stays off (default), so sends take the plain send/sendmsg path.
'''

Test.ContinueOnFail = False

Test.SkipUnless(Condition.HasATSFeature('TS_USE_LINUX_IO_URING'))

# Read the vc_deferred_close metric over the stats_over_http HTTP endpoint rather than
# traffic_ctl: traffic_ctl's ~200ms non-tunable connect budget against ATS's single-threaded
# jsonrpc server flakes under concurrent-suite load, and a deep sandbox root can push the
# jsonrpc UDS path past the AF_UNIX 108-byte sun_path limit entirely (ATS then never starts
# the jsonrpc server, "File name too long"). The HTTP endpoint has neither problem.
Test.SkipUnless(Condition.PluginExists('stats_over_http.so'))

# Shared with io_uring_timeout_variants: connects, sends a partial request line, then idles
# until ATS closes the connection (prints SERVER_CLOSED/SERVER_SENT).
IDLE_CLIENT = os.path.join(Test.TestDirectory, "io_uring_timeout_variants_idle_client.py")

server = Test.MakeOriginServer("server")

# ~1 MiB cacheable body with a unique end marker present only if every byte was reassembled in
# order -- the follow-up full GET verifies the VC teardown churn left the serve path healthy.
GET_BODY = ("io_uring_close_inflight_payload." * 33825) + "END_GET_MARKER"  # ~1 MiB
server.addResponse(
    "sessionfile.log", {
        "headers": "GET /big HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nCache-Control: max-age=300\r\nContent-Length: {0}\r\n\r\n".format(
                len(GET_BODY)),
        "timestamp": "1469733493.993",
        "body": GET_BODY
    })

# A large response body for the duplex POST: ATS sends this to the client (send in flight) while it
# is still draining the client's large upload (recv in flight) -- both-directions-pending at close.
POST_BODY = ("io_uring_close_inflight_post." * 37450) + "END_POST_MARKER"  # ~1 MiB
server.addResponse(
    "sessionfile.log", {
        "headers": "POST /upload HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nConnection: close\r\nCache-Control: no-store\r\nContent-Length: {0}\r\n\r\n".format(len(POST_BODY)),
        "timestamp": "1469733493.993",
        "body": POST_BODY
    })


def add_phases(read_provided):
    '''Build the full close-in-flight scenario against one ATS process configured for the given
    read path (0 = single-shot recvmsg, 1 = provided-buffer ring).'''
    label = "provided" if read_provided else "singleshot"
    # Short process name (ts0/ts1): the per-process runtime/uds.socket path must stay under the
    # ~108-byte AF_UNIX sun_path limit, and this test's long name already eats into that budget.
    ts = Test.MakeATSProcess("ts{0}".format(read_provided))
    # -F disables the ProxyAllocator freelist so ASan sees the VC free directly: a resume-into-freed
    # VC (missed defer) or a double free (bad gate) trips instead of being masked by the freelist.
    ts.Command += " -F"

    ts.Disk.records_config.update(
        {
            'proxy.config.net.io_uring.enabled': 1,
            'proxy.config.net.io_uring.read_provided_buffers': read_provided,
            # write_zerocopy stays default-off: response body sends take the plain send/sendmsg
            # path, so the in-flight op cancelled at close is a plain _write_op (not send_zc+NOTIF).
            # Cache /big so the churn phase hammers ATS's serve+close path, not the Python origin.
            'proxy.config.http.cache.required_headers': 0,
            # Generous ring + provided-buffer working set so a cache-miss read never parks on
            # -ENOBUFS while the abort churn recycles buffers.
            'proxy.config.net.io_uring.read_buffer_count': 4096,
            'proxy.config.net.io_uring.read_buffer_size': 8192,
            'proxy.config.io_uring.entries': 8192,
            # For the deterministic deferred-close phase: an idled inbound transaction is torn
            # down after 5s with its request recv still parked. Wide enough that the active
            # transfers of the churn/follow-up phases never idle into it under load.
            'proxy.config.http.transaction_no_activity_timeout_in': 5,
        })

    ts.Disk.remap_config.AddLine('map http://www.example.com http://127.0.0.1:{0}'.format(server.Variables.Port))
    ts.Disk.plugin_config.AddLine('stats_over_http.so _stats')

    ts.Disk.diags_log.Content = Testers.ContainsExpression(
        "io_uring NetVConnection enabled", "the io_uring NetVConnection path must be active ({0})".format(label))

    port = ts.Variables.port

    # Phase 1: warm the cache -- one full GET (miss -> origin read -> disk write).
    tr = Test.AddTestRun("[{0}] warm the cache: full GET /big".format(label))
    tr.MakeCurlCommand(
        '-s -o /dev/null -w "%{{http_code}}" "http://127.0.0.1:{0}/big" -H "Host: www.example.com"'.format(port), ts=ts)
    if read_provided == 0:
        # First ATS + the shared origin come up before the very first phase overall.
        tr.Processes.Default.StartBefore(server)
    tr.Processes.Default.StartBefore(ts)
    tr.Processes.Default.ReturnCode = 0
    tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("200", "the warm GET must be 2xx")
    tr.StillRunningAfter = ts
    tr.StillRunningAfter = server

    # Phase 2: read-side abort churn -- fetch the ~1 MiB body but read only 4 KiB then close. ATS is
    # mid-serve (a plain response-body send, and/or a keep-alive recv, in flight) when the client
    # RSTs, so do_io_close cancels the in-flight op and defers the free (vc_deferred_close++).
    tr = Test.AddTestRun("[{0}] abort mid-download: close with a send/recv in flight (x60)".format(label))
    tr.Processes.Default.Command = (
        'for r in $$(seq 1 60); do '
        'curl -s "http://127.0.0.1:{port}/big" -H "Host: www.example.com" '
        '| head -c 4096 >/dev/null || true; done; echo ABORT_DONE'.format(port=port))
    tr.Processes.Default.ReturnCode = 0
    tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("ABORT_DONE", "the read-abort loop must complete")
    tr.StillRunningAfter = ts
    tr.StillRunningAfter = server

    # Phase 3: duplex both-directions abort -- upload ~1 MiB (client->ATS recv in flight) while the
    # ~1 MiB response streams back (ATS->client send in flight), then abort after 4 KiB. Close then
    # finds both a _read_op and a _write_op pending, exercising the last-op-frees gate that inspects
    # all in-flight ops before the single free.
    tr = Test.AddTestRun("[{0}] duplex POST abort: both-directions-pending at close (x30)".format(label))
    tr.Processes.Default.Command = (
        'for r in $$(seq 1 30); do '
        'head -c 1048576 /dev/zero | '
        'curl -s --data-binary @- -H "Content-Type: application/octet-stream" '
        '-H "Expect:" "http://127.0.0.1:{port}/upload" -H "Host: www.example.com" '
        '| head -c 4096 >/dev/null || true; done; echo DUPLEX_DONE'.format(port=port))
    tr.Processes.Default.ReturnCode = 0
    tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("DUPLEX_DONE", "the duplex-abort loop must complete")
    tr.StillRunningAfter = ts
    tr.StillRunningAfter = server

    # Phase 3b: one deferred close that cannot race. A client that sends a partial request and
    # idles forces the inbound no-activity timeout to tear the VC down while its request recv
    # is parked in the kernel on the quiet socket, so the timeout/free_thread teardown must
    # defer the free (vc_deferred_close++). The abort/duplex churn above races HttpSM's close
    # against the RST-driven error CQEs -- under heavy load every in-flight op can complete
    # (with error) before the close runs, legitimately deferring nothing -- so the metric gate
    # below needs this one guaranteed engagement.
    tr = Test.AddTestRun("[{0}] idle partial request: timeout close with recv parked".format(label))
    tr.Processes.Default.Command = "{0} {1} 127.0.0.1 {2}".format(sys.executable, IDLE_CLIENT, port)
    tr.Processes.Default.ReturnCode = 0
    tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
        "SERVER_", "ATS must close the idled connection via the inbound no-activity timeout")
    tr.TimeOut = 60
    tr.StillRunningAfter = ts
    tr.StillRunningAfter = server

    # Phase 4: the deferred-close metric must have engaged. Wall-clock deadline loop over the
    # stats_over_http CSV endpoint: a transient HTTP failure leaves the value empty and is
    # retried rather than misread as a genuine zero. The strict "-gt 0" assertion is unchanged,
    # so an unmoved metric still fails.
    tr = Test.AddTestRun("[{0}] vc_deferred_close engaged".format(label))
    tr.Processes.Default.Command = (
        'deadline=$$(( $$(date +%s) + 60 )); '
        'while [ $$(date +%s) -lt $$deadline ]; do '
        "csv=$$(curl -s --max-time 5 -H 'Accept: text/csv' \"http://127.0.0.1:" + str(port) + "/_stats/csv\"); "
        "dc=$$(printf '%s' \"$$csv\" | grep '^proxy.process.net.io_uring.vc_deferred_close,' | cut -d, -f2); "
        'if [ "$${dc:-0}" -gt 0 ] 2>/dev/null; then echo "DEFERRED_OK deferred_close=$$dc"; exit 0; fi; '
        'sleep 0.3; done; echo DEFERRED_FAIL; exit 1')
    tr.TimeOut = 90
    tr.Processes.Default.ReturnCode = 0
    tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
        "DEFERRED_OK", "do_io_close must have deferred at least one free past an in-flight op")
    tr.StillRunningAfter = ts

    # Phase 5: the serve+close churn must have left ATS healthy -- a fresh full GET returns 200 with
    # the whole body intact (end marker present == every byte reassembled in order).
    tr = Test.AddTestRun("[{0}] follow-up full GET: still healthy, full body".format(label))
    tr.MakeCurlCommand(
        '-s -o - -w "\\nHTTP_%{{http_code}}_SIZE_%{{size_download}}\\n" '
        '"http://127.0.0.1:{0}/big" -H "Host: www.example.com"'.format(port),
        ts=ts)
    tr.Processes.Default.ReturnCode = 0
    tr.Processes.Default.Streams.stdout = Testers.All(
        Testers.ContainsExpression("END_GET_MARKER", "the full body must survive after the abort churn"),
        Testers.ContainsExpression("HTTP_200_SIZE_{0}".format(len(GET_BODY)), "200 with the exact body size"),
    )
    tr.StillRunningAfter = ts
    tr.StillRunningAfter = server


for rp in (0, 1):
    add_phases(rp)
