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
        })

    ts.Disk.remap_config.AddLine('map http://www.example.com http://127.0.0.1:{0}'.format(server.Variables.Port))

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

    # Phase 4: the deferred-close metric must have engaged. Retry-poll to let the last cancel CQEs
    # settle (mirrors the write_zerocopy metric phase).
    tr = Test.AddTestRun("[{0}] vc_deferred_close engaged".format(label))
    tr.Processes.Default.Command = (
        'for i in $$(seq 1 50); do '
        "dc=$$(traffic_ctl metric get proxy.process.net.io_uring.vc_deferred_close | grep -oE '[0-9]+$$'); "
        'if [ "$${dc:-0}" -gt 0 ]; then echo "DEFERRED_OK deferred_close=$$dc"; exit 0; fi; '
        'sleep 0.2; done; echo DEFERRED_FAIL; traffic_ctl metric match proxy.process.net.io_uring; exit 1')
    tr.Processes.Default.Env = ts.Env
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
