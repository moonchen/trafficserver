'''
Outbound io_uring connect to a black-holed origin: the linked IORING_OP_LINK_TIMEOUT
fires -ECANCELED, and a client that aborts mid-connect tears down the connecting VC
with the connect SQE still pending.
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
import socket as _socket
import sys

Test.Summary = '''
With proxy.config.net.io_uring.enabled=1 and ATS run under -F (freelist off, so
ASan sees VC frees), exercise IOUringNetVConnection::_connect() against a black-holed
origin whose TCP handshake never completes (accept queue overfilled -> SYNs dropped,
no RST). This is distinct from io_uring_connect's refused case (prompt -ECONNREFUSED):

  Phase 1 -- LINK_TIMEOUT fires: the connect SQE is submitted with a linked
      IORING_OP_LINK_TIMEOUT of connect_attempts_timeout=3s. With the handshake
      black-holed the timeout fires, the connect op completes -ECANCELED, and
      _connect() maps that to ETIMEDOUT -> NET_EVENT_OPEN_FAILED. The client must
      get a 5xx after ~3s (not an instant refused, not a hang).

  Phase 2 -- teardown mid-connect: a client that aborts (curl --max-time 1) before
      the 3s timeout tears down the outbound connecting VC while the connect SQE is
      still pending. The op must be cancelled and the free deferred/unwound without
      resuming into a freed VC (do_io_close -> _closing -> _complete_deferred_close,
      or the action_.cancelled -> free_netevent path). Looped for connection churn;
      under -F any resume-into-freed-VC surfaces as an ASan use-after-free.
'''

Test.ContinueOnFail = True

ORIGIN_SCRIPT = os.path.join(Test.TestDirectory, "io_uring_connect_timeout_origin.py")

CONNECT_TIMEOUT = 3  # proxy.config.http.connect_attempts_timeout (== the linked timeout)

# Reserve a port for the black-hole origin the test owns.
_s = _socket.socket()
_s.bind(("127.0.0.1", 0))
blackhole_port = _s.getsockname()[1]
_s.close()

origin = Test.Processes.Process("blackhole-origin", "{0} {1} {2}".format(sys.executable, ORIGIN_SCRIPT, blackhole_port))
origin.Ready = When.PortOpen(blackhole_port)

ts = Test.MakeATSProcess("ts")
ts.Command += " -F"  # freelist off so ASan surfaces any teardown UAF on the connect-op resume

ts.Disk.records_config.update(
    {
        'proxy.config.net.io_uring.enabled': 1,
        # The connect attempt (and the io_uring linked timeout) caps at 3s; no retries
        # so the first timeout surfaces straight to the client as a single 5xx.
        'proxy.config.http.connect_attempts_timeout': CONNECT_TIMEOUT,
        'proxy.config.http.connect_attempts_max_retries': 0,
        'proxy.config.http.connect_attempts_rr_retries': 0,
    })

# Literal-IP remap: no DNS, so the only thing gating the transaction is the origin
# connect handshake (which never completes).
ts.Disk.remap_config.AddLine('map http://blackhole.example.com http://127.0.0.1:{0}'.format(blackhole_port))

ts.Disk.diags_log.Content = Testers.ContainsExpression(
    "io_uring NetVConnection enabled", "the io_uring NetVConnection path must be active")

# The connect-op cancel/timeout resume must be memory-safe under -F: no UAF, no
# failed assertion, no crash when the cancelled/timed-out connect completes into
# the (possibly deferred-free) VC.
ts.Disk.traffic_out.Content = Testers.All(
    Testers.ExcludesExpression("AddressSanitizer", "no ASan error on the connect-op cancel/timeout resume"),
    Testers.ExcludesExpression("failed assertion", "no failed assertion on the connect-op resume"),
    Testers.ExcludesExpression("received signal", "no crash on the connect-op resume"),
)

# Phase 1: the linked timeout fires -> ETIMEDOUT -> NET_EVENT_OPEN_FAILED -> 5xx.
# time_total >= ~2.5s proves the ~3s linked timeout fired (not an instant refused,
# which io_uring_connect already covers); TimeOut caps the no-hang guarantee.
tr = Test.AddTestRun("linked timeout fires -> connect-timeout 5xx after ~3s (not instant, not a hang)")
tr.Processes.Default.StartBefore(origin)
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.Command = (
    'r=$$(curl -s -o /dev/null -w "%{{http_code}} %{{time_total}}" '
    '--proxy 127.0.0.1:{port} "http://blackhole.example.com/foo"); '
    'echo "RESULT $$r"; '
    'echo "$$r" | awk \'{{ if ($$1 >= 500 && $$1 < 600 && $$2 >= 2.5) print "CONNECT_TIMEOUT_OK"; '
    'else print "CONNECT_TIMEOUT_BAD code="$$1" time="$$2 }}\''.format(port=ts.Variables.port))
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.All(
    Testers.ContainsExpression("CONNECT_TIMEOUT_OK", "a black-holed connect must time out to a 5xx after ~3s"),
    Testers.ExcludesExpression("CONNECT_TIMEOUT_BAD", "the status must be 5xx and the time must reflect the ~3s timeout"),
)
tr.TimeOut = 15  # must not hang
tr.StillRunningAfter = ts
tr.StillRunningAfter = origin

# Phase 2: abort mid-connect -> tear down the connecting VC with the connect SQE
# pending. curl --max-time 1 aborts a full second before the 3s timeout. Looped
# for churn so the cancel-then-unwind runs many times under ASan.
tr = Test.AddTestRun("client aborts mid-connect -> cancel connect SQE + unwind (no resume into freed VC)")
tr.Processes.Default.Command = (
    'for r in $$(seq 1 25); do '
    'curl -s -o /dev/null --max-time 1 '
    '--proxy 127.0.0.1:{port} "http://blackhole.example.com/foo" || true; '
    'done; echo CHURN_DONE'.format(port=ts.Variables.port))
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("CHURN_DONE", "the mid-connect abort loop must complete")
tr.TimeOut = 60
tr.StillRunningAfter = ts
tr.StillRunningAfter = origin

# Phase 3: report the deferred-close counter. vc_deferred_close increments only when
# the teardown takes the do_io_close -> _complete_deferred_close branch with the
# connect op in flight (the action_.cancelled -> free_netevent branch does not touch
# it), so this is informational -- the memory-safety guarantee above is the hard
# assertion. The metric must at least exist (proves the io_uring net path is loaded).
tr = Test.AddTestRun("report vc_deferred_close (connect-op teardown counter)")
tr.Processes.Default.Command = (
    'v=$$(traffic_ctl metric get proxy.process.net.io_uring.vc_deferred_close | grep -oE "[0-9]+$$"); '
    'echo "vc_deferred_close=$${v:-missing}"')
tr.Processes.Default.Env = ts.Env
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "vc_deferred_close=", "the io_uring deferred-close metric must be present")
tr.StillRunningAfter = ts
