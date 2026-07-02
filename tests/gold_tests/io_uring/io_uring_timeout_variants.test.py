'''
Timeout-driven teardown with an io_uring recv in flight, via free_thread (not
do_io_close). Two variants distinct from io_uring_origin_timeout (outbound
INACTIVITY): (a) an outbound ACTIVE timeout while an origin-body recv is armed,
and (b) an inbound INACTIVITY timeout while a request recv is armed. Both close
the VC through NetHandler::free_netevent -> free_thread, which must defer the
free until the cancelled recv completes (a UAF otherwise; ASan is blind to it
without -F because VCs go to a ClassAllocator freelist). Run over both read
paths (single-shot and provided-buffer).
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
ASan sees VC frees), drive two timeout-teardowns that reach free_thread with an
io_uring recv in flight:
  (a) outbound ACTIVE timeout: a trickle origin makes steady progress (inactivity
      never fires) but the transaction exceeds transaction_active_timeout_out=3
      while a recvmsg is armed for more origin body -> active timeout closes the
      origin VC with the recv in flight; the client gets a truncated 200 near t=3s.
  (b) inbound INACTIVITY timeout: a raw client connects, sends a partial request
      (recv armed for the rest), and idles past transaction_no_activity_timeout_in=2
      -> the inbound inactivity timeout closes the client VC with that recv in
      flight; the client observes an ATS-initiated close within the idle window.
Both variants run over the single-shot read path (read_provided_buffers=0) and
the default provided-buffer path (read_provided_buffers=1). The teardown must be
memory-safe (no UAF/assert/crash) on both.
'''

Test.SkipUnless(Condition.HasATSFeature('TS_USE_LINUX_IO_URING'))

Test.ContinueOnFail = True

ORIGIN_SCRIPT = os.path.join(Test.TestDirectory, "io_uring_timeout_variants_origin.py")
IDLE_CLIENT = os.path.join(Test.TestDirectory, "io_uring_timeout_variants_idle_client.py")

# Reserve a port for the trickle origin the test owns.
_s = _socket.socket()
_s.bind(("127.0.0.1", 0))
origin_port = _s.getsockname()[1]
_s.close()

origin = Test.Processes.Process("trickle-origin", "{0} {1} {2}".format(sys.executable, ORIGIN_SCRIPT, origin_port))
origin.Ready = When.PortOpen(origin_port)

ACTIVE_TIMEOUT_OUT = 3
NO_ACTIVITY_TIMEOUT_IN = 2

# Two ATS processes: one per read path (single-shot vs provided-buffer). Both
# variants (a) and (b) are exercised against each.
for idx, rpb in enumerate([0, 1]):
    path_name = "single-shot" if rpb == 0 else "provided-buffer"
    ts = Test.MakeATSProcess("ts{0}".format(idx))
    ts.Command += " -F"  # freelist off so ASan surfaces any teardown UAF

    ts.Disk.records_config.update(
        {
            'proxy.config.net.io_uring.enabled': 1,
            'proxy.config.net.io_uring.read_provided_buffers': rpb,
            # (a) cap the outbound transaction total time; keep the outbound
            # inactivity timeout well above it so ACTIVE (not inactivity) fires
            # even though the trickle origin keeps making progress.
            'proxy.config.http.transaction_active_timeout_out': ACTIVE_TIMEOUT_OUT,
            'proxy.config.http.transaction_no_activity_timeout_out': 30,
            # (b) short inbound inactivity timeout for the idle-client close.
            'proxy.config.http.transaction_no_activity_timeout_in': NO_ACTIVITY_TIMEOUT_IN,
            'proxy.config.http.connect_attempts_max_retries': 0,
        })

    ts.Disk.remap_config.AddLine('map http://www.example.com http://127.0.0.1:{0}'.format(origin_port))

    ts.Disk.diags_log.Content = Testers.ContainsExpression(
        "io_uring NetVConnection enabled", "the io_uring NetVConnection path must be active")

    # Teardown must be memory-safe under -F: no UAF, assertion, or crash when the
    # cancelled recv completes into the deferred-free VC.
    ts.Disk.traffic_out.Content = Testers.All(
        Testers.ExcludesExpression("AddressSanitizer", "no ASan error during timeout teardown"),
        Testers.ExcludesExpression("failed assertion", "no failed assertion during timeout teardown"),
        Testers.ExcludesExpression("received signal", "no crash during timeout teardown"),
    )

    # Variant (a): outbound ACTIVE timeout with an origin-body recv in flight.
    tr = Test.AddTestRun("[{0}] (a) outbound active timeout closes with recv in flight".format(path_name))
    if idx == 0:
        tr.Processes.Default.StartBefore(origin)
    tr.Processes.Default.StartBefore(ts)
    tr.MakeCurlCommand(
        '-s -o /dev/null -w "code=%{{http_code}} time=%{{time_total}}\\n" '
        '--proxy 127.0.0.1:{0} "http://www.example.com/a"'.format(ts.Variables.port),
        ts=ts)
    # Truncated body vs the advertised Content-Length -> curl exit 18 (partial).
    tr.Processes.Default.ReturnCode = 18
    tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
        "code=200", "the client must get the 200 headers before the active timeout truncates the body")
    # Finishing well under the 30s outbound inactivity timeout proves the ~3s
    # ACTIVE cap (not inactivity) is what fired.
    tr.TimeOut = 12
    tr.StillRunningAfter = ts
    tr.StillRunningAfter = origin

    # Variant (b): inbound INACTIVITY timeout with a request recv in flight.
    tr = Test.AddTestRun("[{0}] (b) inbound inactivity timeout closes with recv in flight".format(path_name))
    tr.Processes.Default.Command = "{0} {1} 127.0.0.1 {2}".format(sys.executable, IDLE_CLIENT, ts.Variables.port)
    tr.Processes.Default.ReturnCode = 0
    tr.Processes.Default.Streams.stdout = Testers.All(
        Testers.ContainsExpression("elapsed=", "the client must observe an ATS-initiated close"),
        Testers.ExcludesExpression("NO_CLOSE", "ATS must close the idle inbound connection within the window"),
    )
    # Finishing well under the 30s default proves the ~2s inbound inactivity fired.
    tr.TimeOut = 15
    tr.StillRunningAfter = ts
