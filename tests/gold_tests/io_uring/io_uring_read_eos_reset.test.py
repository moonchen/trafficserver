'''
Abrupt origin close on the io_uring read path: graceful EOS (r==0) vs reset
(-ECONNRESET), on BOTH read paths (single-shot _read and provided-buffer
_read_provided).
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
With proxy.config.net.io_uring.enabled=1, an origin abruptly ends a response two
ways while ATS is reading it over io_uring:

  (a) truncated Content-Length: a 200 promises 1000 body bytes but the origin
      writes ~100 then a clean FIN (shutdown(SHUT_WR)). The in-flight recv
      completes r==0 -> the read coroutine takes the VC_EVENT_EOS arm with the
      VIO's Content-Length unsatisfied (the r==0/-ECONNRESET EOS branch shared
      by both _read and _read_provided).

  (b) reset: the origin sends full headers + a few body bytes, then close()s a
      socket with SO_LINGER{onoff=1,linger=0} so the kernel emits an RST. The
      in-flight recv completes with -ECONNRESET, which the read coroutine must
      treat as EOS (same arm) --- NOT route to _readSignalError.

Both arms must be memory-safe under abrupt teardown: run against the ASan build
with the ProxyAllocator freelist disabled (-F) so any use-after-free on the VC
teardown is caught. In both cases the client must get a truncated/failed transfer
promptly (short body, nonzero curl exit), ATS must never deliver the full 1000
promised bytes, must never hang, and must still be running afterward.

Parametrized over proxy.config.net.io_uring.read_provided_buffers 0 (single-shot
recvmsg into the VIO buffer) and 1 (kernel provided-buffer ring) so BOTH read
paths' r<=0 EOS arms are exercised.
'''

Test.SkipUnless(Condition.HasATSFeature('TS_USE_LINUX_IO_URING'))

Test.ContinueOnFail = True

# --- Inline origins the test owns (io_uring_origin_timeout listener style). ---

# (a) Promises Content-Length: 1000 but delivers only 100 bytes then a clean FIN.
# Drains the proxied request first so close() is an orderly FIN (r==0 at ATS), not
# an RST from unread data.
trunc_server = '''
import socket, sys
port = int(sys.argv[1])
ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", port))
ls.listen(128)
print("trunc server ready", flush=True)
while True:
    c, _ = ls.accept()
    c.settimeout(5)
    try:
        c.recv(65536)  # drain the request so the close below is a clean FIN
    except Exception:
        pass
    c.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 1000\\r\\nConnection: close\\r\\n\\r\\n" + b"X" * 100)
    try:
        c.shutdown(socket.SHUT_WR)  # FIN after 100 of the promised 1000 bytes
        c.recv(65536)               # wait for the peer to close, then release
    except Exception:
        pass
    c.close()
'''

# (b) Sends full headers + a few body bytes, then aborts with an RST via
# SO_LINGER{1,0}. A short sleep lets ATS consume the partial bytes and re-arm its
# recv, so the RST lands on an in-flight recv (-ECONNRESET) rather than being seen
# as a plain FIN.
rst_server = '''
import socket, struct, sys, time
port = int(sys.argv[1])
ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", port))
ls.listen(128)
print("rst server ready", flush=True)
while True:
    c, _ = ls.accept()
    c.settimeout(5)
    try:
        c.recv(65536)  # drain the request
    except Exception:
        pass
    c.sendall(b"HTTP/1.1 200 OK\\r\\nContent-Length: 1000\\r\\nConnection: close\\r\\n\\r\\nYYYY")
    time.sleep(0.3)  # let ATS read the partial bytes + re-arm recv before the RST
    c.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    c.close()  # SO_LINGER{1,0} -> RST, so the in-flight recv completes -ECONNRESET
'''

# Reserve origin ports from autest's coordinated port queue (the same queue ATS
# listen ports come from) so the inline origins can never squat on a port autest
# has earmarked for an ATS process. A naive bind-to-0 grabs ephemeral ports out of
# the same range autest uses for ATS, which deterministically collides here (two
# ATS processes) -> "Could not bind ... Address already in use" at ATS startup.
from ports import get_port

trunc_port = get_port(Test, "trunc_port")
rst_port = get_port(Test, "rst_port")

trunc = Test.Processes.Process("trunc-server", "python3 -c '{0}' {1}".format(trunc_server, trunc_port))
trunc.Ready = When.PortOpen(trunc_port)
rst = Test.Processes.Process("rst-server", "python3 -c '{0}' {1}".format(rst_server, rst_port))
rst.Ready = When.PortOpen(rst_port)

# One ATS process per read path so both the single-shot and provided-buffer r<=0
# EOS arms are covered.
started_origins = False
for label, provided in [("single-shot", 0), ("provided", 1)]:
    ts = Test.MakeATSProcess("ts-{0}".format(label))
    ts.Command += " -F"  # disable the ProxyAllocator freelist so ASan sees VC frees (teardown UAF guard)

    ts.Disk.records_config.update(
        {
            'proxy.config.net.io_uring.enabled': 1,
            'proxy.config.net.io_uring.read_provided_buffers': provided,
            # No origin retries: a truncated/aborted 200 is a complete response header,
            # so ATS proxies it once and hits EOS --- keep the failure prompt.
            'proxy.config.http.connect_attempts_max_retries': 0,
            # Bound any pathological stall so a hang can't masquerade as success.
            'proxy.config.http.transaction_no_activity_timeout_out': 5,
        })

    ts.Disk.remap_config.AddLine('map http://trunc.example.com http://127.0.0.1:{0}'.format(trunc_port))
    ts.Disk.remap_config.AddLine('map http://rst.example.com http://127.0.0.1:{0}'.format(rst_port))

    ts.Disk.diags_log.Content = Testers.ContainsExpression(
        "io_uring NetVConnection enabled", "the io_uring NetVConnection path must be active")

    # --- (a) truncated Content-Length: graceful EOS (r==0) with CL unsatisfied. ---
    tr = Test.AddTestRun("[{0}] truncated CL: origin FINs after 100 of 1000 bytes -> EOS".format(label))
    tr.Processes.Default.Command = (
        'curl -s -o /dev/null --max-time 10 '
        '-w "CODE=%{{http_code}} SIZE=%{{size_download}}\\n" '
        '--proxy 127.0.0.1:{port} "http://trunc.example.com/x"; echo "EXIT=$$?"'.format(port=ts.Variables.port))
    if not started_origins:
        tr.Processes.Default.StartBefore(trunc)
        tr.Processes.Default.StartBefore(rst)
        started_origins = True
    tr.Processes.Default.StartBefore(ts)
    tr.Processes.Default.ReturnCode = 0
    tr.Processes.Default.Streams.stdout = Testers.All(
        Testers.ContainsExpression("CODE=200", "ATS forwards the origin 200 header before the truncation"),
        Testers.ContainsExpression(r"SIZE=100\b", "only the 100 delivered bytes reach the client"),
        Testers.ExcludesExpression("SIZE=1000", "ATS must never deliver the full promised 1000 bytes"),
        Testers.ContainsExpression(r"EXIT=[1-9]", "curl must report a failed/truncated transfer (nonzero exit)"),
    )
    tr.TimeOut = 20  # must not hang
    tr.StillRunningAfter = ts

    # --- (b) reset: in-flight recv completes -ECONNRESET, treated as EOS. ---
    tr = Test.AddTestRun("[{0}] reset: origin RSTs mid-body -> -ECONNRESET treated as EOS".format(label))
    tr.Processes.Default.Command = (
        'curl -s -o /dev/null --max-time 10 '
        '-w "CODE=%{{http_code}} SIZE=%{{size_download}}\\n" '
        '--proxy 127.0.0.1:{port} "http://rst.example.com/x"; echo "EXIT=$$?"'.format(port=ts.Variables.port))
    tr.Processes.Default.ReturnCode = 0
    tr.Processes.Default.Streams.stdout = Testers.All(
        Testers.ExcludesExpression("SIZE=1000", "ATS must never deliver the full promised 1000 bytes"),
        Testers.ContainsExpression(r"EXIT=[1-9]", "the abrupt RST must surface as a prompt curl error (nonzero exit)"),
    )
    tr.TimeOut = 20  # must not hang
    tr.StillRunningAfter = ts
