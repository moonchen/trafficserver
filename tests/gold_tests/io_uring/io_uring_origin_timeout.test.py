'''
Origin inactivity timeout while an io_uring recvmsg is in flight (D25): the
timeout closes the origin VC via the inactivity cop / mainEvent (not do_io_close),
so the teardown must defer the free until the in-flight recv drains.
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
With proxy.config.net.io_uring.enabled=1, proxy to an origin that accepts the
connection but never sends a response. ATS arms an io_uring recvmsg for the
origin response; the short server inactivity timeout then closes the origin VC
while that recvmsg is still in flight --- a close driven by the inactivity cop
(mainEvent), not do_io_close. The client must get a 5xx (504) and, run against
the ASan build, the teardown must be memory-safe (no UAF when the cancelled recv
completes into the VC).
'''

Test.ContinueOnFail = True

# An origin that accepts and then hangs (never responds). Reserve its port via a
# Python listener the test owns.
hang_server = '''
import socket, sys, time
ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
ls.bind(("127.0.0.1", int(sys.argv[1])))
ls.listen(128)
print("hang server ready", flush=True)
conns = []
while True:
    c, _ = ls.accept()
    conns.append(c)  # keep it open, never respond
'''

ts = Test.MakeATSProcess("ts")
ts.Command += " -F"  # disable the ProxyAllocator freelist so ASan sees VC frees (teardown UAF guard)

# Reserve a port for the hang origin.
hang_port = ts.Variables.get("hang_port", None)
import socket as _socket

_s = _socket.socket()
_s.bind(("127.0.0.1", 0))
hang_port = _s.getsockname()[1]
_s.close()

server = Test.Processes.Process("hang-server", "python3 -c '{0}' {1}".format(hang_server, hang_port))
server.Ready = When.PortOpen(hang_port)

ts.Disk.records_config.update(
    {
        'proxy.config.net.io_uring.enabled': 1,
        # Short origin (server) inactivity timeout so the armed origin read times
        # out quickly while the recvmsg is in flight.
        'proxy.config.http.transaction_no_activity_timeout_out': 2,
        'proxy.config.http.connect_attempts_max_retries': 0,
    })

ts.Disk.remap_config.AddLine('map http://www.example.com http://127.0.0.1:{0}'.format(hang_port))

ts.Disk.diags_log.Content = Testers.ContainsExpression(
    "io_uring NetVConnection enabled", "the io_uring NetVConnection path must be active")

tr = Test.AddTestRun("origin hangs -> inactivity timeout closes with the recv in flight")
tr.MakeCurlCommand(
    '-s -o /dev/null -w "%{{http_code}}" --proxy 127.0.0.1:{0} "http://www.example.com/x"'.format(ts.Variables.port), ts=ts)
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("50", "a hung origin must time out to a 5xx")
tr.TimeOut = 20
tr.StillRunningAfter = ts
