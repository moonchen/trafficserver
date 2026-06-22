'''
Outbound connect through IOUringNetVConnection: success and refused.
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
With proxy.config.net.io_uring.enabled=1, exercise the outbound (origin) connect
through IOUringNetVConnection. The VC keeps the inherited optimistic non-blocking
connect; io_uring's first recv/send transparently waits for the TCP handshake to
complete (the fd is not in epoll). A refused origin connect must surface as a 5xx
to the client (async VC_EVENT_ERROR, matching the epoll path) --- not a hang.
'''

Test.ContinueOnFail = True

ts = Test.MakeATSProcess("ts")
server = Test.MakeOriginServer("server")
# A second origin we deliberately never start, to reserve a port with no listener.
dead = Test.MakeOriginServer("dead")

request_header = {"headers": "GET /foo HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
response_header = {
    "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 3\r\n\r\n",
    "timestamp": "1469733493.993",
    "body": "abc"
}
server.addResponse("sessionfile.log", request_header, response_header)

ts.Disk.records_config.update({
    'proxy.config.net.io_uring.enabled': 1,
    'proxy.config.http.connect_attempts_max_retries': 0,
})

ts.Disk.remap_config.AddLine('map http://www.example.com http://127.0.0.1:{0}'.format(server.Variables.Port))
ts.Disk.remap_config.AddLine('map http://refused.example.com http://127.0.0.1:{0}'.format(dead.Variables.Port))

ts.Disk.diags_log.Content = Testers.ContainsExpression(
    "io_uring NetVConnection enabled", "the io_uring NetVConnection path must be active")

# Success: a normal proxied transaction completes through the io_uring connect.
tr = Test.AddTestRun("outbound connect succeeds through the io_uring VC")
tr.MakeCurlCommand('-s -o - --proxy 127.0.0.1:{0} "http://www.example.com/foo"'.format(ts.Variables.port), ts=ts)
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("abc", "origin body proxied back")
tr.StillRunningAfter = ts
tr.StillRunningAfter = server

# Refused: the origin port has no listener, so the connect is refused. It must
# come back as a 5xx promptly (not hang); 'dead' is never started.
tr = Test.AddTestRun("refused outbound connect surfaces as 5xx, not a hang")
tr.MakeCurlCommand(
    '-s -o /dev/null -w "%{{http_code}}" --proxy 127.0.0.1:{0} "http://refused.example.com/foo"'.format(ts.Variables.port), ts=ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("50", "a refused origin connect must yield a 5xx")
tr.TimeOut = 10  # must not hang
tr.StillRunningAfter = ts
