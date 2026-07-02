'''
Plain HTTP through IOUringNetVConnection (proxy.config.net.io_uring.enabled=1).
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
Plain HTTP proxied through IOUringNetVConnection, selected by
proxy.config.net.io_uring.enabled. While IOUringNetVConnection is a behavioral
clone of UnixNetVConnection this passes identically to the default net path; it
is the regression guard for swapping the read/write path to io_uring.
'''

Test.SkipUnless(Condition.HasATSFeature('TS_USE_LINUX_IO_URING'))

Test.ContinueOnFail = True

ts = Test.MakeATSProcess("ts")
server = Test.MakeOriginServer("server")

request_header = {"headers": "GET /foo HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
response_header = {
    "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 14\r\n\r\n",
    "timestamp": "1469733493.993",
    "body": "hello-io-uring"
}
server.addResponse("sessionfile.log", request_header, response_header)

ts.Disk.records_config.update({
    'proxy.config.net.io_uring.enabled': 1,
})

ts.Disk.remap_config.AddLine('map http://www.example.com http://127.0.0.1:{0}'.format(server.Variables.Port))

# Prove the gate actually engaged the io_uring VConnection rather than silently
# falling back to UnixNetVConnection (which would pass this test for the wrong
# reason). UnixNetProcessor::allocate_vc emits this once when the flag is read.
ts.Disk.diags_log.Content = Testers.All(
    Testers.ContainsExpression("io_uring NetVConnection enabled", "the io_uring NetVConnection path must be active"),
    Testers.ContainsExpression("io_uring accept enabled", "the io_uring accept path must be active"))

# A full proxied transaction exercises the inbound (client-facing) VC read of the
# request and the outbound (origin-facing) VC read of the response body, both of
# which the io_uring.enabled gate routes through IOUringNetVConnection.
tr = Test.AddTestRun("plain HTTP GET with a body through the io_uring VC")
tr.MakeCurlCommand('--proxy 127.0.0.1:{0} "http://www.example.com/foo" --verbose'.format(ts.Variables.port), ts=ts)
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("hello-io-uring", "the origin body must be proxied back intact")
tr.StillRunningAfter = ts
tr.StillRunningAfter = server
