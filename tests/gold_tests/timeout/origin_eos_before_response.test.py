'''
Test ATS behavior when the origin accepts the connection, reads the request,
and closes without sending any response bytes.
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

Test.Summary = 'Origin closes without sending a response header'

ts = Test.MakeATSProcess("ts")

HOST = 'www.origin-eos-before-response.test'
Test.GetTcpPort("origin_port")

ts.Disk.records_config.update(
    {
        'proxy.config.url_remap.remap_required': 1,
        'proxy.config.http.connect_attempts_max_retries': 0,
        'proxy.config.diags.debug.enabled': 0,
        'proxy.config.diags.debug.tags': 'http',
    })

ts.Disk.remap_config.AddLine('map http://{host} http://127.0.0.1:{port}'.format(host=HOST, port=Test.Variables.origin_port))

origin_close = Test.Processes.Process(
    "origin-close-without-response",
    f"{sys.executable} close_no_response_server.py {Test.Variables.origin_port}",
)
origin_close.ReturnCode = 0
origin_close.Streams.All = Testers.ContainsExpression("CLOSED WITHOUT RESPONSE", "Origin helper should close cleanly")
origin_close.Streams.All += Testers.ContainsExpression("READ ", "Origin helper should read the request before closing")

Test.Setup.Copy("close_no_response_server.py")
Test.Setup.Copy(os.path.join(Test.Variables.AtsTestToolsDir, 'tcp_client.py'))

data_file = Test.Disk.File(f"{HOST}-get.txt", id="origin_eos_request")
data_file.WriteOn("GET / HTTP/1.1\r\nHost: {host}\r\n\r\n".format(host=HOST))

tr = Test.AddTestRun()
tr.Processes.Default.StartBefore(Test.Processes.ts)
tr.Processes.Default.StartBefore(origin_close, ready=When.PortOpen(Test.Variables.origin_port))
tr.Processes.Default.Command = (
    f"{sys.executable} tcp_client.py 127.0.0.1 {ts.Variables.port} {data_file.Name} | "
    r"sed -e '/^Date: /d' -e '/^Server: ATS\//d'")
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "HTTP/1.1 502 Server Hangup", "Should classify empty origin EOS as a hangup")
tr.Processes.Default.Streams.stdout += Testers.ContainsExpression(
    "Server Connection Closed", "Should serve the connect#hangup body")
tr.Processes.Default.Streams.stdout += Testers.ExcludesExpression(
    "Malformed Server Response Status", "Should not report a malformed response status")
tr.StillRunningAfter = Test.Processes.ts
