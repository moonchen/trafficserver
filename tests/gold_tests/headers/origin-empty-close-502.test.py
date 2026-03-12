'''
Test that ATS returns a proper 502 when the origin accepts
the TCP connection but closes it without sending any response bytes.

This exercises a bug where http_parser_parse_resp returned DONE instead
of ERROR on an empty EOF, causing the error to be misclassified as
"Malformed Server Response Status" instead of a connection failure.
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
Test 502 response when origin closes connection without sending data
'''

ts = Test.MakeATSProcess("ts")

HOST = 'www.origin-empty-close.test'

# Use a helper script as the origin that accepts and immediately closes.
Test.Setup.Copy(os.path.join(Test.Variables.AtsTestToolsDir, 'tcp_client.py'))
Test.Setup.Copy('empty_close_server.py')

# We need a port for the fake origin. Use MakeOriginServer just to reserve one.
server = Test.MakeOriginServer("server", ssl=False)

ts.Disk.remap_config.AddLine(f'map http://{HOST} http://127.0.0.1:{server.Variables.Port}')

# Disable retries so we get the 502 on the first attempt.
ts.Disk.records_config.update(
    {
        'proxy.config.http.connect_attempts_max_retries': 0,
        'proxy.config.http.connect_attempts_max_retries_down_server': 0,
    })

data_file = Test.Disk.File("request.txt", id="datafile")
data_file.WriteOn(f"GET / HTTP/1.1\r\nHost: {HOST}\r\n\r\n")

tr = Test.AddTestRun("Origin accepts then closes — expect 502")
# Start the empty-close server instead of the real origin server.
empty_server = tr.Processes.Process("empty_server")
empty_server.Command = f"{sys.executable} empty_close_server.py {server.Variables.Port}"
empty_server.Ready = When.PortOpen(server.Variables.Port)

tr.Processes.Default.StartBefore(Test.Processes.ts)
tr.Processes.Default.StartBefore(empty_server)
tr.Processes.Default.Command = \
    (f"{sys.executable} tcp_client.py 127.0.0.1 {ts.Variables.port} request.txt | "
     r"sed -e '/^Date: /d' -e '/^Server: ATS\//d'")
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("HTTP/1.1 502", "Should receive a 502 response")
# The reason should indicate a connection failure, not a malformed response.
tr.Processes.Default.Streams.stdout += Testers.ExcludesExpression(
    "Malformed Server Response Status", "Should not be classified as a malformed response")
