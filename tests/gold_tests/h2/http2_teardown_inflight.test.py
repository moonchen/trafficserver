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

import sys

Test.Summary = '''
Tear down an HTTP/2 client session while a stream is still awaiting a slow
origin response. Guards the session teardown path (Http2ClientSession
do_io_close/destroy, which drops the cached connection write VIO) against
use-after-free / crash regressions.
'''

# Slow origin for the in-flight aborts: every response is delayed so a client
# abort lands while the proxy still has the stream outstanding to origin.
slow_origin = Test.MakeOriginServer("slow_origin", delay=3)
slow_origin.addResponse(
    "sessionlog.json", {
        "headers": "GET /slow HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nServer: microserver\r\nConnection: close\r\nContent-Length: 4\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": "body"
    })

# Separate fast origin for the post-storm health check, so it cannot be starved
# by the slow origin's outstanding (aborted) transactions.
fast_origin = Test.MakeOriginServer("fast_origin")
fast_origin.addResponse(
    "sessionlog.json", {
        "headers": "GET /ok HTTP/1.1\r\nHost: www.example.com\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": ""
    }, {
        "headers": "HTTP/1.1 200 OK\r\nServer: microserver\r\nConnection: close\r\nContent-Length: 2\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": "ok"
    })

ts = Test.MakeATSProcess('ts', select_ports=True, enable_tls=True)
ts.addDefaultSSLFiles()
ts.Disk.ssl_multicert_yaml.AddLines(
    """
ssl_multicert:
  - dest_ip: "*"
    ssl_cert_name: server.pem
    ssl_key_name: server.key
""".split("\n"))
ts.Disk.records_config.update(
    {
        "proxy.config.http.server_ports": f"{ts.Variables.port} {ts.Variables.ssl_port}:ssl",
        'proxy.config.ssl.server.cert.path': f'{ts.Variables.SSLDir}',
        'proxy.config.ssl.server.private_key.path': f'{ts.Variables.SSLDir}',
        'proxy.config.ssl.client.verify.server.policy': 'PERMISSIVE',
        'proxy.config.ssl.client.alpn_protocols': 'h2,http/1.1',
        'proxy.config.diags.debug.enabled': 0,
    })
ts.Disk.remap_config.AddLines(
    [
        f'map /slow http://127.0.0.1:{slow_origin.Variables.Port}/slow',
        f'map /ok http://127.0.0.1:{fast_origin.Variables.Port}/ok',
    ])

ts.Setup.CopyAs('h2_inflight_teardown_client.py', Test.RunDirectory)

# Storm of aborted in-flight requests: each one forces a client-session teardown
# while the stream is still waiting on the slow origin.
tr = Test.AddTestRun("abort in-flight h2 requests")
tr.Processes.Default.StartBefore(slow_origin)
tr.Processes.Default.StartBefore(fast_origin)
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.Command = (
    f'{sys.executable} h2_inflight_teardown_client.py {ts.Variables.ssl_port} /slow abort --iterations 15 --wait 0.3')
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.All += Testers.ContainsExpression('aborted connection 15/15', 'all aborts issued')

# The proxy must still be alive and serving after the abort storm.
tr = Test.AddTestRun("proxy still serves after teardown storm")
tr.Processes.Default.Command = f'{sys.executable} h2_inflight_teardown_client.py {ts.Variables.ssl_port} /ok complete'
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.All += Testers.ContainsExpression('status=200', 'proxy still serving')

# No crash (ATS prints its own stack trace on signal; ASAN/UAF surfaces here too).
ts.Disk.traffic_out.Content = Testers.ExcludesExpression('received signal', 'ATS must not crash during teardown')
ts.Disk.traffic_out.Content += Testers.ExcludesExpression('use-after-free', 'no ASAN use-after-free')
