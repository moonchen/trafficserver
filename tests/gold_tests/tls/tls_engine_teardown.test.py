'''
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

Test.Summary = '''
Tear down a TLS connection while the async engine has the handshake suspended
(SSL_ERROR_WANT_ASYNC). The async engine delays the server private-key op ~2s; a
client that gives up after 1s drops the connection while the SSLNetVConnection is
parked on the async wait fd. Exercises the teardown-while-parked path -- the async
epoll registration must be cleaned up without a use-after-free. Best run under ASAN.
'''

Test.SkipUnless(
    Condition.HasOpenSSLVersion('1.1.1'),
    Condition.IsOpenSSL(),
)

# Define default ATS
ts = Test.MakeATSProcess("ts", enable_tls=True)
server = Test.MakeOriginServer("server")

ts.Setup.Copy(os.path.join(Test.Variables.AtsTestPluginsDir, 'async_engine.so'), Test.RunDirectory)

server.addResponse(
    "sessionlog.json", {
        "headers": "GET / HTTP/1.1\r\nuuid: basic\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": ""
    }, {
        "headers":
            "HTTP/1.1 200 OK\r\nServer: microserver\r\nConnection: close\r\nCache-Control: max-age=3600\r\nContent-Length: 2\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": "ok"
    })

ts.addSSLfile("ssl/server.pem")
ts.addSSLfile("ssl/server.key")

ts.Disk.remap_config.AddLine('map / http://127.0.0.1:{0}'.format(server.Variables.Port))

ts.Disk.ssl_multicert_yaml.AddLines(
    """
ssl_multicert:
  - dest_ip: "*"
    ssl_cert_name: server.pem
    ssl_key_name: server.key
""".split("\n"))
ts.Disk.records_config.update(
    {
        'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.exec_thread.autoconfig.scale': 1.0,
        'proxy.config.ssl.engine.conf_file': '{0}/ts/config/load_engine.cnf'.format(Test.RunDirectory),
        'proxy.config.ssl.async.handshake.enabled': 1,
        'proxy.config.diags.debug.enabled': 0,
        'proxy.config.diags.debug.tags': 'ssl|http'
    })

ts.Disk.MakeConfigFile('load_engine.cnf').AddLines(
    [
        'openssl_conf = openssl_init',
        '',
        '[openssl_init]',
        '',
        'engines = engine_section',
        '',
        '[engine_section]',
        '',
        'async = async_section',
        '',
        '[async_section]',
        '',
        'dynamic_path = {0}/async_engine.so'.format(Test.RunDirectory),
        '',
        'engine_id = async-test',
        '',
        'default_algorithms = RSA',
        '',
        'init = 1',
    ])

# Run 1: drop the connection mid-async-handshake. The engine delays the server
# private-key op ~2s; --max-time 1 makes curl give up (exit 28) while ATS is still
# parked in SSL_WAIT_FOR_ASYNC, tearing the VC down with the async wait fd registered.
tr = Test.AddTestRun("Abort during async handshake")
tr.MakeCurlCommand("-k -v --max-time 1 -H host:example.com https://127.0.0.1:{0}/".format(ts.Variables.ssl_port), ts=ts)
tr.Processes.Default.ReturnCode = 28  # CURLE_OPERATION_TIMEDOUT
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(Test.Processes.ts, ready=When.PortOpen(ts.Variables.ssl_port))
tr.StillRunningAfter = ts
tr.StillRunningAfter = server

# Run 2: a full async handshake must still succeed -- proves ATS survived the
# teardown-while-parked above and the async path is still healthy.
tr = Test.AddTestRun("Async handshake still works after the abort")
tr.MakeCurlCommand("-k -v -H host:example.com https://127.0.0.1:{0}/".format(ts.Variables.ssl_port), ts=ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.All = Testers.ContainsExpression(r"HTTP/(2|1\.1) 200", "Request succeeds after the parked teardown")
tr.StillRunningAfter = ts
tr.StillRunningAfter = server

# The async engine must have actually suspended a handshake, and ATS must not have
# tripped a sanitizer during the teardown-while-parked.
ts.Disk.traffic_out.Content += Testers.ContainsExpression("Send signal to ", "The Async engine triggers")
ts.Disk.traffic_out.Content += Testers.ExcludesExpression(
    "ERROR: AddressSanitizer", "No ASan error (e.g. use-after-free) during teardown-while-parked")
