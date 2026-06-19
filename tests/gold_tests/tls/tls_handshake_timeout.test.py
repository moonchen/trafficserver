'''
Verify that a stalled inbound TLS handshake is timed out (and does not crash ATS).
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
A client that begins a TLS handshake and then stalls must have the handshake
timed out by proxy.config.ssl.handshake_timeout_in, without crashing ATS.
'''

ts = Test.MakeATSProcess("ts", enable_tls=True, enable_cache=False)
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
        'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
        # Time the handshake out after 1s; the client stalls for 3s.
        'proxy.config.ssl.handshake_timeout_in': 1,
        'proxy.config.diags.debug.enabled': 1,
        'proxy.config.diags.debug.tags': 'ssl',
    })

# The stalled handshake must be released by the timeout, not crash the process.
ts.Disk.traffic_out.Content = Testers.ContainsExpression(
    "expired, release the connection", "the stalled handshake must be timed out")
ts.Disk.traffic_out.Content += Testers.ExcludesExpression(
    "received signal|failed assertion", "ATS must not crash timing out the handshake")

tr = Test.AddTestRun("a stalled TLS handshake is timed out")
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.Command = "python3 {0} -p {1} -w 3".format(
    os.path.join(Test.TestDirectory, 'tls_handshake_timeout_client.py'), ts.Variables.ssl_port)
tr.Processes.Default.ReturnCode = 0
tr.StillRunningAfter = ts
