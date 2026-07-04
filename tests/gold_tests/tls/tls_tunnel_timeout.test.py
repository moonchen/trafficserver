'''
Verify that an idle TLS blind tunnel is timed out and the timeout is relayed
through TunnelNetVConnection (the raw byte-forwarding VC) without crashing ATS.
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
An established but idle SNI blind tunnel (tunnel_route) must be torn down by the
inactivity timeout, with the timeout relayed through TunnelNetVConnection.
'''

ts = Test.MakeATSProcess("ts", enable_tls=True, enable_cache=False)
ts.addDefaultSSLFiles()

# A TLS origin: the blind tunnel forwards the client's raw TLS bytes here.
origin = Test.MakeOriginServer("origin", ssl=True)

ts.Disk.ssl_multicert_yaml.AddLines(
    """
ssl_multicert:
  - dest_ip: "*"
    ssl_cert_name: server.pem
    ssl_key_name: server.key
""".split("\n"))

# tunnel.test is blind-tunnelled (not terminated) straight to the TLS origin.
ts.Disk.sni_yaml.AddLines([
    "sni:",
    "- fqdn: tunnel.test",
    "  tunnel_route: 127.0.0.1:{0}".format(origin.Variables.SSL_Port),
])

ts.Disk.records_config.update(
    {
        'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
        # Make the INBOUND side time out first so its transport fires the
        # timeout into TunnelNetVConnection (the outbound is kept long so it
        # does not preempt by tearing the whole tunnel down from HttpSM).
        'proxy.config.http.transaction_no_activity_timeout_in': 3,
        'proxy.config.http.transaction_no_activity_timeout_out': 30,
        'proxy.config.net.default_inactivity_timeout': 30,
        'proxy.config.diags.debug.enabled': 1,
        'proxy.config.diags.debug.tags': 'ssl_tunnel',
    })

# The inactivity timeout (VC_EVENT_INACTIVITY_TIMEOUT == 105) must reach
# TunnelNetVConnection::mainEvent, which logs "transport event 105" before the
# switch and then relays it via the timeout arm.
ts.Disk.traffic_out.Content = Testers.ContainsExpression(
    "transport event 105", "the idle-tunnel timeout must be relayed through TunnelNetVConnection")
ts.Disk.traffic_out.Content += Testers.ExcludesExpression(
    "received signal|failed assertion", "ATS must not crash tearing down the idle tunnel")

tr = Test.AddTestRun("an idle blind tunnel is timed out")
tr.Processes.Default.StartBefore(origin)
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.Command = "python3 {0} -p {1} -s tunnel.test -w 15".format(
    os.path.join(Test.TestDirectory, 'tls_tunnel_timeout_client.py'), ts.Variables.ssl_port)
tr.Processes.Default.ReturnCode = 0
tr.StillRunningAfter = ts
