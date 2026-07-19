'''
Repro for TLS-refactor finding #3: a fully-idle partial TLS handshake does not
honor proxy.config.ssl.handshake_timeout_in (the timer install in
sslStartHandShake is dead code because _track_first_handshake pre-records the
begin timestamp).
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

Test.Summary = 'Idle partial TLS handshake should hit proxy.config.ssl.handshake_timeout_in'

ts = Test.MakeATSProcess("ts", enable_tls=True)
ts.addSSLfile("ssl/server.pem")
ts.addSSLfile("ssl/server.key")

# Short handshake timeout, everything else long, so only the handshake timer
# can close a stalled handshake within a few seconds.
ts.Disk.records_config.update(
    {
        'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.ssl.handshake_timeout_in': 3,
        'proxy.config.net.default_inactivity_timeout': 20,
        'proxy.config.http.accept_no_activity_timeout': 20,
        'proxy.config.http.transaction_no_activity_timeout_in': 20,
        'proxy.config.net.defer_accept': 0,
    })

ts.Disk.ssl_multicert_yaml.AddLines(
    """
ssl_multicert:
  - dest_ip: "*"
    ssl_cert_name: server.pem
    ssl_key_name: server.key
""".split("\n"))

tr = Test.AddTestRun("idle partial handshake")
tr.Setup.Copy("tls_handshake_idle_client.py")
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.Command = 'python3 tls_handshake_idle_client.py {0} 3'.format(ts.Variables.ssl_port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "HANDSHAKE_TIMEOUT_FIRED", "idle partial handshake closed within the configured handshake timeout")
tr.TimeOut = 60
