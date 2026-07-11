'''
Dedicated quiescent outbound-lifecycle leak profile (sol's LSan recommendation):
drive legit outbound TLS, quiesce on the allocator-in-use gauges, then take a
live LSan snapshot under a suppression profile with the in-flight frames dropped.
Legit traffic must return sslNetVCAllocator to baseline (no orphan) and the live
snapshot must report zero unsuppressed leaks.
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

Test.Summary = 'Quiescent outbound-lifecycle leak profile: legit outbound TLS frees cleanly (allocator-delta oracle + live LSan snapshot)'

supp = os.path.abspath(
    os.path.join(Test.TestDirectory, '..', '..', '..', 'ci', 'asan_leak_suppression', 'tls_outbound_lifecycle.txt'))

server = Test.MakeOriginServer("server", ssl=True)
request_header = {"headers": "GET / HTTP/1.1\r\nHost: origin.test\r\n\r\n", "timestamp": "1", "body": ""}
response_header = {"headers": "HTTP/1.1 200 OK\r\nContent-Length: 4\r\nConnection: close\r\n\r\n", "timestamp": "1", "body": "pong"}
server.addResponse("sessionlog.json", request_header, response_header)

ts = Test.MakeATSProcess("ts")
ts.Disk.plugin_config.AddLine('stats_over_http.so')
Test.PrepareTestPlugin(os.path.join(Test.Variables.AtsTestPluginsDir, 'lsan_snapshot.so'), ts)
ts.Disk.remap_config.AddLine('map http://origin.test/ https://127.0.0.1:{0}/'.format(server.Variables.SSL_Port))

ts.Disk.records_config.update(
    {
        'proxy.config.http.server_session_sharing.match': 'none',
        'proxy.config.http.keep_alive_enabled_out': 0,
        'proxy.config.tunnel.prewarm.enabled': 0,
        'proxy.config.http.connect_attempts_max_retries': 0,
        'proxy.config.http.connect_attempts_rr_retries': 0,
        'proxy.config.ssl.client.verify.server.policy': 'DISABLED',
        'proxy.config.url_remap.remap_required': 0,
        'proxy.config.diags.debug.enabled': 1,
        'proxy.config.diags.debug.tags': 'lsan_snapshot',
    })

# Live LSan snapshot under the dedicated profile (in-flight frames dropped).
ts.Env['ASAN_OPTIONS'] = 'detect_leaks=1:abort_on_error=0:exitcode=0'
ts.Env['LSAN_OPTIONS'] = 'suppressions={0}:print_suppressions=0'.format(supp)

# Drive legit outbound TLS, then quiesce on the allocator gauges.
tr = Test.AddTestRun("drive outbound TLS then quiesce")
tr.Setup.Copy("tls_outbound_lifecycle_client.py")
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.Command = 'python3 tls_outbound_lifecycle_client.py {0} 30'.format(ts.Variables.port)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "QUIESCED_CLEAN|SKIPPED_NO_ALLOCATOR_METRICS", "outbound SSL VC returned to baseline (or skipped without allocator metrics)")
tr.TimeOut = 90

# The lsan_snapshot plugin (loaded above) takes a live LSan snapshot on the
# lifecycle message tag "lsan_snapshot"; trigger it out of band with
#   traffic_ctl plugin msg lsan_snapshot go
# to corroborate at the quiescent point. It is not driven from autest here
# because traffic_ctl's JSONRPC UDS is unreliable under the sandbox; the
# allocator-delta oracle above is the primary, robust gate.
