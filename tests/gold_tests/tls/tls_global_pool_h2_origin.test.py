'''
Verify that HTTP/2 TLS origin sessions are never migrated across threads, even
with the global server-session pool configured.
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
HTTP/2 TLS origin sessions skip cross-thread migration of the global pool
'''

REPLAY = 'tls_global_pool_h2_origin.replay.yaml'

# HTTP/2 TLS origin (keep-alive) served by a Proxy Verifier server.
server = Test.MakeVerifierServerProcess('server', REPLAY)

ts = Test.MakeATSProcess('ts', enable_tls=True)
ts.addSSLfile('ssl/server.pem')
ts.addSSLfile('ssl/server.key')
ts.Disk.ssl_multicert_yaml.AddLines(
    '''
ssl_multicert:
  - dest_ip: "*"
    ssl_cert_name: server.pem
    ssl_key_name: server.key
'''.split('\n'))

ts.Disk.remap_config.AddLine('map / https://127.0.0.1:{0}'.format(server.Variables.https_port))

ts.Disk.records_config.update(
    {
        'proxy.config.http.cache.http': 0,
        'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
        'proxy.config.ssl.client.verify.server.policy': 'PERMISSIVE',
        # Offer h2 to the origin so ATS speaks HTTP/2 upstream.
        'proxy.config.ssl.client.alpn_protocols': 'h2,http/1.1',
        # Force the global pool. For HTTP/1.1 origins this is what drives
        # SSLNetVConnection::migrateToCurrentThread. HTTP/2 origin sessions are
        # pooled per-thread regardless, so this exercises the claim that they
        # never reach that path.
        'proxy.config.http.server_session_sharing.pool': 'global',
        'proxy.config.http.server_session_sharing.match': 'both',
        # Several ET_NET threads so reuse would land on a different thread than
        # the session was created on if it went through the global pool.
        'proxy.config.exec_thread.autoconfig.enabled': 0,
        'proxy.config.exec_thread.limit': 4,
    })

# --repeat opens that many separate HTTP/2 client connections in sequence. Each
# lands on whichever of the 4 ET_NET threads accept assigns it. For an HTTP/1.1
# origin this would yield tens of cross-thread migrations; for an HTTP/2 origin
# the session is pooled per-thread and reused on its own thread, so no migration
# happens at all.
tr = Test.AddTestRun('Drive HTTP/2 traffic to an HTTP/2 TLS origin through the global pool')
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts)
client = tr.AddVerifierClientProcess(
    'client', REPLAY, https_ports=[ts.Variables.ssl_port], other_args='--repeat 50 --thread-limit 4')
tr.Processes.Default.ReturnCode = 0
tr.StillRunningAfter = ts
tr.StillRunningAfter = server

# Assert that no cross-thread migration ever happened: HTTP/2 origins are pooled
# per-thread and never take the SSLNetVConnection migration path.
tr = Test.AddTestRun('No cross-thread migration for HTTP/2 origins')
tr.Processes.Default.Command = 'traffic_ctl metric get proxy.process.ssl.origin_session_cross_thread_migration'
tr.Processes.Default.Env = ts.Env
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.All = Testers.ContainsExpression(
    r'proxy\.process\.ssl\.origin_session_cross_thread_migration 0', 'HTTP/2 origin sessions should never be migrated cross-thread')
tr.StillRunningAfter = ts
tr.StillRunningAfter = server
