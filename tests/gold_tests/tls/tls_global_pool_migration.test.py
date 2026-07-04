'''
Verify that a TLS origin session reused from the global server-session pool is
migrated across threads (rather than the pooled session being closed).
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
Cross-thread migration of a TLS origin session from the global session pool
'''

REPLAY = 'tls_global_pool_migration.replay.yaml'

# TLS origin (keep-alive) served by a Proxy Verifier server.
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
        # Force the global pool so reuse goes through migrateToCurrentThread.
        'proxy.config.http.server_session_sharing.pool': 'global',
        'proxy.config.http.server_session_sharing.match': 'both',
        # Several ET_NET threads so a reused session is usually acquired on a
        # different thread than it was created on.
        'proxy.config.exec_thread.autoconfig.enabled': 0,
        'proxy.config.exec_thread.limit': 4,
    })

# --repeat opens that many separate client connections in sequence. Each lands on
# whichever of the 4 ET_NET threads accept assigns it and reuses the one pooled
# origin session, so roughly 3 of every 4 reuses acquire it from a different thread
# than it lives on. With 50 connections that yields tens of cross-thread migrations
# per run -- far above the >=1 the assertions below require -- so the load-based
# trigger is reliable in practice rather than depending on a single lucky acquire.
tr = Test.AddTestRun('Drive TLS traffic through the global pool')
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts)
client = tr.AddVerifierClientProcess(
    'client', REPLAY, https_ports=[ts.Variables.ssl_port], other_args='--repeat 50 --thread-limit 4')
tr.StillRunningAfter = ts
tr.StillRunningAfter = server

# Assert at least one cross-thread migration actually happened.
tr = Test.AddTestRun('Cross-thread migration occurred')
tr.Processes.Default.Command = 'traffic_ctl metric get proxy.process.ssl.origin_session_cross_thread_migration'
tr.Processes.Default.Env = ts.Env
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.All = Testers.ContainsExpression(
    r'proxy\.process\.ssl\.origin_session_cross_thread_migration [1-9][0-9]*',
    'At least one TLS origin session should have been migrated cross-thread')
tr.StillRunningAfter = ts
tr.StillRunningAfter = server

# Assert there were no migration failures.
tr = Test.AddTestRun('No migration failures')
tr.Processes.Default.Command = 'traffic_ctl metric get proxy.process.http.origin_shutdown.migration_failure'
tr.Processes.Default.Env = ts.Env
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.All = Testers.ContainsExpression(
    r'proxy\.process\.http\.origin_shutdown\.migration_failure 0', 'There should be no migration failures')
tr.StillRunningAfter = ts
tr.StillRunningAfter = server
