'''
Stress the layered SSL origin VConnection's WRITE_COMPLETE path against session
churn. POST bodies drive repeated encrypt-and-drain WRITE_COMPLETE cycles on the
outbound (origin) TLS VC; the global session pool plus several ET_NET threads and
many sequential client connections churn those origin sessions (release, reacquire,
cross-thread migrate) while writes are completing. This is the combination that
produced the production WRITE_COMPLETE-after-close crash, where a deferred
write-completion signal fired against a consumer that had already been torn down.
Every transaction must succeed and ATS must not crash or trip a sanitizer.
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

Test.Summary = __doc__

REPLAY = 'tls_origin_write_complete_churn.replay.yaml'


class TestTlsOriginWriteCompleteChurn:
    '''Drive origin-side WRITE_COMPLETE cycles through global-pool session churn.'''

    def __init__(self) -> None:
        self._server = self._configure_origin()
        self._ts = self._configure_trafficserver()

    def _configure_origin(self) -> 'Process':
        '''A keep-alive TLS origin served by a Proxy Verifier server.'''
        return Test.MakeVerifierServerProcess('server', REPLAY)

    def _configure_trafficserver(self) -> 'Process':
        '''Configure Traffic Server to reuse TLS origin sessions from the global pool.'''
        ts = Test.MakeATSProcess('ts', enable_tls=True, enable_cache=False)
        ts.addSSLfile('ssl/server.pem')
        ts.addSSLfile('ssl/server.key')
        ts.Disk.ssl_multicert_yaml.AddLines(
            '''
ssl_multicert:
  - dest_ip: "*"
    ssl_cert_name: server.pem
    ssl_key_name: server.key
'''.split('\n'))

        ts.Disk.remap_config.AddLine('map / https://127.0.0.1:{0}'.format(self._server.Variables.https_port))

        ts.Disk.records_config.update(
            {
                'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
                'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
                'proxy.config.ssl.client.verify.server.policy': 'PERMISSIVE',
                # Global pool so origin reuse goes through release + migrateToCurrentThread.
                'proxy.config.http.server_session_sharing.pool': 'global',
                'proxy.config.http.server_session_sharing.match': 'both',
                # Several ET_NET threads so a reused session is often acquired on a
                # different thread than it lives on, exercising cross-thread migration.
                'proxy.config.exec_thread.autoconfig.enabled': 0,
                'proxy.config.exec_thread.limit': 4,
            })

        # The run must not crash or trip an assertion / sanitizer -- this is the
        # crash class the test exists to guard against.
        ts.Disk.traffic_out.Content = Testers.ExcludesExpression(
            "received signal|failed assertion", "ATS must not crash draining origin writes under churn")
        ts.Disk.traffic_out.Content += Testers.ExcludesExpression(
            "AddressSanitizer|use-after-free|runtime error:", "no memory-safety error on the origin write path")
        return ts

    def run(self) -> None:
        tr = Test.AddTestRun('Drive POST-heavy TLS origin traffic through the global pool')
        tr.Processes.Default.StartBefore(self._server)
        tr.Processes.Default.StartBefore(self._ts)
        # --repeat opens many separate client connections in sequence; each reuses the
        # pooled origin session and lands on whichever ET_NET thread accept assigns it,
        # so origin sessions are released, reacquired, and migrated repeatedly while the
        # POST bodies keep the origin write path busy completing writes.
        tr.AddVerifierClientProcess(
            'client', REPLAY, https_ports=[self._ts.Variables.ssl_port], other_args='--repeat 50 --thread-limit 4')
        tr.StillRunningAfter = self._ts
        tr.StillRunningAfter = self._server


TestTlsOriginWriteCompleteChurn().run()
