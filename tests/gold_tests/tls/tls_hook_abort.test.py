'''
A plugin fails a TLS handshake from the SSL cert hook via the supported path,
TSVConnReenableEx(vc, TS_EVENT_ERROR). The cert hook fires synchronously while
ATS is still nested inside OpenSSL's SSL_accept(), so the flagged error must be
delivered and the connection torn down on a clean stack: no crash, no sanitizer
report, and the client sees a failed handshake. (Closing the handshake VC
directly from the hook is not a supported action and is rejected by the API.)
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

Test.Summary = __doc__


class TestTlsHookAbort:
    '''Failing a handshake from the cert hook via TSVConnReenableEx(TS_EVENT_ERROR) must be clean.'''

    def __init__(self) -> None:
        self._ts = self._configure_trafficserver()

    def _configure_trafficserver(self) -> 'Process':
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
        ts.Disk.records_config.update(
            {
                'proxy.config.ssl.server.cert.path': '{0}'.format(ts.Variables.SSLDir),
                'proxy.config.ssl.server.private_key.path': '{0}'.format(ts.Variables.SSLDir),
                'proxy.config.diags.debug.enabled': 1,
                'proxy.config.diags.debug.tags': 'ssl_cert_abort',
            })
        ts.Disk.remap_config.AddLine('map / https://127.0.0.1:1/')

        # On an ASAN build, LSan runs at exit. Suppress the known one-time/shutdown
        # allocations so the sanitizer exclusion below stays a real leak oracle: an
        # unsuppressed leak on the hook-failed handshake path (e.g. an orphaned
        # protocol acceptor) still prints and fails the test.
        supp = os.path.abspath(os.path.join(Test.TestDirectory, '..', '..', '..', 'ci', 'asan_leak_suppression', 'tls_autest.txt'))
        ts.Env['ASAN_OPTIONS'] = 'detect_leaks=1:abort_on_error=0:exitcode=0'
        ts.Env['LSAN_OPTIONS'] = 'suppressions={0}:print_suppressions=0'.format(supp)

        # The plugin fails every inbound handshake from the cert hook.
        Test.PrepareTestPlugin(os.path.join(Test.Variables.AtsTestPluginsDir, 'ssl_cert_abort.so'), ts)

        # The plugin must actually fire (otherwise the test is vacuous). The DIAG
        # output lands in traffic.out.
        ts.Disk.traffic_out.Content = Testers.ContainsExpression(
            "failing the handshake", "the cert hook must run and fail the handshake")
        # The deferred error delivery and teardown must be clean.
        ts.Disk.traffic_out.Content += Testers.ExcludesExpression(
            "received signal|failed assertion", "ATS must not crash failing a handshake from the cert hook")
        ts.Disk.traffic_out.Content += Testers.ExcludesExpression(
            "AddressSanitizer|use-after-free|runtime error:", "no memory-safety error on the hook-failed handshake path")
        return ts

    def run(self) -> None:
        tr = Test.AddTestRun("Fail several TLS handshakes from the cert hook; ATS must stay up and clean")
        tr.Processes.Default.StartBefore(self._ts)
        # Each handshake is failed by the plugin, so curl fails -- that is expected.
        # We drive several attempts and assert ATS stays up and clean, not curl's exit.
        tr.MakeCurlCommandMulti(
            (
                '{{curl}} -k --tlsv1.2 https://127.0.0.1:{0}; '
                '{{curl}} -k https://127.0.0.1:{0}; '
                '{{curl}} -k https://127.0.0.1:{0}').format(self._ts.Variables.ssl_port),
            ts=self._ts)
        tr.Processes.Default.ReturnCode = Any(0, 35, 55, 56)  # handshake-failure exits vary by curl/TLS lib and RST timing
        tr.StillRunningAfter = self._ts


TestTlsHookAbort().run()
