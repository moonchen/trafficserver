'''
A plugin may fail a TLS handshake from an SSL hook. When it does so with
TSVConnAbort (rather than the reenable-based path), the abort's do_io_close runs
synchronously while ATS is still nested inside OpenSSL's SSL_accept() -- the cert
hook fires mid-handshake. The layered SSLNetVConnection must not free its SSL
object inline there (that would be a use-after-free inside libssl); it must defer
the teardown until the OpenSSL frame has returned. ATS must survive the abort.
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
    '''A synchronous TSVConnAbort from an SSL cert hook must not crash ATS.'''

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

        # The plugin aborts every inbound handshake from the cert hook.
        Test.PrepareTestPlugin(os.path.join(Test.Variables.AtsTestPluginsDir, 'ssl_cert_abort.so'), ts)

        # The plugin must actually fire (otherwise the test is vacuous). The DIAG
        # output lands in traffic.out.
        ts.Disk.traffic_out.Content = Testers.ContainsExpression(
            "aborting ssl_vc", "the cert hook must run and abort the handshake")
        # The abort must not crash or trip a sanitizer -- this is the whole point.
        ts.Disk.traffic_out.Content += Testers.ExcludesExpression(
            "received signal|failed assertion", "ATS must not crash on a mid-handshake TSVConnAbort")
        ts.Disk.traffic_out.Content += Testers.ExcludesExpression(
            "AddressSanitizer|use-after-free|runtime error:", "no memory-safety error on a mid-handshake abort")
        return ts

    def run(self) -> None:
        tr = Test.AddTestRun("Abort several TLS handshakes from the cert hook; ATS must survive")
        tr.Processes.Default.StartBefore(self._ts)
        # Each handshake is aborted by the plugin, so curl fails -- that is expected.
        # We drive several attempts and assert ATS stays up and clean, not curl's exit.
        tr.MakeCurlCommandMulti(
            (
                '{{curl}} -k --tlsv1.2 https://127.0.0.1:{0}; '
                '{{curl}} -k https://127.0.0.1:{0}; '
                '{{curl}} -k https://127.0.0.1:{0}').format(self._ts.Variables.ssl_port),
            ts=self._ts)
        tr.Processes.Default.ReturnCode = Any(0, 35, 56)  # handshake-failure exits vary by curl/TLS lib
        tr.StillRunningAfter = self._ts


TestTlsHookAbort().run()
