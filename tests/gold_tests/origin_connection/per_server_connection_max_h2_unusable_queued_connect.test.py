'''
Verify that an HTTP/2 origin connection that none of the requests queued behind it can use does not
count against proxy.config.http.per_server.connection.max when they connect on their own.
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
import sys

from ports import get_port

Test.Summary = __doc__


class UnusableH2QueuedConnectTest:
    """Verify the per server maximum when no queued request can use the new HTTP/2 session.

    All requests run on one thread, so when they arrive together the first one opens the
    connection and the others queue behind it. Traffic Server sends no SNI, so the handshake
    checks the certificate against the origin address, which it names. Each request then checks
    the certificate against its Host header, which it does not name, so every request connects on
    its own, from inside the handoff. The unused session has to give its count back before that,
    or with a maximum equal to the number of requests the last one is throttled.
    """

    _request_count: int = 6
    _idle_timeout: int = 3

    # The per group metrics are derived metrics, refreshed every raw_stat_sync_interval_ms.
    _stat_sync_interval_ms: int = 500
    _stat_sync_wait_seconds: int = 2

    def __init__(self) -> None:
        """Configure the test processes in preparation for the TestRun."""
        self._configure_server()
        self._configure_trafficserver()
        self._group = f'127.0.0.1:{self._server.Variables.https_port}'

    def _configure_server(self) -> None:
        """Configure an HTTP/2 origin whose certificate names its address but not the requested host."""
        self._server = Test.Processes.Process('origin')
        port = get_port(self._server, 'https_port')
        origin = os.path.join(Test.TestDirectory, 'counting_origin.py')
        self._server.Command = f'{sys.executable} {origin} {port} --delay 0 --h2 127.0.0.1'
        self._server.Ready = When.PortOpenv4(port)

    def _configure_trafficserver(self) -> None:
        """Configure Traffic Server with one thread so that all requests share a connection queue."""
        self._ts = Test.MakeATSProcess('ts', enable_cache=False)
        self._ts.Disk.remap_config.AddLine(f'map / https://127.0.0.1:{self._server.Variables.https_port}')
        self._ts.Disk.records_config.update(
            {
                'proxy.config.exec_thread.autoconfig.enabled': 0,
                'proxy.config.exec_thread.limit': 1,
                # Accept each connection when it opens, not when its request arrives, so that requests are read in the order sent.
                'proxy.config.net.defer_accept': 0,
                'proxy.config.raw_stat_sync_interval_ms': self._stat_sync_interval_ms,
                'proxy.config.diags.debug.enabled': 1,
                'proxy.config.diags.debug.tags': 'http_connect|http_ss|conn_track',
                'proxy.config.ssl.client.alpn_protocols': 'h2',
                # An empty fixed name sends no SNI.
                'proxy.config.ssl.client.sni_policy': '@',
                'proxy.config.url_remap.pristine_host_hdr': 1,
                # The origin certificate is self-signed.
                'proxy.config.ssl.client.verify.server.properties': 'NAME',
                'proxy.config.ssl.client.verify.server.policy': 'ENFORCED',
                'proxy.config.http2.no_activity_timeout_out': self._idle_timeout,
                'proxy.config.http.per_server.connection.max': self._request_count,
                'proxy.config.http.per_server.connection.metric_enabled': 1,
                'proxy.config.http.per_server.connection.match': 'port',
            })
        self._ts.Disk.traffic_out.Content += Testers.ContainsExpression(
            'Queue behind existing request', 'Requests should queue behind the first new origin connection.')
        self._ts.Disk.traffic_out.Content += Testers.ContainsExpression(
            f'ConnectingEntry Pass along CONNECT_EVENT_DIRECT {self._request_count - 1}',
            'Every queued request should connect on its own.')
        self._ts.Disk.traffic_out.Content += Testers.ExcludesExpression(
            'ConnectingEntry Pass along CONNECT_EVENT_TXN', 'No queued request should get the HTTP/2 session.')
        self._ts.Disk.diags_log.Content += Testers.ContainsExpression(
            r'Origin hostname \(www.example.com\) not in certificate. Action=Terminate',
            'The certificate should not name the requested host.')
        self._ts.Disk.diags_log.Content += Testers.ExcludesExpression(
            'Number of tracked connections should be greater than or equal to zero',
            'A connection count should never be released twice.')

    def _test_requests(self) -> None:
        """Send all requests at once and verify that all of them are served."""
        tr = Test.AddTestRun('Send concurrent requests that cannot use the HTTP/2 connection they queued behind')
        tr.Processes.Default.StartBefore(self._server)
        tr.Processes.Default.StartBefore(self._ts)
        client = os.path.join(Test.TestDirectory, 'concurrent_client.py')
        tr.Processes.Default.Command = f'{sys.executable} {client} {self._ts.Variables.port} --count {self._request_count}'
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.Streams.stdout += Testers.ContainsExpression(
            f'status 200: {self._request_count} responses', 'Every request should be served.')
        tr.StillRunningAfter = self._server
        tr.StillRunningAfter += self._ts

    def _test_not_throttled(self) -> None:
        """Verify that no request was throttled by the unused connection."""
        tr = Test.AddTestRun('Verify the requests were not throttled')
        tr.Processes.Default.Command = (
            f'sleep {self._stat_sync_wait_seconds}; '
            'traffic_ctl metric get proxy.process.http.origin_connections_throttled_out; '
            'traffic_ctl metric match per_server')
        tr.Processes.Default.Env = self._ts.Env
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.Streams.stdout += Testers.ContainsExpression(
            'proxy.process.http.origin_connections_throttled_out 0', 'No request should be throttled by the unused connection.')
        tr.Processes.Default.Streams.stdout += Testers.ContainsExpression(
            f'per_server.blocked_connection.{self._group} 0', 'The group should not count any blocked connection.')
        tr.StillRunningAfter = self._server
        tr.StillRunningAfter += self._ts

    def _test_counts_released(self) -> None:
        """Verify that every count is given back when the idle connections time out."""
        tr = Test.AddTestRun('Verify the closed origin connections gave their counts back')
        tr.Processes.Default.Command = (
            f'sleep {self._idle_timeout * 3}; '
            'traffic_ctl metric get proxy.process.http2.current_server_connections; '
            "traffic_ctl rpc invoke get_connection_tracker_info -p 'table: outbound' -f json")
        tr.Processes.Default.Env = self._ts.Env
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.Streams.stdout += Testers.ContainsExpression(
            'proxy.process.http2.current_server_connections 0', 'The idle origin connections should close.')
        tr.Processes.Default.Streams.stdout += Testers.ExcludesExpression(
            r'"current":\s*"?[1-9]', 'Every closed connection should give its count back.')
        tr.StillRunningAfter = self._server
        tr.StillRunningAfter += self._ts

    def run(self) -> None:
        """Configure the TestRuns."""
        self._test_requests()
        self._test_not_throttled()
        self._test_counts_released()


UnusableH2QueuedConnectTest().run()
