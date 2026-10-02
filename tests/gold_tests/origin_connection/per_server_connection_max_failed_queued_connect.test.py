'''
Verify that requests queued behind an origin connection that fails are not throttled by its
proxy.config.http.per_server.connection.max count.
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


class FailedQueuedConnectTest:
    """Verify the per server maximum when a connection that requests queued behind fails.

    All requests run on one thread, so when they arrive together the first one opens the
    connection and the others queue behind it. When the connection fails, each queued request
    retries at once, from inside the failure notice. The failed connection's count has to be given
    back before that, or with a maximum of one every retry is throttled.
    """

    _request_count: int = 6
    _connect_timeout_seconds: int = 1

    # The per group metrics are derived metrics, refreshed every raw_stat_sync_interval_ms.
    _stat_sync_interval_ms: int = 500
    _stat_sync_wait_seconds: int = 2

    def __init__(self) -> None:
        """Configure the test processes in preparation for the TestRun."""
        self._configure_server()
        self._configure_trafficserver()

    def _configure_server(self) -> None:
        """Configure an origin that accepts connections but never completes a TLS handshake.

        The origin waits for a plain HTTP request header, which a TLS client hello never
        completes, so every connection to it fails at the connect timeout.
        """
        self._server = Test.Processes.Process('origin')
        port = get_port(self._server, 'http_port')
        origin = os.path.join(Test.TestDirectory, 'counting_origin.py')
        self._server.Command = f'{sys.executable} {origin} {port}'
        self._server.Ready = When.PortOpenv4(port)

    def _configure_trafficserver(self) -> None:
        """Configure Traffic Server with one thread so that all requests share a connection queue."""
        self._ts = Test.MakeATSProcess('ts', enable_cache=False)
        self._ts.Disk.remap_config.AddLine(f'map / https://127.0.0.1:{self._server.Variables.http_port}')
        self._ts.Disk.records_config.update(
            {
                'proxy.config.exec_thread.autoconfig.enabled': 0,
                'proxy.config.exec_thread.limit': 1,
                # Accept each connection when it opens, not when its request arrives, so that requests are read in the order sent.
                'proxy.config.net.defer_accept': 0,
                'proxy.config.raw_stat_sync_interval_ms': self._stat_sync_interval_ms,
                'proxy.config.diags.debug.enabled': 1,
                'proxy.config.diags.debug.tags': 'http_connect|http_ss|conn_track',
                'proxy.config.http.connect_attempts_timeout': self._connect_timeout_seconds,
                'proxy.config.http.connect_attempts_max_retries': 1,
                'proxy.config.http.per_server.connection.max': 1,
                'proxy.config.http.per_server.connection.metric_enabled': 1,
                'proxy.config.http.per_server.connection.match': 'port',
            })
        self._ts.Disk.traffic_out.Content += Testers.ContainsExpression(
            'Queue behind existing request', 'Requests should queue behind the first new origin connection.')
        self._ts.Disk.traffic_out.Content += Testers.ContainsExpression(
            'state machines waiting for failed origin', 'The queued requests should be told that the connection failed.')
        self._ts.Disk.diags_log.Content += Testers.ExcludesExpression(
            'Number of tracked connections should be greater than or equal to zero',
            'A connection count should never be released twice.')

    def _test_requests(self) -> None:
        """Send all requests at once to the origin that does not answer."""
        tr = Test.AddTestRun('Send concurrent requests that queue behind an origin connection that fails')
        tr.Processes.Default.StartBefore(self._server)
        tr.Processes.Default.StartBefore(self._ts)
        client = os.path.join(Test.TestDirectory, 'concurrent_client.py')
        tr.Processes.Default.Command = f'{sys.executable} {client} {self._ts.Variables.port} --count {self._request_count}'
        tr.Processes.Default.ReturnCode = 0
        tr.StillRunningAfter = self._server
        tr.StillRunningAfter += self._ts

    def _test_counts(self) -> None:
        """Verify that no retry was throttled and that no count is left behind."""
        group = f'127.0.0.1:{self._server.Variables.http_port}'

        tr = Test.AddTestRun('Verify the retries were not throttled')
        tr.Processes.Default.Command = (
            f'sleep {self._stat_sync_wait_seconds}; '
            'traffic_ctl metric get proxy.process.http.origin_connections_throttled_out; '
            'traffic_ctl metric match per_server; '
            "traffic_ctl rpc invoke get_connection_tracker_info -p 'table: outbound' -f json")
        tr.Processes.Default.Env = self._ts.Env
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.Streams.stdout += Testers.ContainsExpression(
            'proxy.process.http.origin_connections_throttled_out 0', 'No retry should be throttled by the failed connection.')
        tr.Processes.Default.Streams.stdout += Testers.ContainsExpression(
            f'per_server.blocked_connection.{group} 0', 'The group should not count any blocked connection.')
        tr.Processes.Default.Streams.stdout += Testers.ExcludesExpression(
            r'"current":\s*"?[1-9]', 'Every failed connection should give its count back.')
        tr.StillRunningAfter = self._server
        tr.StillRunningAfter += self._ts

    def run(self) -> None:
        """Configure the TestRuns."""
        self._test_requests()
        self._test_counts()


FailedQueuedConnectTest().run()
