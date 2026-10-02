'''
Verify that proxy.config.http.per_server.connection.min keeps an origin connection that
several requests queued behind.
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
import re
import sys

from ports import get_port

Test.Summary = __doc__


class QueuedConnectMinTest:
    """Verify the per server minimum when requests queue behind one new origin connection.

    All requests run on one thread, so when they arrive together the first one opens the
    connection and the others queue behind it. The connection count that the first request
    reserved has to stay with the connection, whichever queued request gets the session.
    Otherwise the group counts one connection fewer than are open, and the minimum does not
    keep that connection when it times out.
    """

    _request_count: int = 6
    _min_connections: int = 3
    _max_connections: int = 20
    _response_delay_seconds: int = 2
    _keep_alive_timeout: int = 3

    # The per group metrics are derived metrics, refreshed every raw_stat_sync_interval_ms.
    _stat_sync_interval_ms: int = 500

    def __init__(self) -> None:
        """Configure the test processes in preparation for the TestRun."""
        self._configure_server()
        self._configure_trafficserver()

    def _configure_server(self) -> None:
        """Configure the origin, which holds each response so that the connections overlap."""
        self._server = Test.Processes.Process('origin')
        port = get_port(self._server, 'http_port')
        origin = os.path.join(Test.TestDirectory, 'counting_origin.py')
        self._server.Command = f'{sys.executable} {origin} {port} --delay {self._response_delay_seconds}'
        self._server.Ready = When.PortOpenv4(port)
        self._server.Streams.stdout += Testers.ContainsExpression(
            f'peak={self._request_count}', 'Every request should have its own origin connection.')

    def _configure_trafficserver(self) -> None:
        """Configure Traffic Server with one thread so that all requests share a connection queue."""
        self._ts = Test.MakeATSProcess('ts', enable_cache=False)
        self._ts.Disk.remap_config.AddLine(f'map / http://127.0.0.1:{self._server.Variables.http_port}')
        self._ts.Disk.records_config.update(
            {
                'proxy.config.exec_thread.autoconfig.enabled': 0,
                'proxy.config.exec_thread.limit': 1,
                # Accept each connection when it opens, not when its request arrives, so that requests are read in the order sent.
                'proxy.config.net.defer_accept': 0,
                'proxy.config.raw_stat_sync_interval_ms': self._stat_sync_interval_ms,
                'proxy.config.diags.debug.enabled': 1,
                'proxy.config.diags.debug.tags': 'http_connect|http_ss|conn_track',
                'proxy.config.http.keep_alive_no_activity_timeout_out': self._keep_alive_timeout,
                'proxy.config.http.per_server.connection.max': self._max_connections,
                'proxy.config.http.per_server.connection.min': self._min_connections,
                'proxy.config.http.per_server.connection.metric_enabled': 1,
                'proxy.config.http.per_server.connection.match': 'port',
            })
        self._ts.Disk.traffic_out.Content += Testers.ContainsExpression(
            'Queue behind existing request', 'Requests should queue behind the first new origin connection.')
        self._ts.Disk.traffic_out.Content += Testers.ContainsExpression(
            'ConnectingEntry send CONNECT_EVENT_TXN', 'The queued connection should be handed to one of the requests.')
        self._ts.Disk.traffic_out.Content += Testers.ContainsExpression(
            r'\[(\d+)\] Queue multiplexed request.*ConnectingEntry create session for \[(?!\1\])\d+\]',
            'The session should go to a queued request, not to the request that opened the connection.',
            reflags=re.M | re.S)
        self._ts.Disk.traffic_out.Content += Testers.ContainsExpression(
            'resetting timeout to maintain minimum number of connections', 'The minimum should keep idle origin connections.')
        self._ts.Disk.diags_log.Content += Testers.ExcludesExpression(
            'Number of tracked connections should be greater than or equal to zero',
            'A connection count should never be released twice.')

    def _test_requests(self) -> None:
        """Send all requests at once and verify that all of them are served."""
        tr = Test.AddTestRun('Send concurrent requests that queue behind one origin connection')
        tr.Processes.Default.StartBefore(self._server)
        tr.Processes.Default.StartBefore(self._ts)
        client = os.path.join(Test.TestDirectory, 'concurrent_client.py')
        tr.Processes.Default.Command = f'{sys.executable} {client} {self._ts.Variables.port} --count {self._request_count}'
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.Streams.stdout += Testers.ContainsExpression(
            f'status 200: {self._request_count} responses', 'Every request should be served.')
        tr.StillRunningAfter = self._server
        tr.StillRunningAfter += self._ts

    def _test_minimum_kept(self) -> None:
        """Verify that the minimum is kept after the idle connections time out.

        The minimum alone ends at the same number of open connections whether or not one of them
        was counted, because uncounted connections close anyway. The peak count of the group
        shows whether every connection was counted: it has to equal the number that were open at
        once.
        """
        group = f'127.0.0.1:{self._server.Variables.http_port}'

        tr = Test.AddTestRun('Verify the minimum number of origin connections is kept')
        tr.Processes.Default.Command = (
            f'sleep {self._keep_alive_timeout * 3}; '
            'traffic_ctl metric get proxy.process.http.current_server_connections; '
            'traffic_ctl metric match per_server.current_connection; '
            "traffic_ctl rpc invoke get_connection_tracker_info -p 'table: outbound' -f json")
        tr.Processes.Default.Env = self._ts.Env
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.Streams.stdout += Testers.ContainsExpression(
            f'proxy.process.http.current_server_connections {self._min_connections}',
            'The idle origin connections over the minimum should be closed.')
        tr.Processes.Default.Streams.stdout += Testers.ContainsExpression(
            f'per_server.current_connection.{group} {self._min_connections}',
            'The group should count every open origin connection.')
        tr.Processes.Default.Streams.stdout += Testers.ContainsExpression(
            rf'"current":\s*"?{self._min_connections}\b', 'The tracker should count every open origin connection.')
        tr.Processes.Default.Streams.stdout += Testers.ContainsExpression(
            rf'"max":\s*"?{self._request_count}\b', 'The tracker should have counted every origin connection.')
        tr.StillRunningAfter = self._server
        tr.StillRunningAfter += self._ts

    def run(self) -> None:
        """Configure the TestRuns."""
        self._test_requests()
        self._test_minimum_kept()


QueuedConnectMinTest().run()
