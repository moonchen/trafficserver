'''
Verify that proxy.config.http.per_server.connection.max counts an origin connection that
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


class QueuedConnectMaxTest:
    """Verify the per server maximum when requests queue behind one new origin connection.

    All requests run on one thread, so when they arrive together the first one opens the
    connection and the others queue behind it. The connection count that the first request
    reserved has to stay with the connection, whichever queued request gets the session, or the
    connection is not counted against the maximum.
    """

    _request_count: int = 6
    _max_connections: int = 2
    _response_delay_seconds: int = 2

    # The per group metrics are derived metrics, refreshed every raw_stat_sync_interval_ms.
    _stat_sync_interval_ms: int = 500
    _stat_sync_wait_seconds: int = 2

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
            f'peak={self._max_connections}', 'The origin should see as many connections as the maximum allows.')
        self._server.Streams.stdout += Testers.ExcludesExpression(
            f'peak={self._max_connections + 1}', 'The origin should never see more connections than the maximum.')

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
                'proxy.config.http.per_server.connection.max': self._max_connections,
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
        self._ts.Disk.diags_log.Content += Testers.ExcludesExpression(
            'Number of tracked connections should be greater than or equal to zero',
            'A connection count should never be released twice.')

    def _test_requests(self) -> None:
        """Send all requests at once and verify that only the maximum number are served."""
        tr = Test.AddTestRun('Send concurrent requests that queue behind one origin connection')
        tr.Processes.Default.StartBefore(self._server)
        tr.Processes.Default.StartBefore(self._ts)
        client = os.path.join(Test.TestDirectory, 'concurrent_client.py')
        tr.Processes.Default.Command = f'{sys.executable} {client} {self._ts.Variables.port} --count {self._request_count}'
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.Streams.stdout += Testers.ContainsExpression(
            f'status 200: {self._max_connections} responses', 'Only the maximum number of requests should reach the origin.')
        tr.StillRunningAfter = self._server
        tr.StillRunningAfter += self._ts

    def _test_throttle_metrics(self) -> None:
        """Verify that every other request was throttled."""
        throttled = self._request_count - self._max_connections
        group = f'127.0.0.1:{self._server.Variables.http_port}'

        tr = Test.AddTestRun('Verify the throttled request counters')
        tr.Processes.Default.Command = (
            f'sleep {self._stat_sync_wait_seconds}; '
            'traffic_ctl metric get proxy.process.http.origin_connections_throttled_out; '
            'traffic_ctl metric match per_server')
        tr.Processes.Default.Env = self._ts.Env
        tr.Processes.Default.ReturnCode = 0
        tr.Processes.Default.Streams.stdout += Testers.ContainsExpression(
            f'proxy.process.http.origin_connections_throttled_out {throttled}',
            'Every request over the maximum should be throttled.')
        tr.Processes.Default.Streams.stdout += Testers.ContainsExpression(
            f'per_server.blocked_connection.{group} {throttled}', 'The group should count every throttled request.')
        tr.StillRunningAfter = self._server
        tr.StillRunningAfter += self._ts

    def run(self) -> None:
        """Configure the TestRuns."""
        self._test_requests()
        self._test_throttle_metrics()


QueuedConnectMaxTest().run()
