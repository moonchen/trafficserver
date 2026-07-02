'''
Async DNS resolution through IOUringNetVConnection (proxy.config.net.io_uring.enabled=1).
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
A proxied transaction whose origin must be resolved by an async DNS lookup, with
the io_uring net path enabled. Regression guard for a starvation bug: an io_uring
net thread blocks directly in the ring and never calls epoll_wait, but the DNS UDP
sockets are epoll-registered (a DNSConnection is not an io_uring VConnection) and
run on a net thread. Without bridging the epoll fd into the ring, the DNS reply
never wakes the thread and resolution hangs -- so any hostname-based origin stalls.
The io_uring_* tests all remap to a literal IP (no DNS); this is the only one that
exercises async resolution, and it covers both DNS thread modes
(proxy.config.dns.dedicated_thread 0 and 1, which both run the io_uring net loop).
'''

Test.SkipUnless(Condition.HasATSFeature('TS_USE_LINUX_IO_URING'))

Test.ContinueOnFail = True


def add_case(label: str, dedicated_dns_thread: int) -> None:
    """A GET whose origin is a hostname, so the 200 can only arrive once the async
    DNS lookup completes -- under the io_uring net path.

    Each case gets its own origin, DNS server, and ATS so the runs are independent.

    :param dedicated_dns_thread: proxy.config.dns.dedicated_thread. 0 runs DNS on a
        shared net thread, 1 spawns a dedicated ET_DNS thread; both run the io_uring
        net loop, so the epoll-fd bridge must service the DNS sockets in either mode.
    """
    suffix = "dedicated" if dedicated_dns_thread else "shared"
    server = Test.MakeOriginServer(f"server-{suffix}")
    dns = Test.MakeDNServer(f"dns-{suffix}", default='127.0.0.1')

    request_header = {"headers": "GET /foo HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
    response_header = {
        "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 14\r\n\r\n",
        "timestamp": "1469733493.993",
        "body": "hello-io-uring"
    }
    server.addResponse("sessionfile.log", request_header, response_header)

    ts = Test.MakeATSProcess(f"ts-{suffix}")
    ts.Disk.records_config.update(
        {
            'proxy.config.net.io_uring.enabled': 1,
            'proxy.config.dns.dedicated_thread': dedicated_dns_thread,
            'proxy.config.dns.nameservers': f'127.0.0.1:{dns.Variables.Port}',
            'proxy.config.dns.resolv_conf': 'NULL',
        })
    # The remap target is a hostname (not a literal IP), so the origin connection is
    # gated on an async DNS lookup of origin.io-uring.test.
    ts.Disk.remap_config.AddLine(f'map http://www.example.com http://origin.io-uring.test:{server.Variables.Port}')
    # Prove the io_uring VC path actually engaged (not a silent fallback to epoll,
    # which would resolve DNS fine and pass for the wrong reason).
    ts.Disk.diags_log.Content = Testers.ContainsExpression(
        "io_uring NetVConnection enabled", "the io_uring NetVConnection path must be active")

    tr = Test.AddTestRun(label)
    tr.MakeCurlCommand(f'--proxy 127.0.0.1:{ts.Variables.port} "http://www.example.com/foo" --verbose', ts=ts)
    tr.Processes.Default.StartBefore(dns)
    tr.Processes.Default.StartBefore(server)
    tr.Processes.Default.StartBefore(ts)
    tr.Processes.Default.ReturnCode = 0
    tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
        "hello-io-uring", "the origin body must come back, which requires DNS to have resolved under io_uring")
    tr.StillRunningAfter = ts
    tr.StillRunningAfter = server


add_case("hostname origin via async DNS, io_uring net path (shared DNS thread)", dedicated_dns_thread=0)
add_case("hostname origin via async DNS, io_uring net path (dedicated DNS thread)", dedicated_dns_thread=1)
