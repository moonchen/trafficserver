#!/usr/bin/env python3
"""Driver for the dedicated quiescent outbound-lifecycle LSan profile.

Drives M inbound requests that ATS reverse-proxies over TLS to a real origin
(each a fresh outbound TLS connection, since sharing/keep-alive-out are off),
then polls the allocator-in-use gauges to a metric-gated quiescence barrier.

After quiescence, a legitimate implementation returns
proxy.process.allocator.inuse.sslNetVCAllocator to its pre-traffic baseline: no
outbound SSL VC orphaned. A surviving delta is a genuine leak. This is the
allocator-delta oracle sol recommended; the lsan_snapshot plugin then takes a
live LSan snapshot at this same quiescent point for stack-level corroboration.
"""
import sys
import time
import json
import urllib.request

ats_port = int(sys.argv[1])
M = int(sys.argv[2])

SSL_VC = 'proxy.process.allocator.inuse.sslNetVCAllocator'
NET_VC = 'proxy.process.allocator.inuse.netVCAllocator'
OPEN = 'proxy.process.net.connections_currently_open'


def read_stats():
    with urllib.request.urlopen("http://127.0.0.1:{0}/_stats".format(ats_port), timeout=10) as r:
        body = r.read().decode()
    vals = {}
    data = json.loads(body)
    g = data.get('global', data)
    for k, v in g.items():
        try:
            vals[k] = int(float(v))
        except (ValueError, TypeError):
            pass
    return vals


def do_request():
    req = urllib.request.Request("http://127.0.0.1:{0}/".format(ats_port), headers={'Host': 'origin.test'})
    with urllib.request.urlopen(req, timeout=10) as r:
        r.read()


base = read_stats()
if SSL_VC not in base:
    # The allocator-in-use gauges only exist in an ENABLE_ALLOCATOR_METRICS build;
    # this profile is a no-op otherwise.
    print("SKIPPED_NO_ALLOCATOR_METRICS (build without ENABLE_ALLOCATOR_METRICS)")
    sys.exit(0)
base_ssl = base.get(SSL_VC, 0)
print(
    "base: sslNetVCAllocator={0} netVCAllocator={1} connections_currently_open={2}".format(
        base_ssl, base.get(NET_VC), base.get(OPEN)))

ok = 0
for _ in range(M):
    try:
        do_request()
        ok += 1
    except Exception as e:  # noqa: BLE001
        print("request error: {0}".format(e), file=sys.stderr)
print("completed {0}/{1} outbound-TLS requests".format(ok, M))

# Metric-gated quiescence: sslNetVCAllocator at baseline for 3 consecutive samples.
stable = 0
for _ in range(30):
    time.sleep(1)
    s = read_stats()
    if s.get(SSL_VC, 10**9) <= base_ssl:
        stable += 1
        if stable >= 3:
            break
    else:
        stable = 0

final = read_stats()
print(
    "final: sslNetVCAllocator={0} netVCAllocator={1} connections_currently_open={2}".format(
        final.get(SSL_VC), final.get(NET_VC), final.get(OPEN)))

delta = final.get(SSL_VC, 10**9) - base_ssl
if delta <= 0:
    print("QUIESCED_CLEAN (no outbound SSL VC orphaned)")
else:
    print("QUIESCED_LEAK sslNetVCAllocator_delta={0}".format(delta))
