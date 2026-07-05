'''
TLS over io_uring: arena-backed SSL _write_buf engages send_zc_fixed.
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
Under a layered SSLNetVConnection whose inner transport is an IOUringNetVConnection,
the bytes the transport sends are ciphertext staged in the SSL VC's _write_buf. With
write zero-copy + the registered fixed-buffer arena enabled and the SSL write-buffer
water mark raised, _write_buf's blocks are drawn from the arena, so the staged
ciphertext goes out as send_zc_fixed:

  (a) Engagement: a large TLS response must advance write_zerocopy_fixed (> 0) with
      full body integrity (marker + exact byte count). On loopback the kernel
      copy-falls-back internally, but the FIXED counter still counts engagement.

  (b) Off-path: with the feature records at their defaults (write_zerocopy=0, no
      arena, default water mark), the same TLS transfer must leave
      write_zerocopy_fixed at 0 and be byte-identical (marker + exact byte count).

EXPERIMENTAL (write_zerocopy and the arena are both off by default).
'''

Test.ContinueOnFail = False

Test.SkipUnless(Condition.HasATSFeature('TS_USE_LINUX_IO_URING'))

# Metrics are read over the stats_over_http plugin's HTTP endpoint rather than traffic_ctl:
# io_uring test sandboxes routinely push the jsonrpc UDS path past the AF_UNIX 108-byte
# limit, so traffic_ctl cannot connect. The HTTP endpoint has no such limit.
Test.SkipUnless(Condition.PluginExists('stats_over_http.so'))

# ---- origin: cache is disabled below, so every GET is a fresh pass-through ----
server = Test.MakeOriginServer("server")

# ~512 KB body: well above the low write_zerocopy_threshold (4096), so once ciphertext
# stages in >= 64 KiB arena blocks, sends from those blocks engage send_zc_fixed.
body = ("io_uring_tls_zc." * 32768) + "END_TLS_ZC_MARKER"  # 524288 + 17 bytes
response_header = {
    "headers": "HTTP/1.1 200 OK\r\nContent-Length: {0}\r\n\r\n".format(len(body)),
    "timestamp": "1469733493.993",
    "body": body
}
request_header = {"headers": "GET /big HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}
server.addResponse("sessionfile.log", request_header, response_header)


def _make_ts(name, extra_records):
    # enable_uds=False: nothing here talks over the UDS listener, and long sandbox paths
    # overflow the AF_UNIX 108-byte sun_path limit (see io_uring_write_zerocopy_variants).
    ts = Test.MakeATSProcess(name, enable_tls=True, enable_uds=False)
    ts.addSSLfile("ssl/server.pem")
    ts.addSSLfile("ssl/server.key")
    records = {
        'proxy.config.net.io_uring.enabled': 1,
        'proxy.config.ssl.server.cert.path': ts.Variables.SSLDir,
        'proxy.config.ssl.server.private_key.path': ts.Variables.SSLDir,
        'proxy.config.ssl.client.verify.server.policy': 'DISABLED',
        # Force every request to be a pass-through server transfer.
        'proxy.config.http.cache.http': 0,
        # The origin serves one request per connection; don't pool dead origin sessions.
        'proxy.config.http.keep_alive_enabled_out': 0,
    }
    records.update(extra_records)
    ts.Disk.records_config.update(records)
    ts.Disk.ssl_multicert_yaml.AddLines(
        """
ssl_multicert:
  - dest_ip: "*"
    ssl_cert_name: server.pem
    ssl_key_name: server.key
""".split("\n"))
    ts.Disk.remap_config.AddLine(
        'map https://www.example.com:{0} http://127.0.0.1:{1}'.format(ts.Variables.ssl_port, server.Variables.Port))
    ts.Disk.plugin_config.AddLine('stats_over_http.so _stats')
    ts.Disk.diags_log.Content = Testers.ContainsExpression(
        "io_uring accept enabled for TLS port", "TLS accepts must arm on the ring, not epoll")
    return ts


# Cell 1: the full engagement stack -- write zero-copy on, low threshold, registered
# arena built, SSL write-buffer water mark raised to 256 KiB so _write_buf's blocks
# clear the arena's 64 KiB floor.
ts_zc = _make_ts(
    "ts_zc",
    {
        'proxy.config.net.io_uring.write_zerocopy': 1,
        'proxy.config.net.io_uring.write_zerocopy_threshold': 4096,
        'proxy.config.net.io_uring.fixed_arena_size': 67108864,
        'proxy.config.net.io_uring.fixed_arena_block_size': 2097152,
        'proxy.config.ssl.write_buffer_water_mark': 262144,
        # Two CQEs per zero-copy send (result + notification); size the ring for that.
        'proxy.config.io_uring.entries': 8192,
    })

# Cell 2: feature records at their defaults (write_zerocopy off, no arena, default
# water mark). Same transfer must be byte-identical with write_zerocopy_fixed pinned at 0.
ts_off = _make_ts("ts_off", {})


def _curl_body(ts):
    return ('-s -o - -k --resolve www.example.com:{0}:127.0.0.1 "https://www.example.com:{0}/big"'.format(ts.Variables.ssl_port))


def _curl_size(ts):
    return (
        '-s -o /dev/null -w "SIZE=%{{size_download}}\\n" -k --resolve www.example.com:{0}:127.0.0.1 '
        '"https://www.example.com:{0}/big"'.format(ts.Variables.ssl_port))


# =====================================================================================
# Cell 1 (ts_zc): TLS ciphertext staged in arena blocks -> send_zc_fixed engages
# =====================================================================================

tr = Test.AddTestRun("zc: large TLS fetch, body integrity (marker)")
tr.MakeCurlCommand(_curl_body(ts_zc), ts=ts_zc)
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts_zc)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "END_TLS_ZC_MARKER", "the full body must survive the arena-backed TLS serve")
tr.StillRunningAfter = ts_zc
tr.StillRunningAfter = server

tr = Test.AddTestRun("zc: large TLS fetch, body integrity (exact size)")
tr.MakeCurlCommand(_curl_size(ts_zc), ts=ts_zc)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "SIZE={0}".format(len(body)), "the TLS response must be exactly {0} bytes".format(len(body)))
tr.StillRunningAfter = ts_zc

# The load-bearing assertion: ciphertext sends came from registered arena blocks.
tr = Test.AddTestRun("zc: write_zerocopy_fixed advanced (send_zc_fixed engaged under TLS)")
tr.Processes.Default.Command = (
    'for i in $$(seq 1 50); do '
    "csv=$$(curl -s -H 'Accept: text/csv' \"http://127.0.0.1:" + str(ts_zc.Variables.port) + "/_stats/csv\"); "
    "fx=$$(echo \"$$csv\" | grep '^proxy.process.net.io_uring.write_zerocopy_fixed,' | cut -d, -f2); "
    "zc=$$(echo \"$$csv\" | grep '^proxy.process.net.io_uring.write_zerocopy,' | cut -d, -f2); "
    'if [ "$${fx:-0}" -gt 0 ]; then '
    'echo "TLS_ZC_OK fixed=$$fx zerocopy=$$zc"; exit 0; fi; '
    'sleep 0.2; done; echo "TLS_ZC_FAIL fixed=$${fx:-0} zerocopy=$${zc:-0}"; exit 1')
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.All(
    Testers.ContainsExpression("TLS_ZC_OK", "write_zerocopy_fixed must advance for the TLS transfer"),
    Testers.ExcludesExpression("TLS_ZC_FAIL", "the fixed counter must move"),
)
tr.StillRunningAfter = ts_zc

# =====================================================================================
# Cell 2 (ts_off): defaults -- same transfer, write_zerocopy_fixed stays 0
# =====================================================================================

tr = Test.AddTestRun("off: large TLS fetch, body integrity (marker)")
tr.MakeCurlCommand(_curl_body(ts_off), ts=ts_off)
tr.Processes.Default.StartBefore(ts_off)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "END_TLS_ZC_MARKER", "the full body must survive the default-config TLS serve")
tr.StillRunningAfter = ts_off

tr = Test.AddTestRun("off: large TLS fetch, body integrity (exact size)")
tr.MakeCurlCommand(_curl_size(ts_off), ts=ts_off)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "SIZE={0}".format(len(body)), "the default-config TLS response must be exactly {0} bytes".format(len(body)))
tr.StillRunningAfter = ts_off

# All sends for the transfer were submitted before the client saw the last body byte,
# so a single post-transfer read proves the counter never moved.
tr = Test.AddTestRun("off: write_zerocopy_fixed stays 0 on a default-config run")
tr.Processes.Default.Command = (
    "csv=$$(curl -s -H 'Accept: text/csv' \"http://127.0.0.1:" + str(ts_off.Variables.port) + "/_stats/csv\"); "
    "fx=$$(echo \"$$csv\" | grep '^proxy.process.net.io_uring.write_zerocopy_fixed,' | cut -d, -f2); "
    'if [ "$${fx:-0}" -eq 0 ]; then echo "OFF_OK fixed=$${fx:-0}"; exit 0; fi; '
    'echo "OFF_FAIL fixed=$$fx"; exit 1')
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.All(
    Testers.ContainsExpression("OFF_OK", "write_zerocopy_fixed must stay 0 with the feature records at defaults"),
    Testers.ExcludesExpression("OFF_FAIL", "the fixed counter must not move by default"),
)
tr.StillRunningAfter = ts_off
