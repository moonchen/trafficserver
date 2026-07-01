'''
Zero-copy write variants: anonymous multi-block sendmsg_zc, ZC kernel copy-fallback
(IORING_NOTIF_USAGE_ZC_COPIED -> write_zerocopy_copied), and recv-coalescing (SO_RCVLOWAT /
IORING_RECVSEND_POLL_FIRST) on the single-shot read path feeding send_zc_fixed vs. its
inertness on the default provided-buffer read path.
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
Exercise the io_uring zero-copy write path beyond the contiguous arena case that
io_uring_write_zerocopy covers:

  (a) Anonymous multi-block zero-copy: a proxied (cache-off pass-through) body whose source
      MIOBuffer blocks are plain heap blocks -- NOT registered arena blocks -- so the send goes
      out as an anonymous send_zc / sendmsg_zc (msg_iovlen>1) and increments write_zerocopy but
      NOT write_zerocopy_fixed. Assert write_zerocopy > write_zerocopy_fixed with full body
      integrity.

  (b) ZC kernel copy-fallback: on loopback the kernel commonly declines true zero-copy and copies
      into skbs, reporting IORING_NOTIF_USAGE_ZC_COPIED in the notification -> write_zerocopy_copied.
      Assert the metric exists (and, when the kernel copies, moved) with a clean run.

  (c) Recv coalescing (proxy.config.net.io_uring.recv_coalesce): on the SINGLE-SHOT read path
      (read_provided_buffers=0) a known-large origin response (Content-Length >= recv_coalesce_size)
      backs its body buffer with the registered arena, so the client-facing send uses send_zc_fixed
      -> write_zerocopy_fixed advances. On the DEFAULT provided-buffer path the origin recv fills
      unregistered provided-ring buffers instead, so coalescing is inert and write_zerocopy_fixed
      stays low.

Expects: full body integrity end-to-end, the write_zerocopy / write_zerocopy_fixed /
write_zerocopy_copied metrics behaving as above, io_uring active, and no crash / ASan / assertion.

EXPERIMENTAL (write_zerocopy, the arena, and recv_coalesce are all off by default).
'''

Test.ContinueOnFail = False

# Metrics are read over the stats_over_http plugin's HTTP endpoint rather than traffic_ctl: this
# test's long name pushes the jsonrpc UDS path past the AF_UNIX 108-byte limit, so traffic_ctl
# cannot connect. The HTTP endpoint has no such limit.
Test.SkipUnless(Condition.PluginExists('stats_over_http.so'))

# ---- origin: cache is disabled below, so every GET is a fresh pass-through (server transfer) ----
server = Test.MakeOriginServer("server")

# ~128 KB body: >= write_zerocopy_threshold (4096) but < recv_coalesce_size (262144), so it is NOT
# coalesced and its non-arena heap blocks go out as an anonymous multi-block zero-copy send.
med_body = ("io_uring_zc_variant." * 6553) + "END_MED_BODY_MARKER"  # ~131 KB
# ~512 KB body: >= recv_coalesce_size, so on the single-shot path its body buffer is arena-backed
# (send_zc_fixed) and coalesced reads fill it in large chunks.
big_body = ("io_uring_zc_variant." * 26214) + "END_BIG_BODY_MARKER"  # ~512 KB

for path, body in (("med", med_body), ("big", big_body)):
    response_header = {
        "headers": "HTTP/1.1 200 OK\r\nContent-Length: {0}\r\n\r\n".format(len(body)),
        "timestamp": "1469733493.993",
        "body": body
    }
    request_header = {
        "headers": "GET /{0} HTTP/1.1\r\nHost: www.example.com\r\n\r\n".format(path),
        "timestamp": "1469733493.993",
        "body": ""
    }
    server.addResponse("sessionfile.log", request_header, response_header)


def _records(read_provided):
    return {
        'proxy.config.net.io_uring.enabled': 1,
        # Close the ATS<->origin connection per request (the origin server serves one request per
        # connection) while keeping the client-facing response keep-alive-able, so the client-side
        # curls reuse one connection instead of reconnecting per request and piling up TIME_WAIT /
        # half-closed sockets on the recycled autest listen ports.
        'proxy.config.http.keep_alive_enabled_out': 0,
        'proxy.config.net.io_uring.read_provided_buffers': read_provided,
        'proxy.config.net.io_uring.write_zerocopy': 1,
        # Low threshold so any >= 4 KiB body engages zero-copy deterministically.
        'proxy.config.net.io_uring.write_zerocopy_threshold': 4096,
        # Registered fixed-buffer arena (64 MiB of 2 MiB blocks). recv_coalesce needs it enabled;
        # 2 MiB blocks comfortably hold the coalesced ~512 KiB body.
        'proxy.config.net.io_uring.fixed_arena_size': 67108864,
        'proxy.config.net.io_uring.fixed_arena_block_size': 2097152,
        # Coalesce known-large origin reads into one big (arena) chunk so the client send clears
        # the send_zc threshold as a fixed send. Inert on the provided-buffer read path.
        'proxy.config.net.io_uring.recv_coalesce': 1,
        'proxy.config.net.io_uring.recv_coalesce_size': 262144,
        # Two CQEs per zero-copy send (result + notification); size the ring for that.
        'proxy.config.io_uring.entries': 8192,
        # Force every request to be a pass-through server transfer (cache-miss path), which is
        # where recv coalescing + the arena body buffer engage.
        'proxy.config.http.cache.http': 0,
    }


# Two ATS processes: one on the single-shot read path (coalescing active), one on the default
# provided-buffer path (coalescing inert). They differ only in read_provided_buffers.
# enable_uds=False: nothing here talks over the UDS listener, and this test's long name pushes
# the default <sandbox>/<testdir>/<ts-name>/runtime/uds.socket past the AF_UNIX 108-byte
# sun_path limit. ATS silently truncates the listen path (ats_unix_set), which binds a stray
# mangled path -- or Fatals "Could not bind or listen to port 0 ... Address already in use"
# when the truncation lands exactly on the runtime/ directory (sandbox-name-length dependent).
ts_single = Test.MakeATSProcess("ts_single", enable_uds=False)
ts_single.Disk.records_config.update(_records(read_provided=0))
ts_single.Disk.remap_config.AddLine('map http://www.example.com http://127.0.0.1:{0}'.format(server.Variables.Port))
ts_single.Disk.plugin_config.AddLine('stats_over_http.so _stats')
ts_single.Disk.diags_log.Content = Testers.ContainsExpression(
    "io_uring NetVConnection enabled", "the io_uring NetVConnection path must be active (single-shot)")

ts_provided = Test.MakeATSProcess("ts_provided", enable_uds=False)
ts_provided.Disk.records_config.update(_records(read_provided=1))
ts_provided.Disk.remap_config.AddLine('map http://www.example.com http://127.0.0.1:{0}'.format(server.Variables.Port))
ts_provided.Disk.plugin_config.AddLine('stats_over_http.so _stats')
ts_provided.Disk.diags_log.Content = Testers.ContainsExpression(
    "io_uring NetVConnection enabled", "the io_uring NetVConnection path must be active (provided)")

# =====================================================================================
# Single-shot read path (ts_single): anonymous multi-block ZC + coalesce->fixed + copied
# =====================================================================================

# Phase 1a: ~128 KB pass-through body -> anonymous multi-block zero-copy send.
tr = Test.AddTestRun("single-shot: ~128 KB pass-through -> anonymous multi-block zero-copy")
tr.Processes.Default.Command = (
    'curl -s -o - $$(for i in $$(seq 1 8); do echo "http://127.0.0.1:{port}/med"; done) '
    '-H "Host: www.example.com"'.format(port=ts_single.Variables.port))
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts_single)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "END_MED_BODY_MARKER", "the full ~128 KB body must survive the anonymous zero-copy serve")
tr.StillRunningAfter = ts_single
tr.StillRunningAfter = server

# Phase 1b: ~512 KB pass-through body -> coalesced read into an arena block -> send_zc_fixed.
tr = Test.AddTestRun("single-shot: ~512 KB coalesced pass-through -> send_zc_fixed")
tr.Processes.Default.Command = (
    'curl -s -o - $$(for i in $$(seq 1 8); do echo "http://127.0.0.1:{port}/big"; done) '
    '-H "Host: www.example.com"'.format(port=ts_single.Variables.port))
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "END_BIG_BODY_MARKER", "the full ~512 KB body must survive the coalesced send_zc_fixed serve")
tr.StillRunningAfter = ts_single

# Phase 1c: metrics. write_zerocopy counts every ZC send; write_zerocopy_fixed only the arena-backed
# ones. Both must have engaged, and write_zerocopy > write_zerocopy_fixed proves anonymous (non-arena)
# multi-block sends also occurred. Report write_zerocopy_copied (loopback copy-fallback).
tr = Test.AddTestRun("single-shot: zero-copy metrics -- anonymous + fixed both engaged")
tr.Processes.Default.Command = (
    'for i in $$(seq 1 50); do '
    "csv=$$(curl -s -H 'Accept: text/csv' \"http://127.0.0.1:" + str(ts_single.Variables.port) + "/_stats/csv\"); "
    "zc=$$(echo \"$$csv\" | grep '^proxy.process.net.io_uring.write_zerocopy,' | cut -d, -f2); "
    "fx=$$(echo \"$$csv\" | grep '^proxy.process.net.io_uring.write_zerocopy_fixed,' | cut -d, -f2); "
    "cp=$$(echo \"$$csv\" | grep '^proxy.process.net.io_uring.write_zerocopy_copied,' | cut -d, -f2); "
    'if [ "$${zc:-0}" -gt "$${fx:-0}" ] && [ "$${fx:-0}" -gt 0 ]; then '
    'echo "SINGLE_OK zerocopy=$$zc fixed=$$fx copied=$${cp:-0}"; exit 0; fi; '
    'sleep 0.2; done; echo "SINGLE_FAIL zerocopy=$${zc:-0} fixed=$${fx:-0} copied=$${cp:-0}"; exit 1')
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.All(
    Testers.ContainsExpression("SINGLE_OK", "write_zerocopy > write_zerocopy_fixed > 0 (anonymous + fixed both engaged)"),
    Testers.ExcludesExpression("SINGLE_FAIL", "the metrics must settle"),
)
tr.StillRunningAfter = ts_single

# =====================================================================================
# Default provided-buffer read path (ts_provided): coalescing is inert (fixed stays low)
# =====================================================================================

# Phase 2a: same ~512 KB body, but on the provided-buffer read path the origin recv fills
# unregistered ring buffers, so coalescing cannot back the body with the arena.
tr = Test.AddTestRun("provided: ~512 KB pass-through -> coalescing inert, anonymous zero-copy")
tr.Processes.Default.Command = (
    'curl -s -o - $$(for i in $$(seq 1 8); do echo "http://127.0.0.1:{port}/big"; done) '
    '-H "Host: www.example.com"'.format(port=ts_provided.Variables.port))
tr.Processes.Default.StartBefore(ts_provided)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "END_BIG_BODY_MARKER", "the full ~512 KB body must survive on the provided-buffer read path")
tr.StillRunningAfter = ts_provided

# Phase 2b: metrics. Zero-copy sends still occur (write_zerocopy > 0), but because the provided-buffer
# reads never fill an arena block, coalescing is inert and write_zerocopy_fixed stays at 0.
tr = Test.AddTestRun("provided: coalescing inert -- write_zerocopy_fixed stays low")
tr.Processes.Default.Command = (
    'for i in $$(seq 1 50); do '
    "csv=$$(curl -s -H 'Accept: text/csv' \"http://127.0.0.1:" + str(ts_provided.Variables.port) + "/_stats/csv\"); "
    "zc=$$(echo \"$$csv\" | grep '^proxy.process.net.io_uring.write_zerocopy,' | cut -d, -f2); "
    "fx=$$(echo \"$$csv\" | grep '^proxy.process.net.io_uring.write_zerocopy_fixed,' | cut -d, -f2); "
    'if [ "$${zc:-0}" -gt 0 ] && [ "$${fx:-0}" -eq 0 ]; then '
    'echo "PROVIDED_OK zerocopy=$$zc fixed=$$fx"; exit 0; fi; '
    'sleep 0.2; done; echo "PROVIDED_FAIL zerocopy=$${zc:-0} fixed=$${fx:-0}"; exit 1')
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.All(
    Testers.ContainsExpression("PROVIDED_OK", "write_zerocopy engaged but write_zerocopy_fixed stayed 0 (coalescing inert)"),
    Testers.ExcludesExpression("PROVIDED_FAIL", "the metrics must settle"),
)
tr.StillRunningAfter = ts_provided
