'''
Zero-copy write path (IORING_OP_SEND_ZC / send_zc_fixed) + registered-buffer arena.
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
Drive the io_uring zero-copy write path (proxy.config.net.io_uring.write_zerocopy=1) and the
registered fixed-buffer arena (proxy.config.net.io_uring.fixed_arena_size>0).

Large cache hits served from disk draw their Doc buffer from the io_uring-registered arena, so
the body goes out with send_zc_fixed (the kernel DMAs straight from the pre-pinned region, no
per-send page pin). A small RAM cache plus round-robin over many distinct objects forces actual
disk reads -- hammering one object serves it from the open-read buffer and never engages the
arena. The mid-read abort phase closes the connection while a send_zc + its IORING_CQE_F_NOTIF
are still in flight, exercising the cancel/teardown path that must not recycle an arena block
the NIC is still reading (run under ASan, this is the arena-lifetime gate).

Expects: full body integrity, the write_zerocopy / write_zerocopy_fixed metrics engaged, zero
socket / non-2xx errors under load, and no crash across connection churn + mid-write aborts.

EXPERIMENTAL (write_zerocopy and the arena are off by default).
'''

Test.SkipUnless(Condition.HasATSFeature('TS_USE_LINUX_IO_URING'))
Test.SkipUnless(Condition.HasProgram("wrk", "wrk is needed for the load phase"))
# Metrics are read over the stats_over_http HTTP endpoint rather than traffic_ctl: under a deep
# sandbox root this test's jsonrpc UDS path (<sandbox>/<testdir>/<ts-name>/runtime/jsonrpc20.sock)
# overflows the AF_UNIX 108-byte sun_path limit, so ATS never starts the jsonrpc server ("File
# name too long") and every traffic_ctl query fails. The HTTP endpoint has no such limit.
Test.SkipUnless(Condition.PluginExists('stats_over_http.so'))

Test.ContinueOnFail = False

N = 16  # distinct objects; must match the round-robin Lua's default object count

# enable_uds=False: nothing here talks over the UDS listener, and under a deep sandbox root the
# default <sandbox>/<testdir>/<ts-name>/runtime/uds.socket path exceeds the AF_UNIX 108-byte
# sun_path limit. ATS silently truncates the listen path (ats_unix_set), which binds a stray
# mangled path -- or Fatals "Could not bind or listen to port 0 ... Address already in use" when
# the truncation lands exactly on the runtime/ directory (sandbox-name-length dependent).
ts = Test.MakeATSProcess("ts", enable_uds=False)
server = Test.MakeOriginServer("server")

# ~1 MiB cacheable bodies, each with a unique end marker (present only if every read landed and
# was reassembled in order). 1 MiB > the 64 KiB arena floor and > the RAM cache, so a cache hit
# disk-reads into an arena block.
base = "io_uring_zc_payload."  # 20 bytes
for i in range(N):
    body = base * 52429 + "END_OBJ_{0}_MARKER".format(i)  # ~1048596 bytes
    response_header = {
        "headers": "HTTP/1.1 200 OK\r\nCache-Control: max-age=300\r\nContent-Length: {0}\r\n\r\n".format(len(body)),
        "timestamp": "1469733493.993",
        "body": body
    }
    request_header = {
        "headers": "GET /obj/{0} HTTP/1.1\r\nHost: www.example.com\r\n\r\n".format(i),
        "timestamp": "1469733493.993",
        "body": ""
    }
    server.addResponse("sessionfile.log", request_header, response_header)

ts.Disk.records_config.update(
    {
        'proxy.config.net.io_uring.enabled': 1,
        # Close the ATS<->origin connection per request (the test's microserver serves one
        # request per connection) while leaving the cached/client-facing response keep-alive-able
        # -- so client cache hits reuse connections instead of reconnecting per request, which
        # otherwise piles up TIME_WAIT/half-closed sockets on the recycled autest listen ports.
        'proxy.config.http.keep_alive_enabled_out': 0,
        'proxy.config.net.io_uring.write_zerocopy': 1,
        # Below this many bytes a send stays on the copy path (the notification + pin cost more
        # than the copy). Low here so any large object engages zero-copy deterministically.
        'proxy.config.net.io_uring.write_zerocopy_threshold': 4096,
        # Registered fixed-buffer arena: 128 MiB split evenly across the 64K..2M size classes,
        # so the 2 MiB class gets ~10 blocks. Cache disk reads >= 64 KiB draw their Doc buffer
        # from here, enabling send_zc_fixed. A block must hold the whole on-disk Doc (Doc struct
        # + marshalled header + body), so the ~1 MiB objects land in the 2 MiB class -- a 1 MiB
        # top class would reject them (req_bytes > block_size) and silently fall back to a heap
        # buffer (no send_zc_fixed).
        'proxy.config.net.io_uring.fixed_arena_size': 134217728,
        'proxy.config.net.io_uring.fixed_arena_block_size': 2097152,
        # Two CQEs per zero-copy send (result + notification); size the ring for that under load.
        'proxy.config.io_uring.entries': 8192,
        # RAM cache smaller than one object so every hit is a disk read into an arena block.
        'proxy.config.cache.ram_cache.size': 524288,
        # Cache the objects so the load phase hammers ATS, not the Python origin.
        'proxy.config.http.cache.required_headers': 0,
    })

ts.Disk.remap_config.AddLine('map http://www.example.com http://127.0.0.1:{0}'.format(server.Variables.Port))
ts.Disk.plugin_config.AddLine('stats_over_http.so _stats')

ts.Disk.diags_log.Content = Testers.ContainsExpression(
    "io_uring NetVConnection enabled", "the io_uring NetVConnection path must be active")

# Phase 1: warm the cache -- one full GET of each object (cache miss -> origin read -> disk write).
tr = Test.AddTestRun("warm the cache: GET each object once (miss -> disk write)")
tr.Processes.Default.Command = (
    'for i in $$(seq 0 {n}); do '
    'curl -s -o /dev/null -w "obj/$$i %{{http_code}}\\n" '
    '"http://127.0.0.1:{port}/obj/$$i" -H "Host: www.example.com"; '
    'done; echo WARM_DONE'.format(n=N - 1, port=ts.Variables.port))
tr.Processes.Default.StartBefore(server)
tr.Processes.Default.StartBefore(ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.All(
    Testers.ContainsExpression("WARM_DONE", "all warm requests issued"),
    Testers.ExcludesExpression(r"obj/\d+ [^2]\d\d", "every warm request must be 2xx"),
)
tr.StillRunningAfter = ts
tr.StillRunningAfter = server

# Phase 2: cache hit served zero-copy, full body integrity end-to-end.
tr = Test.AddTestRun("cache hit served zero-copy: full body integrity")
tr.MakeCurlCommand('-s -o - "http://127.0.0.1:{0}/obj/0" -H "Host: www.example.com"'.format(ts.Variables.port), ts=ts)
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "END_OBJ_0_MARKER", "the full ~1 MiB body must survive the zero-copy serve")
tr.StillRunningAfter = ts

# Phase 3: round-robin load -- forces disk reads (arena send_zc_fixed) plus connection churn.
tr = Test.AddTestRun("round-robin load: disk reads -> arena send_zc_fixed + churn")
# The Lua round-robins over its own default of 16 objects (== N); keep them in sync. (autest
# exec's a command with no shell operators directly, so an env-var prefix can't be used here.)
tr.Processes.Default.Command = (
    'wrk -t 4 -c 16 -d 5s --latency '
    '-s {testdir}/io_uring_write_zerocopy_rr.lua '
    'http://127.0.0.1:{port}/'.format(testdir=Test.TestDirectory, port=ts.Variables.port))
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.All(
    Testers.ContainsExpression("requests in", "the load run must complete"),
    Testers.ExcludesExpression("Socket errors", "no socket errors under load"),
    Testers.ExcludesExpression("Non-2xx or 3xx responses", "every response must be 2xx under load"),
)
tr.StillRunningAfter = ts

# Phase 4: abort mid-read -- close while a send_zc + its NOTIF are in flight (the arena-lifetime
# / cancel-teardown gate; under ASan a recycled-while-in-flight block trips here).
tr = Test.AddTestRun("abort mid-read: close while send_zc + NOTIF in flight")
tr.Processes.Default.Command = (
    'for r in $$(seq 1 24); do '
    'curl -s "http://127.0.0.1:{port}/obj/$$((r % {n}))" -H "Host: www.example.com" '
    '| head -c 4096 >/dev/null || true; done; echo ABORT_DONE'.format(port=ts.Variables.port, n=N))
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression("ABORT_DONE", "the abort loop must complete")
tr.StillRunningAfter = ts

# Phase 5: the zero-copy + arena metrics must have engaged. write_zerocopy counts every ZC send;
# write_zerocopy_fixed counts the arena-backed ones (disk-read Doc buffers). Wall-clock deadline
# loop over the stats_over_http CSV endpoint: a transient HTTP failure (endpoint not yet serving)
# leaves the values empty and is retried rather than misread as a genuine zero. The strict
# "-gt 0" assertions are unchanged, so an unmoved metric still fails.
tr = Test.AddTestRun("zero-copy + arena metrics engaged")
tr.Processes.Default.Command = (
    'deadline=$$(( $$(date +%s) + 60 )); '
    'while [ $$(date +%s) -lt $$deadline ]; do '
    "csv=$$(curl -s --max-time 5 -H 'Accept: text/csv' \"http://127.0.0.1:" + str(ts.Variables.port) + "/_stats/csv\"); "
    "zc=$$(printf '%s' \"$$csv\" | grep '^proxy.process.net.io_uring.write_zerocopy,' | cut -d, -f2); "
    "fx=$$(printf '%s' \"$$csv\" | grep '^proxy.process.net.io_uring.write_zerocopy_fixed,' | cut -d, -f2); "
    'if [ "$${zc:-0}" -gt 0 ] && [ "$${fx:-0}" -gt 0 ] 2>/dev/null; then echo "ZC_OK zerocopy=$$zc fixed=$$fx"; exit 0; fi; '
    'sleep 0.3; done; echo ZC_FAIL; '
    "printf '%s\\n' \"$$csv\" | grep '^proxy.process.net.io_uring' || true; exit 1")
tr.TimeOut = 90
tr.Processes.Default.ReturnCode = 0
tr.Processes.Default.Streams.stdout = Testers.ContainsExpression(
    "ZC_OK", "both write_zerocopy and write_zerocopy_fixed must have engaged")
tr.StillRunningAfter = ts
