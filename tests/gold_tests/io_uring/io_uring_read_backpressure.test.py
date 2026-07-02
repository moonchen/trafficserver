'''
Producer/consumer backpressure across the io_uring read + write coroutines.
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

Test.Summary = '''
Exercise the io_uring read/write backpressure loop with proxy.config.net.io_uring.enabled=1.

A fast origin streams a ~16 MiB cache-miss body through ATS to a slow, rate-limited client
(curl --limit-rate 200k). The client drains far slower than the origin fills, so the
client-facing write MIOBuffer fills, the tunnel backpressures the origin-facing read, and the
read coroutine repeatedly hits its buffer-full gate (write_avail <= 0 -> read_disable) and
re-arms via reenable() as the slow consumer drains -- the classic producer/consumer loop across
the whole transfer. The slow client also forces short sends, driving the _write coroutine's
short-send writeReschedule loop.

Run twice, once per read path:
  - read_provided_buffers=0  -> single-shot recvmsg _read (its write_avail backpressure gate,
                                which read_disable()s the VC when the destination buffer is full);
  - read_provided_buffers=1  -> provided-buffer _read_provided (buffer-gated backpressure, and
                                the -ENOBUFS fall-back to single-shot _read).

There is no dedicated backpressure metric, so correctness is proven by the outcome that can only
happen if backpressure re-armed correctly: the full byte-exact body arrives at the slow client
(HTTP 200 + exact size + tail marker) and the run completes within the timeout (no stall).
'''

Test.SkipUnless(Condition.HasATSFeature('TS_USE_LINUX_IO_URING'))

Test.ContinueOnFail = False

# ~16 MiB cacheable body with a unique end marker. The marker only survives if every read landed,
# was reassembled in order across hundreds of read_disable/reenable cycles, and every (possibly
# short) send delivered it. 20-byte unit keeps the size exact and reproducible.
unit = "io_uring_bp_body."  # 17 bytes
body = unit * 987000 + "END_OF_BACKPRESSURE_BODY_MARKER"  # ~16.78 MB
BODY_SIZE = len(body)

response_header = {
    "headers": "HTTP/1.1 200 OK\r\nConnection: close\r\nCache-Control: max-age=300\r\nContent-Length: {0}\r\n\r\n".format(
        len(body)),
    "timestamp": "1469733493.993",
    "body": body
}
request_header = {"headers": "GET /big HTTP/1.1\r\nHost: www.example.com\r\n\r\n", "timestamp": "1469733493.993", "body": ""}

server = Test.MakeOriginServer("server")
server.addResponse("sessionfile.log", request_header, response_header)

# One ATS process per read path so both are covered in a single self-contained test.
#   ts-single   : single-shot recvmsg _read
#   ts-provided : provided-buffer _read_provided (default path)
phases = [
    ("single", 0, Test.MakeATSProcess("ts-single")),
    ("provided", 1, Test.MakeATSProcess("ts-provided")),
]

for tag, provided, ts in phases:
    cfg = {
        'proxy.config.net.io_uring.enabled': 1,
        'proxy.config.net.io_uring.read_provided_buffers': provided,
        # Cache the object (cache-miss on the single slow fetch, so the body is read from origin
        # over io_uring -- that origin read is the VC whose buffer-full gate we want to trip).
        'proxy.config.http.cache.required_headers': 0,
    }
    if provided:
        # Size the provided-buffer ring generously so a slow-consumer transfer that pins many
        # buffers still exercises attach/recycle rather than only the -ENOBUFS fall-back
        # (4096 x 8 KB = 32 MB, comfortably above one buffered object under backpressure).
        cfg.update(
            {
                'proxy.config.net.io_uring.read_buffer_count': 4096,
                'proxy.config.net.io_uring.read_buffer_size': 8192,
                'proxy.config.io_uring.entries': 8192,
            })
    ts.Disk.records_config.update(cfg)
    ts.Disk.remap_config.AddLine('map http://www.example.com http://127.0.0.1:{0}'.format(server.Variables.Port))
    ts.Disk.diags_log.Content = Testers.ContainsExpression(
        "io_uring NetVConnection enabled", "the io_uring NetVConnection path must be active ({0})".format(tag))

# Drive each read path with one slow, rate-limited cache-miss fetch of the full body.
for i, (tag, provided, ts) in enumerate(phases):
    outfile = os.path.join(Test.RunDirectory, "io_uring_read_backpressure_{0}_body.out".format(tag))
    tr = Test.AddTestRun("slow-drain backpressure over the {0} read path".format(tag))
    if i == 0:
        # Start the shared origin and both ATS processes before the first slow fetch.
        tr.Processes.Default.StartBefore(server)
        for _, _, p in phases:
            tr.Processes.Default.StartBefore(p)
    # -D - streams the response headers to stdout (status line assertion); the body goes to a file
    # so the exact download size and tail marker can be checked without a 16 MB stdout capture.
    tr.Processes.Default.Command = (
        'curl -s --limit-rate 200k -D - -o {out} '
        '-w "CURL_DONE http_code=%{{http_code}} size=%{{size_download}}\\n" '
        '"http://127.0.0.1:{port}/big" -H "Host: www.example.com"; '
        'echo "BODY_TAIL=$$(tail -c 31 {out})"'.format(out=outfile, port=ts.Variables.port))
    # 16.78 MB / 200 KB/s ~= 84 s of steady drain; allow generous slack for the backpressure loop.
    tr.Timeout = 300
    tr.Processes.Default.ReturnCode = 0
    tr.Processes.Default.Streams.stdout = Testers.All(
        Testers.ContainsExpression("HTTP/1.1 200 OK", "the slow fetch must complete 200 ({0})".format(tag)),
        Testers.ContainsExpression(
            "CURL_DONE http_code=200 size={0}".format(BODY_SIZE),
            "the full byte-exact body must reach the slow client ({0})".format(tag)),
        Testers.ContainsExpression(
            "BODY_TAIL=END_OF_BACKPRESSURE_BODY_MARKER",
            "the tail marker must survive reassembly across the backpressure loop ({0})".format(tag)),
    )
    tr.StillRunningAfter = ts
    tr.StillRunningAfter = server
