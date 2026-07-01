#!/usr/bin/env python3
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
'''
Raw HTTP/1.1 pipelining client. curl cannot pipeline (it waits for each
response before sending the next request); this client writes TWO requests
back-to-back in a SINGLE send() on one connection, then reads.

The point is to make ATS read request /a, dispatch it, and have the bytes of
request /b already sitting in the inbound socket (and, on the io_uring
provided-buffer path, already pulled into a kernel-filled provided buffer that
must be HELD and REPLAYED across the transaction boundary). If ATS desyncs the
pipelined stream --- consuming any of /b's bytes into /a, or dropping the held
provided buffer --- the strict Content-Length framing parse below misaligns and
the test fails.

argv: <port> <marker_a> <marker_b>
Exit 0 and print PIPELINE_OK only if BOTH responses come back, in order, each
200, each body exactly its own marker payload with no cross-contamination.
'''
import socket
import sys

port = int(sys.argv[1])
marker_a = sys.argv[2].encode()
marker_b = sys.argv[3].encode()

# Request /a is keep-alive so ATS holds the inbound connection open for the
# pipelined /b; request /b carries Connection: close so ATS closes after
# responding to it, giving us a clean EOF to read to.
req_a = ("GET /a HTTP/1.1\r\n"
         "Host: www.example.com\r\n"
         "Connection: keep-alive\r\n"
         "\r\n")
req_b = ("GET /b HTTP/1.1\r\n"
         "Host: www.example.com\r\n"
         "Connection: close\r\n"
         "\r\n")

s = socket.create_connection(("127.0.0.1", port), timeout=15)
s.settimeout(15)
# One send(): both requests hit the wire together (true pipelining).
s.sendall((req_a + req_b).encode())

buf = b""
try:
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        buf += chunk
except socket.timeout:
    print("FAIL: timed out reading pipelined responses; got {0} bytes".format(len(buf)))
    print(repr(buf[:512]))
    sys.exit(1)
finally:
    s.close()


def parse_one(data, off):
    '''Parse one HTTP/1.1 response starting at off. Returns (status_line, body, next_off).'''
    hdr_end = data.find(b"\r\n\r\n", off)
    if hdr_end < 0:
        raise ValueError("no header terminator at offset {0}".format(off))
    header = data[off:hdr_end]
    lines = header.split(b"\r\n")
    status = lines[0]
    clen = None
    chunked = False
    for line in lines[1:]:
        low = line.lower()
        if low.startswith(b"content-length:"):
            clen = int(line.split(b":", 1)[1].strip())
        elif low.startswith(b"transfer-encoding:") and b"chunked" in low:
            chunked = True
    body_start = hdr_end + 4
    if clen is not None:
        body = data[body_start:body_start + clen]
        if len(body) != clen:
            raise ValueError("short body: have {0} want {1}".format(len(body), clen))
        return status, body, body_start + clen
    if chunked:
        # Minimal de-chunk to the terminating 0-size chunk.
        body = b""
        pos = body_start
        while True:
            nl = data.find(b"\r\n", pos)
            if nl < 0:
                raise ValueError("truncated chunk size")
            size = int(data[pos:nl], 16)
            pos = nl + 2
            if size == 0:
                return status, body, data.find(b"\r\n\r\n", pos) + 4 if data.find(b"\r\n\r\n", pos) >= 0 else pos + 2
            body += data[pos:pos + size]
            pos += size + 2
    raise ValueError("response has neither Content-Length nor chunked framing")


try:
    status1, body1, off1 = parse_one(buf, 0)
    status2, body2, off2 = parse_one(buf, off1)
except ValueError as e:
    print("FAIL: framing parse error ({0}) --- pipelined stream desynced".format(e))
    print(repr(buf[:1024]))
    sys.exit(1)

ok = True
if not status1.startswith(b"HTTP/1.1 200"):
    print("FAIL: first response not 200: {0!r}".format(status1))
    ok = False
if not status2.startswith(b"HTTP/1.1 200"):
    print("FAIL: second response not 200: {0!r}".format(status2))
    ok = False

# Response 1 must be /a's body ONLY; response 2 must be /b's body ONLY. Any
# cross-contamination means bytes of one request were consumed into the other.
if marker_a not in body1:
    print("FAIL: /a marker missing from first response body")
    ok = False
if marker_b in body1:
    print("FAIL: /b bytes leaked into the first (/a) response --- pipeline desync")
    ok = False
if marker_b not in body2:
    print("FAIL: /b marker missing from second response body")
    ok = False
if marker_a in body2:
    print("FAIL: /a bytes leaked into the second (/b) response --- pipeline desync")
    ok = False

# Both responses must fit exactly in what we read (no leftover/truncation).
if off2 != len(buf):
    print("FAIL: {0} trailing bytes after the two responses (framing off)".format(len(buf) - off2))
    ok = False

if ok:
    print(
        "PIPELINE_OK: two responses on one connection, in order, correctly framed "
        "(body1={0}B body2={1}B)".format(len(body1), len(body2)))
    sys.exit(0)
sys.exit(1)
