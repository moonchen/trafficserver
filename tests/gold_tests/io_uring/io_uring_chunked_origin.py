#!/usr/bin/env python3
'''
Raw-socket HTTP/1.1 origin for io_uring_chunked.test.py.

Gives byte-exact control over response framing (Transfer-Encoding: chunked) and
over request-body reads (chunked *or* Content-Length), which the stock
MakeOriginServer cannot do. Handles Expect: 100-continue on the origin side too,
so the test works whether ATS relays the Expect to origin or answers it itself.

Routes (by method):
  GET  ... -> a Transfer-Encoding: chunked response: several chunks + 0-chunk
              terminator, reassembling to a body that ends in CHUNKED_END_MARKER.
  POST ... -> read the whole request body (dechunking if chunked), then echo it
              back verbatim with a Content-Length so the client can verify the
              full body made the round trip byte-for-byte.

Keep-alive is supported (one thread per connection, looping until the peer
closes), so ATS origin-session reuse does not wedge the origin.
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

import socket
import sys
import threading

CHUNKED_END_MARKER = b"CHUNKED_END_MARKER"


class LineSocket:
    """Buffered reader over a blocking socket: readline + read(n)."""

    def __init__(self, conn):
        self._conn = conn
        self._buf = b""

    def readline(self):
        while b"\r\n" not in self._buf:
            data = self._conn.recv(65536)
            if not data:
                # Connection closed; return whatever is left (possibly b"").
                line, self._buf = self._buf, b""
                return line
            self._buf += data
        line, self._buf = self._buf.split(b"\r\n", 1)
        return line + b"\r\n"

    def read(self, n):
        while len(self._buf) < n:
            data = self._conn.recv(65536)
            if not data:
                break
            self._buf += data
        out, self._buf = self._buf[:n], self._buf[n:]
        return out


def read_headers(rs):
    """Return (request_line, {lower_header: value}) or (None, None) on EOF."""
    request_line = rs.readline()
    if not request_line.endswith(b"\r\n") or request_line == b"\r\n":
        return None, None
    headers = {}
    while True:
        line = rs.readline()
        if line in (b"\r\n", b""):
            break
        if b":" in line:
            k, v = line.split(b":", 1)
            headers[k.strip().lower()] = v.strip()
    return request_line, headers


def read_chunked_body(rs):
    """Dechunk a Transfer-Encoding: chunked request body; return the raw bytes."""
    body = b""
    while True:
        size_line = rs.readline().strip()
        if not size_line:
            break
        # A chunk-size may carry chunk-extensions after a ';'.
        size = int(size_line.split(b";", 1)[0], 16)
        if size == 0:
            # Consume the (possibly empty) trailer section up to the blank line.
            while True:
                trailer = rs.readline()
                if trailer in (b"\r\n", b""):
                    break
            break
        body += rs.read(size)
        rs.read(2)  # trailing CRLF after each chunk
    return body


def read_body(rs, headers):
    te = headers.get(b"transfer-encoding", b"")
    if b"chunked" in te.lower():
        return read_chunked_body(rs)
    cl = headers.get(b"content-length")
    if cl is not None:
        return rs.read(int(cl))
    return b""


def send_chunked_response(conn):
    """A chunked response that dechunks to <prefix...>CHUNKED_END_MARKER."""
    conn.sendall(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Cache-Control: no-store\r\n"
        b"\r\n")
    # Several distinctly sized chunks so the read path reassembles across recvs.
    chunks = [b"io_uring_chunked_resp." * 200 for _ in range(6)]
    chunks.append(CHUNKED_END_MARKER)
    for c in chunks:
        conn.sendall(b"%x\r\n" % len(c) + c + b"\r\n")
    conn.sendall(b"0\r\n\r\n")


def send_echo_response(conn, body):
    conn.sendall(
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: application/octet-stream\r\n"
        b"Cache-Control: no-store\r\n"
        b"Content-Length: %d\r\n"
        b"\r\n" % len(body))
    conn.sendall(body)


def handle_conn(conn):
    try:
        rs = LineSocket(conn)
        while True:
            request_line, headers = read_headers(rs)
            if request_line is None:
                break
            method = request_line.split(b" ", 1)[0].upper()

            # Honor Expect: 100-continue on the origin side too (harmless if ATS
            # already answered it and stripped the header).
            expect = headers.get(b"expect", b"")
            if b"100-continue" in expect.lower():
                conn.sendall(b"HTTP/1.1 100 Continue\r\n\r\n")

            body = read_body(rs, headers)

            if method == b"GET":
                send_chunked_response(conn)
            else:
                send_echo_response(conn, body)
    except (ConnectionError, OSError):
        pass
    finally:
        try:
            conn.close()
        except OSError:
            pass


def main():
    host = sys.argv[1]
    port = int(sys.argv[2])
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((host, port))
    ls.listen(128)
    print("io_uring_chunked origin ready", flush=True)
    while True:
        conn, _ = ls.accept()
        threading.Thread(target=handle_conn, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
