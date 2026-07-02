#!/usr/bin/env python3
"""Drip origin for io_uring_drip_origin.test.py.

Serves a fixed, known body with a correct Content-Length, but trickles the body
back to ATS in small (64-byte) pieces with a short sleep between each piece.

Each io_uring recv on the ATS origin VC therefore returns far fewer bytes than it
attempted (a short read), forcing the read coroutine to re-arm and block in the
kernel for the next piece -- the short-read re-arm branch in _read (mirrored in
_read_provided) that a bulk-send origin never exercises. The full body
must still be reassembled in order (no premature EOS) across the many recvs.
"""
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
import time

CHUNK_SIZE = 64
CHUNK_DELAY = 0.05  # seconds between pieces

# Deterministic body: numbered segments so any out-of-order / dropped bytes would
# corrupt the tail, followed by a unique end marker that can only appear if every
# short read landed and was reassembled in order.
BODY = ("".join("drip{:04d}.".format(i) for i in range(80)) + "END_OF_DRIP_BODY_MARKER").encode("ascii")

RESPONSE_HEADERS = ("HTTP/1.1 200 OK\r\n"
                    "Connection: close\r\n"
                    "Content-Length: {0}\r\n"
                    "\r\n").format(len(BODY)).encode("ascii")


def handle(conn):
    try:
        # Drain the request headers.
        buf = b""
        while b"\r\n\r\n" not in buf:
            data = conn.recv(4096)
            if not data:
                return
            buf += data
        # Send the response headers, then trickle the body in small pieces.
        conn.sendall(RESPONSE_HEADERS)
        for off in range(0, len(BODY), CHUNK_SIZE):
            conn.sendall(BODY[off:off + CHUNK_SIZE])
            time.sleep(CHUNK_DELAY)
    finally:
        try:
            conn.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        conn.close()


def main():
    port = int(sys.argv[1])
    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", port))
    ls.listen(128)
    print("drip server ready", flush=True)
    while True:
        conn, _ = ls.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    main()
