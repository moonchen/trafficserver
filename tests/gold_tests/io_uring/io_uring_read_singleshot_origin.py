#!/usr/bin/env python3
"""A raw origin that returns a close-delimited HTTP body (no Content-Length).

The response terminates by closing the socket, so the proxy's origin read
observes recv() == 0 (a clean EOS) as the body-length signal. This drives the
io_uring single-shot _read() r==0 clean-EOS arm.
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

import argparse
import socket
import sys

# A close-delimited body with distinct start/end markers. Both markers only
# appear in the client output if the whole body was read up to the FIN (r==0)
# and reassembled in order.
BODY = ("CLOSE_DELIMITED_START" + ("io_uring_close_payload." * 2048) + "CLOSE_DELIMITED_END").encode("utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("address", help="Address to listen on")
    parser.add_argument("port", type=int, help="The port to listen on")
    return parser.parse_args()


def read_request_headers(sock: socket.socket) -> bytes:
    """Read until the end of the request headers (blank line)."""
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
    return buf


def main() -> int:
    args = parse_args()
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind((args.address, args.port))
    listener.listen(16)
    print(f"Listening on {args.address}:{args.port}", flush=True)

    # No Content-Length and Connection: close: the body length is signalled by
    # the FIN below, which the proxy sees as recv() == 0.
    response = b"HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n" + BODY

    while True:
        conn, _ = listener.accept()
        with conn:
            request = read_request_headers(conn)
            if not request:
                # A readiness probe (PortOpenv4) or an aborted connection: no
                # request was sent, so there is nothing to serve.
                continue
            try:
                conn.sendall(response)
                # Half-close the write side to send FIN, delimiting the body.
                conn.shutdown(socket.SHUT_WR)
            except OSError:
                # Peer went away mid-send; just move on to the next connection.
                pass

    return 0


if __name__ == "__main__":
    sys.exit(main())
