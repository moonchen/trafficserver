#!/usr/bin/env python3
"""Origin for io_uring_post_abort: replies early mid-POST, or RSTs mid-POST.

Two teardown-race behaviours, selected by --mode:

  early: read the request headers, then send a final response IMMEDIATELY, before
         draining the POST body, and close without draining. ATS still has body to
         forward to the origin, so HttpSM's abort_tunnel calls
         do_io_write(this, 0, nullptr) on the origin VC while the body send is in
         flight (the quick_server write-abandon path).

  rst:   read the request headers, then abort the connection with a TCP RST
         (SO_LINGER 0 + close) and no response, driving the origin-facing _write
         into its error/close branch (the server_abort path).
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
import struct
import sys


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("address", help="Address to listen on")
    parser.add_argument("port", type=int, help="The port to listen on")
    parser.add_argument("--mode", choices=["early", "rst"], required=True)
    parser.add_argument("--count", type=int, default=60, help="Number of real (non-probe) connections to serve")
    return parser.parse_args()


def read_headers(sock: socket.socket) -> bytes:
    """Read until the end of the request headers (or the peer closes)."""
    data = b""
    while b"\r\n\r\n" not in data:
        try:
            chunk = sock.recv(4096)
        except OSError:
            break
        if not chunk:
            break
        data += chunk
    return data


def main() -> int:
    args = parse_args()

    ls = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind((args.address, args.port))
    ls.listen(128)
    print(f"post_abort origin ready mode={args.mode} on {args.address}:{args.port}", flush=True)

    served = 0
    while served < args.count:
        sock, _ = ls.accept()
        try:
            headers = read_headers(sock)
            if not headers:
                # A PortOpenv4 readiness probe (or an empty connection). Do not
                # count it against the serve budget.
                sock.close()
                continue

            if args.mode == "early":
                # Final response before the body is drained; leave the body unread.
                body = b"early-origin\n"
                response = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Content-Length: " + str(len(body)).encode() + b"\r\n"
                    b"Connection: close\r\n"
                    b"\r\n" + body)
                sock.sendall(response)
            else:  # rst
                # Force a RST on close: no response, abort mid-POST-receive.
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        except OSError as e:
            print(f"conn {served} exception: {e}", flush=True)
        finally:
            sock.close()
            served += 1
            print(f"served {served}/{args.count}", flush=True)

    print("post_abort origin done", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
