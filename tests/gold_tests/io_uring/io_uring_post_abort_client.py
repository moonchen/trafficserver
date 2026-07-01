#!/usr/bin/env python3
"""Client for io_uring_post_abort: streams a large chunked POST, races the origin teardown.

Each iteration opens a connection to the proxy, sends POST request headers, then
streams a large chunked body from a background thread WHILE the main thread reads
the response. Reading concurrently means the early origin status is still captured
even when ATS closes the client's write side mid-send. The loop is repeated --count
times to widen the window in which the origin body-write is in flight when the
origin tears the transaction down.
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
import threading


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("address", help="Address of the proxy to connect to")
    parser.add_argument("port", type=int, help="Port of the proxy to connect to")
    parser.add_argument("--host", required=True, help="Host header (selects the remap)")
    parser.add_argument("--mode", choices=["early", "rst"], required=True)
    parser.add_argument("--count", type=int, default=40, help="Number of POST iterations")
    parser.add_argument("--chunks", type=int, default=256, help="Number of 1 KiB body chunks per POST")
    parser.add_argument("--timeout", type=float, default=8.0)
    return parser.parse_args()


def one_iteration(address: str, port: int, host: str, chunks: int, timeout: float) -> str:
    """Run one POST; return the response status code (as a string) or a sentinel.

    :returns: the 3-digit status, "reset" if the connection was reset/refused, or
        "none" if no HTTP response line was read.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((address, port))
    except OSError:
        return "reset"

    request = (f"POST / HTTP/1.1\r\n"
               f"Host: {host}\r\n"
               f"Transfer-Encoding: chunked\r\n"
               f"\r\n").encode()
    try:
        sock.sendall(request)
    except OSError:
        sock.close()
        return "reset"

    body_chunk = b"400\r\n" + (b"A" * 1024) + b"\r\n"  # 0x400 == 1024

    def sender() -> None:
        try:
            for _ in range(chunks):
                sock.sendall(body_chunk)
            sock.sendall(b"0\r\n\r\n")
        except OSError:
            # ATS closed the write side mid-send (teardown). Expected in these races.
            pass

    t = threading.Thread(target=sender, daemon=True)
    t.start()

    data = b""
    try:
        while b"\r\n\r\n" not in data:
            r = sock.recv(4096)
            if not r:
                break
            data += r
    except OSError:
        pass

    t.join(timeout)
    sock.close()

    if data.startswith(b"HTTP/"):
        parts = data.split(b" ", 2)
        if len(parts) >= 2 and parts[1].isdigit():
            return parts[1].decode()
    if not data:
        return "reset"
    return "none"


def main() -> int:
    args = parse_args()
    print(args, flush=True)

    counts = {"2xx": 0, "3xx": 0, "4xx": 0, "5xx": 0, "reset": 0, "none": 0}
    for i in range(args.count):
        status = one_iteration(args.address, args.port, args.host, args.chunks, args.timeout)
        if status in ("reset", "none"):
            counts[status] += 1
        elif status.startswith("2"):
            counts["2xx"] += 1
        elif status.startswith("3"):
            counts["3xx"] += 1
        elif status.startswith("4"):
            counts["4xx"] += 1
        elif status.startswith("5"):
            counts["5xx"] += 1
        else:
            counts["none"] += 1
        print(f"iter {i}: status={status}", flush=True)

    print(
        f"{args.mode.upper()}_SUMMARY total={args.count} "
        f"2xx={counts['2xx']} 3xx={counts['3xx']} 4xx={counts['4xx']} "
        f"5xx={counts['5xx']} reset={counts['reset']} none={counts['none']}",
        flush=True)

    if args.mode == "early":
        # The early origin 200 must survive the write-abandon and reach the client.
        if counts["2xx"] > 0:
            print("EARLY_STATUS_OBSERVED", flush=True)
    else:  # rst
        # The origin never responds, so no transaction may succeed; every one must
        # end in a 5xx or a reset/dropped connection.
        if counts["2xx"] == 0 and counts["3xx"] == 0 and (counts["5xx"] + counts["reset"] + counts["none"]) > 0:
            print("RST_ABORT_OBSERVED", flush=True)

    print(f"{args.mode.upper()}_DONE", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
