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
"""Origin, client and log helpers for the tests of proxy.config.http.cache.max_write_lead."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import socket
import struct
import sys
import time
from typing import Any, Callable

from tools.uranium.services import ProcessService, ServiceFactory

HERE = Path(__file__).parent
KiB = 1 << 10
MiB = 1 << 20
LINE = 16

# Small socket buffers, so that a client that stops reading holds back Traffic Server within a few hundred KiB.
RECORDS = {
    "proxy.config.net.sock_send_buffer_size_in": 64 * KiB,
    "proxy.config.net.sock_recv_buffer_size_out": 64 * KiB,
}


def body(beg: int, end: int) -> bytes:
    """Return the origin's body bytes [beg, end): every 16-byte line holds its own offset.

    :param beg: First byte.
    :param end: One past the last byte.
    """

    first = beg - beg % LINE
    lines = b"".join(b"%015x\n" % offset for offset in range(first, end, LINE))
    return lines[beg - first:end - first]


class Origin:
    """The paced origin, serving /<rate_kib>/<name>/<size>, and its request log."""

    def __init__(self, services: ServiceFactory, directory: Path) -> None:
        """Create the origin process.

        :param services: Factory owning support services and their cleanup.
        :param directory: Directory for the request log.
        """

        self.port = services.allocate_port()
        self.log = directory / "origin.jsonl"
        self.process: ProcessService = services.process(
            "origin", (sys.executable, HERE / "paced_origin.py", str(self.port), str(self.log)), ready_port=self.port)

    def start(self) -> None:
        """Start the origin."""

        self.process.start()

    def requests(self, path: str) -> list[dict[str, Any]]:
        """Return the origin's requests for a path, oldest first.

        Each has the Range, the bytes sent so far and, once it ended, whether the whole body was sent.

        :param path: Origin path to select.
        """

        requests: dict[int, dict[str, Any]] = {}
        if self.log.exists():
            for line in self.log.read_text().splitlines():
                record = json.loads(line)
                if record["ev"] == "start":
                    if record["path"] == path:
                        requests[record["id"]] = {"range": record["range"], "sent": 0, "complete": None}
                elif record["id"] in requests:
                    requests[record["id"]]["sent"] = record["sent"]
                    if record["ev"] == "end":
                        requests[record["id"]]["complete"] = record["complete"]
        return [requests[i] for i in sorted(requests)]

    def sent(self, path: str) -> int:
        """Return the bytes the origin has sent so far for a path, over all its requests.

        :param path: Origin path to select.
        """

        return sum(r["sent"] for r in self.requests(path))

    def wait_idle(self, path: str, timeout: float = 30.0) -> None:
        """Wait until every request for a path has ended.

        :param path: Origin path to select.
        :param timeout: Seconds to wait at most.
        """

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if all(r["complete"] is not None for r in self.requests(path)):
                return
            time.sleep(0.1)
        raise TimeoutError(f"origin still sending {path}")


def get(
        port: int,
        host: str,
        path: str,
        *,
        rate: float = 0,
        stall_after: int | None = None,
        stall_for: float = 0.0,
        close_after: int | None = None,
        timeout: float = 30.0) -> dict[str, Any]:
    """Send one HTTP/1.1 GET through Traffic Server's forward-proxy listener and check the body as it arrives.

    :param port: Traffic Server's HTTP port.
    :param host: Remap host.
    :param path: Origin path.
    :param rate: Bytes per second to read the body at, or 0 for no limit.
    :param stall_after: Body bytes after which the client stops reading for stall_for seconds.
    :param stall_for: Seconds of the stall.
    :param close_after: Body bytes after which the client resets the connection.
    :param timeout: Socket timeout in seconds.
    :return: The status, the Content-Length, the body bytes received, whether they were right, the outcome and the
        times of the start, the stall, the resume and the end.
    """

    result: dict[str, Any] = {"t_start": time.monotonic(), "status": None, "length": None, "received": 0, "ok": True}
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    outcome = "complete"
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 64 * KiB)
        sock.settimeout(timeout)
        sock.connect(("127.0.0.1", port))
        sock.sendall(f"GET http://{host}{path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = sock.recv(64 * KiB)
            if not chunk:
                raise EOFError("connection closed before the response header")
            data += chunk
        head, _, pending = data.partition(b"\r\n\r\n")
        lines = head.decode(errors="replace").split("\r\n")
        result["status"] = int(lines[0].split()[1])
        headers = {k.strip().lower(): v.strip() for k, _, v in (line.partition(":") for line in lines[1:])}
        length = int(headers.get("content-length", "-1"))
        result["length"] = length

        def take(chunk: bytes) -> None:
            received = result["received"]
            if result["ok"] and chunk != body(received, received + len(chunk)):
                result["ok"] = False
            result["received"] = received + len(chunk)

        read_start = time.monotonic()
        stalled = False
        while result["received"] < length:
            if pending:
                chunk, pending = pending[:64 * KiB], pending[64 * KiB:]
            else:
                want = 16 * KiB if rate else 64 * KiB
                for limit in (close_after, None if stalled else stall_after):
                    if limit is not None and limit > result["received"]:
                        want = min(want, limit - result["received"])
                chunk = sock.recv(min(want, length - result["received"]))
                if not chunk:
                    outcome = "eof"
                    break
            take(chunk)
            if close_after is not None and result["received"] >= close_after:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                outcome = "reset"
                break
            if stall_after is not None and not stalled and result["received"] >= stall_after:
                stalled = True
                result["t_stall"] = time.monotonic()
                time.sleep(stall_for)
                result["t_resume"] = time.monotonic()
            if rate:
                delay = read_start + result["received"] / rate - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
    except socket.timeout:
        outcome = "timeout"
    except (EOFError, OSError) as e:
        outcome = f"error: {e!r}"
    finally:
        sock.close()
    result["t_end"] = time.monotonic()
    result["outcome"] = outcome
    result["complete"] = outcome == "complete" and result["received"] == result["length"] and result["ok"]
    return result


def run_together(jobs: list[tuple[float, Callable[[], dict[str, Any]]]]) -> list[dict[str, Any]]:
    """Run each job in its own thread, delay seconds after the first one starts.

    :param jobs: (delay, job) pairs.
    :return: The jobs' results, in order.
    """

    start = time.monotonic()

    def run(delay: float, job: Callable[[], dict[str, Any]]) -> dict[str, Any]:
        time.sleep(max(0.0, start + delay - time.monotonic()))
        return job()

    with ThreadPoolExecutor(len(jobs)) as pool:
        futures = [pool.submit(run, delay, job) for delay, job in jobs]
        return [f.result() for f in futures]
