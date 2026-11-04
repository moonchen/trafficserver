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
"""Slice's --inline-first-block serves GETs from the block that holds their first byte."""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
import json
from pathlib import Path
import re
import shlex
import socket
import struct
import sys
import time

import pytest

from tools.uranium.services import ATS, ATSFactory, Curl, ProcessService, ServiceFactory, wait_for_file_lines

TEST_DIRECTORY = Path(__file__).parent
BLOCK = 7
ALPHABET = b"abcdefghijklmnopqrstuvwxyz0123456789"


def body_for(size: int) -> bytes:
    """Return the origin's body for an object of the given size.

    :param size: Object length in bytes.
    """

    return (ALPHABET * (size // len(ALPHABET) + 1))[:size]


@dataclass
class Response:
    status: int
    headers: dict[str, str]
    body: bytes
    returncode: int


class Scenario:
    """An origin and a Traffic Server with an inline rule and a plain slice rule."""

    def __init__(
            self,
            ats_factory: ATSFactory,
            services: ServiceFactory,
            curl: Curl,
            *,
            size_table: bool = False,
            tls: bool = False,
            ram_cache: bool = True,
            block: int = BLOCK,
            inline_extra: str = "",
            crr_extra: str = "",
            records: dict[str, int | str] | None = None) -> None:
        """Configure the origin and the remap rules.

        :param ats_factory: Factory for isolated Traffic Server instances.
        :param services: Factory owning support services and their cleanup.
        :param curl: Transport-aware curl command runner.
        :param size_table: Whether the inline rule keeps a size table of large objects.
        :param tls: Whether Traffic Server also listens for TLS clients.
        :param ram_cache: Whether cache hits may come from the RAM cache.
        :param block: Slice block size in bytes.
        :param inline_extra: More slice parameters for the inline rule.
        :param crr_extra: More cache_range_requests parameters for both rules.
        :param records: More records.yaml settings.
        """

        self.curl = curl
        self.directory = ats_factory.run_directory
        self.origin_log = self.directory / "origin.jsonl"
        port = services.allocate_port()
        self.origin: ProcessService = services.process(
            "origin",
            (sys.executable, TEST_DIRECTORY / "inline_origin.py", str(port), str(self.origin_log)),
            ready_port=port,
        )
        self.ats: ATS = ats_factory.create("ts", enable_tls=tls)
        if tls:
            self.ats.add_default_ssl_files()
        if not self.ats.plugin_exists("slice.so") or not self.ats.plugin_exists("cache_range_requests.so"):
            pytest.skip("slice.so and cache_range_requests.so are required")
        slice_args = f"@plugin=slice.so @pparam=--blockbytes-test={block}"
        inline_args = f"{slice_args} @pparam=--inline-first-block {inline_extra}".rstrip()
        if size_table:
            inline_args += " @pparam=--metadata-cache-size=16"
        crr = f"@plugin=cache_range_requests.so {crr_extra}".rstrip()
        self.ats.remap_config.add_lines(
            (
                f"map http://inline/ http://127.0.0.1:{port}/ {inline_args} {crr}",
                f"map http://sliced/ http://127.0.0.1:{port}/ {slice_args} {crr}",
            ))
        if tls:
            self.ats.remap_config.add_line(
                f"map https://inline:{self.ats.https_port}/ http://127.0.0.1:{port}/ {inline_args} {crr}")
        self.ats.records.update(
            {
                "proxy.config.diags.debug.enabled": 1,
                "proxy.config.diags.debug.tags": "slice",
                "proxy.config.http.cache.required_headers": 0,
            })
        if not ram_cache:
            # Only objects smaller than the cutoff enter the RAM cache, so every hit reads the disk cache.
            self.ats.records.update({"proxy.config.cache.ram_cache_cutoff": 1})
        self.ats.records.update(records or {})
        self.origin.start()
        self.ats.start()

    def get(self, host: str, path: str, *extra: str, method: str = "GET", name: str = "body") -> Response:
        """Send one request through Traffic Server's forward-proxy listener.

        :param host: Remap host: ``inline`` or ``sliced``.
        :param path: Origin path selecting the behavior and size.
        :param extra: Additional curl arguments.
        :param method: Request method.
        :param name: Name of the body file, unique among concurrent requests.
        """

        body_file = self.directory / f"{name}.out"
        body_file.unlink(missing_ok=True)
        arguments = [
            "--silent",
            "--dump-header",
            "/dev/stdout",
            "--output",
            str(body_file),
            "--max-time",
            "10",
        ]
        if "--http2" not in extra:
            arguments.extend(("--proxy", f"http://127.0.0.1:{self.ats.http_port}"))
        if method == "HEAD":
            arguments.append("--head")
        arguments.extend(extra)
        if "--http2" in extra:
            arguments.extend(("--insecure", "--resolve", f"{host}:{self.ats.https_port}:127.0.0.1"))
            arguments.append(f"https://{host}:{self.ats.https_port}{path}")
        else:
            arguments.append(f"http://{host}{path}")
        result = self.curl.run_for(self.ats, shlex.join(arguments))
        blocks = [b for b in re.split(r"\r?\n\r?\n", result.stdout) if b.startswith("HTTP/")]
        status, headers = 0, {}
        if blocks:
            lines = blocks[-1].splitlines()
            status = int(lines[0].split()[1])
            for line in lines[1:]:
                name, _, value = line.partition(":")
                headers[name.strip().lower()] = value.strip()
        body = body_file.read_bytes() if body_file.exists() else b""
        return Response(status, headers, body, result.returncode)

    def origin_requests(self, path: str) -> list[dict[str, str | None]]:
        """Return the requests the origin logged for a path.

        :param path: Origin path to select.
        """

        return [r for r in self._origin_records(path) if "event" not in r]

    def origin_events(self, path: str, event: str) -> int:
        """Count the events of a kind that the origin logged for a path.

        :param path: Origin path to select.
        :param event: ``held``, ``sent`` or ``cut``.
        """

        return sum(1 for r in self._origin_records(path) if r.get("event") == event)

    def _origin_records(self, path: str) -> list[dict[str, str | None]]:
        if not self.origin_log.exists():
            return []
        records = [json.loads(line) for line in self.origin_log.read_text().splitlines()]
        return [r for r in records if r["path"] == path]

    def wait_for_origin_event(self, path: str, event: str) -> None:
        """Wait until the origin logged an event for a path.

        :param path: Origin path to select.
        :param event: ``held``, ``sent`` or ``cut``.
        """

        deadline = time.monotonic() + 10
        while self.origin_events(path, event) == 0:
            assert time.monotonic() < deadline, self._origin_records(path)
            time.sleep(0.05)

    def wait_for_origin_requests(self, path: str, count: int) -> None:
        """Wait until the origin logged at least a number of requests for a path.

        :param path: Origin path to select.
        :param count: Number of requests.
        """

        deadline = time.monotonic() + 10
        while len(self.origin_requests(path)) < count:
            assert time.monotonic() < deadline, self.origin_requests(path)
            time.sleep(0.05)

    def release_origin(self) -> None:
        """Let a held origin response send the rest of its body."""

        Path(f"{self.origin_log}.release").touch()

    def errors(self) -> list[str]:
        """Stop Traffic Server and return the ERROR lines of its diagnostic log."""

        self.ats.stop()
        return [line for line in self.ats.diags_log.read_text(errors="replace").splitlines() if "ERROR:" in line]

    def debug_lines(self, text: str) -> int:
        """Count slice debug lines that contain the text.

        :param text: Text to count.
        """

        return self.ats.traffic_out.read_text(errors="replace").count(text)


class SocketClient:
    """A GET through Traffic Server's forward-proxy listener whose body the test reads in steps.

    Its receive buffer is small, so a client that stops reading pushes back on Traffic Server at once.
    """

    def __init__(self, port: int, host: str, path: str) -> None:
        """Send the request and read the response header.

        :param port: Traffic Server's HTTP port.
        :param host: Remap host.
        :param path: Origin path selecting the behavior and size.
        """

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
        self.sock.settimeout(10)
        self.sock.connect(("127.0.0.1", port))
        self.sock.sendall(f"GET http://{host}{path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while b"\r\n\r\n" not in data:
            chunk = self.sock.recv(65536)
            assert chunk, data
            data += chunk
        head, _, self.body = data.partition(b"\r\n\r\n")
        self.status = int(head.split(b" ", 2)[1])

    def read(self, count: int) -> bytes:
        """Read until the body holds at least a number of bytes or the response ends, and return the body.

        :param count: Number of body bytes.
        """

        while len(self.body) < count:
            chunk = self.sock.recv(65536)
            if not chunk:
                break
            self.body += chunk
        return self.body

    def reset(self) -> None:
        """Abort the connection with a reset."""

        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        self.sock.close()


def assert_whole(response: Response, size: int) -> None:
    """Require a complete 200 for the whole object.

    :param response: Response to check.
    :param size: Object length in bytes.
    """

    assert response.returncode == 0, response
    assert response.status == 200, response
    assert response.headers.get("content-length") == str(size), response
    assert "content-range" not in response.headers, response
    assert response.body == body_for(size), response


def assert_range(response: Response, size: int, beg: int, end: int) -> None:
    """Require a complete 206 for the half-open range [beg, end) of the object.

    :param response: Response to check.
    :param size: Object length in bytes.
    :param beg: First byte of the range.
    :param end: Byte after the last byte of the range.
    """

    assert response.returncode == 0, response
    assert response.status == 206, response
    assert response.headers.get("content-range") == f"bytes {beg}-{end - 1}/{size}", response
    assert response.headers.get("content-length") == str(end - beg), response
    assert response.body == body_for(size)[beg:end], response


def block_range(k: int) -> str:
    """Return the Range of block k.

    :param k: Block number.
    """

    return f"bytes={k * BLOCK}-{(k + 1) * BLOCK - 1}"


def same_response(a: Response, b: Response) -> tuple:
    """Return the parts of two responses that must match, side by side.

    :param a: First response.
    :param b: Second response.
    """

    def parts(r: Response) -> tuple:
        return (r.status, r.body, r.headers.get("content-range"), r.headers.get("content-length"))

    return parts(a), parts(b)


def test_slice_inline_small_and_large(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """Objects up to one block take one transaction; larger ones continue after the first block.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    scenario = Scenario(ats_factory, services, curl)

    for size in (1, 5, BLOCK):
        path = f"/normal/{size}"
        assert_whole(scenario.get("inline", path), size)
        assert scenario.origin_requests(path) == [
            {
                "method": "GET",
                "path": path,
                "range": f"bytes=0-{BLOCK - 1}",
                "slicer": "-",
                "ident": None
            }
        ]
        # The second request is a cache hit on the stored first block.
        assert_whole(scenario.get("inline", path), size)
        assert len(scenario.origin_requests(path)) == 1
    # Neither transaction was intercepted.
    assert scenario.debug_lines("slice accepting and slicing") == 0

    size = 3 * BLOCK - 1
    path = f"/normal/{size}"
    assert_whole(scenario.get("inline", path), size)
    # The rest of the object comes from block requests; slice never requests block 0 again as a reference.
    assert scenario.debug_lines(f"requestBlock: bytes=0-{BLOCK - 1}") == 0
    ranges = [r["range"] for r in scenario.origin_requests(path)]
    assert ranges == [f"bytes=0-{BLOCK - 1}", f"bytes={BLOCK}-{2 * BLOCK - 1}", f"bytes={2 * BLOCK}-{3 * BLOCK - 1}"], ranges
    # As in slice's own block requests, every block after the first carries the first block's identity.
    assert [r["ident"] for r in scenario.origin_requests(path)[1:]] == ['Etag "v1"', 'Etag "v1"']
    # Without a size table the next request is also inline: a cached first block, then cached blocks.
    assert_whole(scenario.get("inline", path), size)
    assert len(scenario.origin_requests(path)) == 3
    # The inline rule stored the same blocks that plain slicing reads.
    assert_whole(scenario.get("sliced", path), size)
    assert len(scenario.origin_requests(path)) == 3
    assert scenario.errors() == []


def test_slice_inline_disk_hit(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """A large object whose first block comes from the disk cache still gets its remainder.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    scenario = Scenario(ats_factory, services, curl, ram_cache=False)
    size = 3 * BLOCK - 1
    path = f"/normal/{size}"
    for _ in range(3):
        assert_whole(scenario.get("inline", path), size)
    assert len(scenario.origin_requests(path)) == 3
    assert scenario.errors() == []


def test_slice_inline_disk_hit_large_blocks(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """Blocks that span several cache fragments: the inline rule returns the whole object from the disk cache.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    block = 4 << 20
    scenario = Scenario(ats_factory, services, curl, ram_cache=False, block=block)
    size = 2 * block
    path = f"/normal/{size}"
    assert_whole(scenario.get("sliced", path), size)
    for _ in range(2):
        assert_whole(scenario.get("inline", path), size)
    assert scenario.errors() == []


@pytest.mark.parametrize("ram_cache", (True, False), ids=("ram", "disk"))
def test_slice_inline_stale_first_block(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, ram_cache: bool) -> None:
    """A stale first block of a large object is revalidated, and the client still gets the whole object.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param ram_cache: Whether cache hits may come from the RAM cache.
    """

    scenario = Scenario(ats_factory, services, curl, ram_cache=ram_cache)
    for size in (5, 3 * BLOCK - 1):
        path = f"/stale/{size}"
        assert_whole(scenario.get("sliced", path), size)
        time.sleep(2)  # the origin's max-age is 1 second
        for _ in range(2):
            assert_whole(scenario.get("inline", path), size)
    assert scenario.errors() == []


def test_slice_inline_origin_down(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """With the origin unreachable, a stale object is served whole, as plain slicing serves it.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    scenario = Scenario(ats_factory, services, curl)
    sizes = (5, 3 * BLOCK - 1)
    for size in sizes:
        assert_whole(scenario.get("inline", f"/stale/{size}"), size)
    time.sleep(2)  # the origin's max-age is 1 second
    scenario.origin.stop()
    for size in sizes:
        path = f"/stale/{size}"
        assert_whole(scenario.get("sliced", path), size)
        assert_whole(scenario.get("inline", path), size)
    path = f"/stale/{sizes[1]}"
    assert_range(scenario.get("sliced", path, "--range", "8-16"), sizes[1], 8, 17)
    assert_range(scenario.get("inline", path, "--range", "8-16"), sizes[1], 8, 17)


def test_slice_inline_revalidated(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """A stale first block that the origin revalidates with a 304 is served whole from the cache.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    scenario = Scenario(ats_factory, services, curl)
    for size in (5, 3 * BLOCK - 1):
        path = f"/cond/{size}"
        assert_whole(scenario.get("inline", path), size)
        time.sleep(2)  # the origin's max-age is 1 second
        assert_whole(scenario.get("inline", path), size)
        assert_whole(scenario.get("inline", path), size)
        first_block = [r for r in scenario.origin_requests(path) if r["range"] == f"bytes=0-{BLOCK - 1}"]
        assert len(first_block) >= 2, scenario.origin_requests(path)
    assert scenario.errors() == []


@pytest.mark.parametrize("host", ("inline", "sliced"))
def test_slice_inline_version_change_heals(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, host: str) -> None:
    """After the object changes once, the failed response repairs the first block and the next response is whole.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param host: Remap host: the inline rule, or plain slicing for comparison.
    """

    scenario = Scenario(ats_factory, services, curl, crr_extra="@pparam=--consider-ident")
    size = 3 * BLOCK - 1
    path = f"/bump/{size}"
    first = scenario.get(host, path)
    assert first.returncode != 0 or len(first.body) < size, first
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if any(r["range"] == f"bytes=0-{BLOCK - 1}" and r["ident"] == 'Etag "v2"' for r in scenario.origin_requests(path)):
            break
        time.sleep(0.1)
    assert_whole(scenario.get(host, path), size)


def test_slice_inline_slow_client(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """A client that stops reading holds about two blocks, and never holds back the cache write of a block.

    As in slice, a block that was requested is read to its end as fast as it arrives, and the next block is requested
    only while at most one block waits for the client. Requests that read those blocks from their cache writes finish
    while the client is stalled.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    block = 4 << 20
    scenario = Scenario(
        ats_factory,
        services,
        curl,
        block=block,
        records={
            "proxy.config.cache.enable_read_while_writer": 2,
            "proxy.config.net.sock_send_buffer_size_in": 65536,
        })
    size = 4 * block
    path = f"/hold/{size}"
    blocks = [f"bytes={k * block}-{(k + 1) * block - 1}" for k in range(4)]
    client = SocketClient(scenario.ats.http_port, "inline", path)
    assert client.status == 200
    scenario.wait_for_origin_event(path, "held")
    client.read(256 << 10)
    # The next block is requested when the first one starts, and read to its end while the first is held.
    scenario.wait_for_origin_requests(path, 2)
    with ThreadPoolExecutor(2) as pool:
        first = pool.submit(scenario.get, "inline", path, "--range", f"{block - 100}-{block - 1}", name="first")
        assert_range(
            scenario.get("inline", path, "--range", f"{2 * block - 100}-{2 * block - 1}"), size, 2 * block - 100, 2 * block)
        assert not first.done()
        scenario.release_origin()
        assert_range(first.result(), size, block - 100, block)
    time.sleep(1)  # time for a third block request, which must not come while the client is stalled
    assert [r["range"] for r in scenario.origin_requests(path)] == blocks[:2]
    assert client.read(size) == body_for(size)
    assert [r["range"] for r in scenario.origin_requests(path)] == blocks
    assert scenario.errors() == []


def test_slice_inline_range_while_writing(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """A range inside a first block that another request is still writing is cut out of that block as it arrives.

    Core reads such a block only as far as it is written; with read-while-writer mode 2 it would send a range past
    that to the origin, uncached.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    block = 4 << 20
    scenario = Scenario(ats_factory, services, curl, block=block, records={"proxy.config.cache.enable_read_while_writer": 2})
    size = 2 * block
    path = f"/hold/{size}"
    beg = 3000000
    with ThreadPoolExecutor(2) as pool:
        writer = pool.submit(scenario.get, "inline", path, name="writer")
        scenario.wait_for_origin_event(path, "held")
        reader = pool.submit(scenario.get, "inline", path, "--range", f"{beg}-{beg + 99}", name="reader")
        wait_for_file_lines(scenario.ats.traffic_out, "still being written|of the cached block", 1)
        scenario.release_origin()
        assert_whole(writer.result(), size)
        assert_range(reader.result(), size, beg, beg + 100)
    assert [r["range"] for r in scenario.origin_requests(path)] == [f"bytes=0-{block - 1}", f"bytes={block}-{2 * block - 1}"]
    assert scenario.debug_lines("still being written") == 1
    assert scenario.debug_lines("of the cached block") == 0
    assert scenario.errors() == []


@pytest.mark.parametrize("host", ("inline", "sliced"))
def test_slice_range_while_copy_written(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, host: str) -> None:
    """A range that finds the complete copy of an object whose origin ignores Range while another request still writes
    it gets its range as a 206, cut out of the copy as it arrives, without a request to the origin.

    Core reads such a copy only as far as it is written; with read-while-writer mode 2 it would send a range past that
    to the origin, uncached.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param host: ``inline`` for --inline-first-block, ``sliced`` for slice's intercept.
    """

    block = 4 << 20
    scenario = Scenario(ats_factory, services, curl, block=block, records={"proxy.config.cache.enable_read_while_writer": 2})
    size = 2 * block
    path = f"/holdwhole/{size}"
    # Past the part of the copy that the origin sends before it holds the rest.
    beg = 6000000
    with ThreadPoolExecutor(2) as pool:
        writer = pool.submit(scenario.get, host, path, name="writer")
        scenario.wait_for_origin_event(path, "held")
        reader = pool.submit(scenario.get, host, path, "--range", f"{beg}-{beg + 99}", name="reader")
        wait_for_file_lines(scenario.ats.traffic_out, "out of the complete copy", 1)
        scenario.release_origin()
        assert_whole(writer.result(), size)
        assert_range(reader.result(), size, beg, beg + 100)
    assert [r["range"] for r in scenario.origin_requests(path)] == [f"bytes=0-{block - 1}"]
    assert scenario.errors() == []


@pytest.mark.parametrize("host", ("inline", "sliced"))
def test_slice_range_from_copy_http10(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, host: str) -> None:
    """Core serves ranges only to HTTP/1.1 requests, so an HTTP/1.0 range is cut out of the complete copy in the
    client's transaction. Slice's intercept sends its block requests as HTTP/1.1, so core serves the range there.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param host: ``inline`` for --inline-first-block, ``sliced`` for slice's intercept.
    """

    scenario = Scenario(ats_factory, services, curl)
    path = "/ignore/20"
    assert_whole(scenario.get(host, path), 20)
    assert_range(scenario.get(host, path, "--http1.0", "--range", "8-10"), 20, 8, 11)
    assert len(scenario.origin_requests(path)) == 1
    assert scenario.debug_lines("out of the complete copy") == (1 if host == "inline" else 0)
    assert scenario.errors() == []


def test_slice_inline_client_abort_first_block(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """A client that aborts while its first block arrives leaves that block's cache write to finish in the background.

    A request reading the block from that writer still gets the whole object, and the block is stored.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    block = 4 << 20
    scenario = Scenario(
        ats_factory,
        services,
        curl,
        block=block,
        records={
            "proxy.config.cache.enable_read_while_writer": 2,
            "proxy.config.diags.debug.tags": "slice|http",
        })
    size = 2 * block
    path = f"/hold/{size}"
    with ThreadPoolExecutor(1) as pool:
        leader = SocketClient(scenario.ats.http_port, "inline", path)
        assert leader.status == 200
        scenario.wait_for_origin_event(path, "held")
        leader.read(1 << 20)
        follower = pool.submit(scenario.get, "inline", path, name="follower")
        # Both transforms have their first bytes: the follower reads the block from the leader's cache write.
        wait_for_file_lines(scenario.ats.traffic_out, "Inline first block transform", 2)
        leader.reset()
        wait_for_file_lines(scenario.ats.traffic_out, r"\[tunnel_handler_ua, \S*VC_EVENT_(ERROR|EOS)\]", 1)
        scenario.release_origin()
        assert_whole(follower.result(), size)
    scenario.wait_for_origin_event(path, "sent")
    assert scenario.debug_lines("Initiating background fill") >= 1
    assert_whole(scenario.get("inline", path), size)
    assert [r["range"] for r in scenario.origin_requests(path)] == [f"bytes=0-{block - 1}", f"bytes={block}-{2 * block - 1}"]
    assert scenario.errors() == []


def test_slice_inline_prefetch(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """With --prefetch-count, a first block that missed starts background fetches ahead of the block in flight.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    scenario = Scenario(ats_factory, services, curl, inline_extra="@pparam=--prefetch-count=2")
    size = 5 * BLOCK
    path = f"/normal/{size}"
    assert_whole(scenario.get("inline", path), size)
    # Block 1 is requested by the transform itself; blocks 2 and 3 are prefetched with it, block 4 with block 2.
    assert scenario.debug_lines("Request background block") == 3
    assert {r["range"] for r in scenario.origin_requests(path)} == {f"bytes={k * BLOCK}-{(k + 1) * BLOCK - 1}" for k in range(5)}
    # A fresh first block does not prefetch.
    assert_whole(scenario.get("inline", path), size)
    assert scenario.debug_lines("Request background block") == 3
    assert scenario.errors() == []


def test_slice_inline_size_table(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """With a size table, a URL found to be large is sliced on the next request.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    scenario = Scenario(ats_factory, services, curl, size_table=True)
    size = 3 * BLOCK - 1
    path = f"/normal/{size}"
    assert_whole(scenario.get("inline", path), size)
    assert_whole(scenario.get("inline", path), size)
    wait_for_file_lines(scenario.ats.traffic_out, "Known large object, slicing", 1)
    assert len(scenario.origin_requests(path)) == 3

    small = "/normal/5"
    assert_whole(scenario.get("inline", small), 5)
    assert_whole(scenario.get("inline", small), 5)
    assert scenario.debug_lines("Known large object, slicing") == 1
    assert scenario.errors() == []


@pytest.mark.parametrize("size", (5, 3 * BLOCK - 1))
def test_slice_inline_ignored_range(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, size: int) -> None:
    """An origin that ignores Range sends a 200, which reaches the client unchanged.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param size: Object length in bytes.
    """

    scenario = Scenario(ats_factory, services, curl)
    assert_whole(scenario.get("inline", f"/ignore/{size}"), size)
    assert_whole(scenario.get("sliced", f"/ignore/{size}"), size)
    assert scenario.errors() == []


def test_slice_inline_short_first_block(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """A first block shorter than requested is not stored, and the rest is fetched from its end.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    scenario = Scenario(ats_factory, services, curl)
    for size in (5, 3 * BLOCK - 1):
        path = f"/short/{size}"
        assert_whole(scenario.get("inline", path), size)
        assert_whole(scenario.get("inline", path), size)
        assert_whole(scenario.get("sliced", path), size)
    assert scenario.errors() == []


@pytest.mark.parametrize("mode", ("badcr", "star", "nocr", "wrongstart"))
def test_slice_inline_bad_partial_content(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, mode: str) -> None:
    """A 206 without a usable Content-Range becomes a 502 and is not stored.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param mode: Origin behavior.
    """

    scenario = Scenario(ats_factory, services, curl)
    path = f"/{mode}/5"
    for _ in range(2):
        response = scenario.get("inline", path)
        assert response.status == 502, response
    assert len(scenario.origin_requests(path)) == 2
    errors = scenario.errors()
    assert len(errors) == 2 and all("unusable 206 Content-Range" in line for line in errors), errors


def test_slice_inline_empty_object(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """A 416 for a zero-length object becomes an empty 200.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    scenario = Scenario(ats_factory, services, curl)
    response = scenario.get("inline", "/empty/0")
    assert response.returncode == 0, response
    assert response.status == 200, response
    assert response.headers.get("content-length") == "0", response
    assert response.body == b"", response
    assert scenario.errors() == []


@pytest.mark.parametrize("code", (302, 404, 500))
def test_slice_inline_error_status(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, code: int) -> None:
    """Statuses other than 206 and 416 reach the client as the origin sent them.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param code: Origin status.
    """

    scenario = Scenario(ats_factory, services, curl)
    path = f"/status/{code}"
    inline = scenario.get("inline", path)
    sliced = scenario.get("sliced", path)
    assert inline.status == code, inline
    assert inline.body == f"status {code}\n".encode(), inline
    assert (inline.status, inline.body) == (sliced.status, sliced.body)
    assert scenario.errors() == []


def test_slice_inline_changed_object(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """A remainder from a different version of the object ends the response instead of mixing versions.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    scenario = Scenario(ats_factory, services, curl, crr_extra="@pparam=--consider-ident")
    size = 3 * BLOCK - 1
    path = f"/changing/{size}"
    response = scenario.get("inline", path)
    assert response.status == 200, response
    assert response.returncode != 0, response
    assert len(response.body) < size, response
    assert response.body == body_for(size)[:len(response.body)], response
    # Block 1 came from a newer version, so the first block is requested again with that version's identity, which
    # cache_range_requests (with --consider-ident) treats as a reason to refetch it.
    assert scenario.debug_lines("Refetching the first block for a new version") == 1
    deadline = time.monotonic() + 10
    repair = [r for r in scenario.origin_requests(path) if r["range"] == f"bytes=0-{BLOCK - 1}" and r["ident"] == 'Etag "v2"']
    while not repair and time.monotonic() < deadline:
        time.sleep(0.1)
        repair = [r for r in scenario.origin_requests(path) if r["range"] == f"bytes=0-{BLOCK - 1}" and r["ident"] == 'Etag "v2"']
    assert repair, scenario.origin_requests(path)
    errors = scenario.errors()
    assert any("Inline first block: remainder" in line for line in errors), errors


def test_slice_inline_http2(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """HTTP/2 clients get the same whole objects, including the remainder of a large one.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    if not curl.supports("http2"):
        pytest.skip("curl lacks HTTP/2 support")
    scenario = Scenario(ats_factory, services, curl, tls=True)
    for size in (5, 3 * BLOCK - 1):
        path = f"/normal/{size}"
        for _ in range(2):
            response = scenario.get("inline", path, "--http2")
            assert response.returncode == 0, response
            assert response.status == 200, response
            assert "content-range" not in response.headers, response
            assert response.body == body_for(size), response
    size = 3 * BLOCK - 1
    for _ in range(2):
        response = scenario.get("inline", f"/normal/{size}", "--http2", "--range", "5-16")
        assert response.returncode == 0, response
        assert response.status == 206, response
        assert response.headers.get("content-range") == f"bytes 5-16/{size}", response
        assert response.body == body_for(size)[5:17], response
    assert scenario.errors() == []


# Ranges of the 20-byte object, whose blocks are [0, 7), [7, 14) and [14, 20), and of a 5-byte object. Each case is
# (path, Range, expected half-open range, blocks the origin sees).
RANGE_CASES = {
    "in_first_block": ("/normal/20", "2-4", (2, 5), (0,)),
    "in_later_block": ("/normal/20", "8-10", (8, 11), (1,)),
    "first_block": ("/normal/20", "0-6", (0, 7), (0,)),
    "later_block": ("/normal/20", "7-13", (7, 14), (1,)),
    "spanning": ("/normal/20", "5-16", (5, 17), (0, 1, 2)),
    "open": ("/normal/20", "10-", (10, 20), (1, 2)),
    "past_end": ("/normal/20", "10-100", (10, 20), (1, 2)),
    "whole": ("/normal/20", "0-", (0, 20), (0, 1, 2)),
    "last_byte": ("/normal/20", "19-19", (19, 20), (2,)),
    "small": ("/normal/5", "1-3", (1, 4), (0,)),
    "small_whole": ("/normal/5", "0-", (0, 5), (0,)),
    # The first response for the block ends early, so the transform fetches the block again for the rest.
    "short_block": ("/short/20", "8-12", (8, 13), (1, 1)),
}


@pytest.mark.parametrize("case", RANGE_CASES.values(), ids=RANGE_CASES.keys())
def test_slice_inline_range(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, case: tuple) -> None:
    """A range starts at the block that holds its first byte, and only the blocks it covers are fetched.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param case: Path, Range, expected range and the blocks the origin sees.
    """

    path, range_, (beg, end), blocks = case
    size = int(path.rsplit("/", 1)[1])
    first_block, last_block = beg // BLOCK, (end - 1) // BLOCK
    last_block_end = min((last_block + 1) * BLOCK, size)
    # A range inside one block, other than the whole block, is served from that block by core once it is cached.
    in_one_block = first_block == last_block and not (beg % BLOCK == 0 and end == last_block_end)
    # A range over several blocks that ends inside its last block stops reading that block once it is cached.
    stops_early = first_block != last_block and end < last_block_end
    scenario = Scenario(ats_factory, services, curl)
    first = scenario.get("inline", path, "--range", range_)
    assert_range(first, size, beg, end)
    requests = scenario.origin_requests(path)
    assert [r["range"] for r in requests] == [block_range(k) for k in blocks], requests
    # As in slice's own block requests, the skip header carries the client's range for the first block.
    assert requests[0]["slicer"] == f"bytes={range_}", requests
    assert scenario.debug_lines("slice accepting and slicing") == 0
    assert scenario.debug_lines("of the cached block") == 0
    assert scenario.debug_lines("not being stored") == 0
    # The blocks are stored whole; the second request reads them from the cache.
    assert_range(scenario.get("inline", path, "--range", range_), size, beg, end)
    assert len(scenario.origin_requests(path)) == len(blocks)
    assert scenario.debug_lines("of the cached block") == int(in_one_block)
    assert scenario.debug_lines("not being stored") == int(stops_early)
    inline, sliced = same_response(first, scenario.get("sliced", path, "--range", range_))
    assert inline == sliced
    assert scenario.errors() == []


@pytest.mark.parametrize(
    "case", (("/normal/20", "30-"), ("/normal/16", "16-"), ("/normal/16", "17-20")),
    ids=("past_last_block", "at_end", "in_last_block"))
def test_slice_inline_range_unsatisfiable(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, case: tuple) -> None:
    """A range that starts at or past the end of the object gets a 416 with the object's length.

    The 16-byte object ends inside its last block, so the block request succeeds and the transform answers with
    the 416.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param case: Path and Range.
    """

    path, range_ = case
    size = int(path.rsplit("/", 1)[1])
    scenario = Scenario(ats_factory, services, curl)
    for _ in range(2):
        inline = scenario.get("inline", path, "--range", range_)
        assert inline.returncode == 0, inline
        assert inline.status == 416, inline
        assert inline.headers.get("content-range") == f"bytes */{size}", inline
    sliced = scenario.get("sliced", path, "--range", range_)
    # Plain slicing leaves the unit out of its Content-Range ("*/<length>").
    assert (sliced.status, sliced.headers.get("content-range")) == (416, f"*/{size}"), sliced
    assert scenario.errors() == []


def test_slice_inline_range_ignored(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """An origin that ignores Range sends a 200, which reaches the client unchanged, as plain slicing sends it. It is
    stored under the URL's own key, where both rules find it for the next ranges.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    scenario = Scenario(ats_factory, services, curl)
    path = "/ignore/20"
    sliced = scenario.get("sliced", "/ignore/21", "--range", "8-10")
    inline = scenario.get("inline", path, "--range", "8-10")
    assert_whole(inline, 20)
    assert (inline.status, inline.headers.get("content-range")) == (sliced.status, sliced.headers.get("content-range"))
    assert_range(scenario.get("sliced", path, "--range", "8-10"), 20, 8, 11)
    assert_range(scenario.get("inline", path, "--range", "12-15"), 20, 12, 16)
    assert len(scenario.origin_requests(path)) == 1
    assert scenario.errors() == []


def test_slice_inline_range_disk_hit(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """Ranges whose blocks come from the disk cache: one inside a block, one over three blocks.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    scenario = Scenario(ats_factory, services, curl, ram_cache=False)
    path = "/normal/20"
    for _ in range(3):
        assert_range(scenario.get("inline", path, "--range", "8-10"), 20, 8, 11)
        assert_range(scenario.get("inline", path, "--range", "5-16"), 20, 5, 17)
    assert len(scenario.origin_requests(path)) == 3
    assert scenario.debug_lines("Serving bytes=1-3 of the cached block") == 2
    assert scenario.debug_lines("not being stored") == 2
    assert scenario.errors() == []


def test_slice_inline_range_http10(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """Core serves ranges only to HTTP/1.1 requests, so an HTTP/1.0 range is cut out of the block by the transform.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    scenario = Scenario(ats_factory, services, curl)
    path = "/normal/20"
    for _ in range(2):
        assert_range(scenario.get("inline", path, "--http1.0", "--range", "8-10"), 20, 8, 11)
    assert scenario.debug_lines("of the cached block") == 0
    assert scenario.errors() == []


@pytest.mark.parametrize("mode", ("normal", "cond"))
def test_slice_inline_range_made_stale(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, mode: str) -> None:
    """A plugin after slice makes the fresh block stale at cache lookup, after slice gave core a range within it.

    cache_range_requests with --consider-ident does that when the client's identity header does not match the
    stored block. The origin then sends a new block (normal) or a 304 (cond); either way the client gets its range.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param mode: Origin behavior.
    """

    scenario = Scenario(ats_factory, services, curl, crr_extra="@pparam=--consider-ident")
    path = f"/{mode}/20"
    assert_range(scenario.get("inline", path, "--range", "8-10"), 20, 8, 11)
    response = scenario.get("inline", path, "--range", "8-10", "--header", 'X-Crr-Ident: Etag "v0"')
    assert_range(response, 20, 8, 11)
    assert scenario.debug_lines("Serving bytes=1-3 of the cached block") == 1
    assert len(scenario.origin_requests(path)) == 2
    # The first request, a miss, cuts the range out of the block with the transform. After a new block the second
    # does too; after a 304 core serves the stored block.
    assert scenario.debug_lines("Inline first block transform") == (2 if mode == "normal" else 1)
    assert scenario.errors() == []


def test_slice_inline_range_prefetch(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """Prefetch stays inside the client's range.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    scenario = Scenario(ats_factory, services, curl, inline_extra="@pparam=--prefetch-count=2")
    size = 5 * BLOCK
    path = f"/normal/{size}"
    # Blocks 1 and 2: the transform fetches block 2 itself, and nothing lies past it.
    assert_range(scenario.get("inline", path, "--range", f"{BLOCK + 1}-{3 * BLOCK - 1}"), size, BLOCK + 1, 3 * BLOCK)
    assert scenario.debug_lines("Request background block") == 0
    assert {r["range"] for r in scenario.origin_requests(path)} == {block_range(1), block_range(2)}
    # From block 1 to the end of a six-block object: the request for block 2 prefetches blocks 3 and 4, and the
    # request for block 3 prefetches block 5.
    other = "/normal/36"
    assert_range(scenario.get("inline", other, "--range", f"{BLOCK + 1}-"), 36, BLOCK + 1, 36)
    assert scenario.debug_lines("Request background block") == 3
    assert {r["range"] for r in scenario.origin_requests(other)} == {block_range(k) for k in range(1, 6)}
    assert scenario.errors() == []


@pytest.mark.parametrize(
    "case", (
        ("suffix", ("--range", "-4")),
        ("multiple", ("--range", "2-4,8-10")),
        ("invalid", ("--header", "Range: bytes=5-2")),
        ("head", ()),
        ("conditional", ("--header", 'If-None-Match: "v1"')),
    ),
    ids=lambda case: case[0])
def test_slice_inline_bypass(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, case: tuple) -> None:
    """Suffix, multiple and invalid ranges, HEAD and conditional requests take the ordinary slice path.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param case: Case name and extra curl arguments.
    """

    name, extra = case
    scenario = Scenario(ats_factory, services, curl)
    path = f"/normal/{3 * BLOCK - 1}"
    method = "HEAD" if name == "head" else "GET"
    sliced = scenario.get("sliced", path, *extra, method=method)
    inline = scenario.get("inline", path, *extra, method=method)
    assert (inline.status, inline.body, inline.headers.get("content-range"), inline.headers.get("content-length")) == (
        sliced.status, sliced.body, sliced.headers.get("content-range"), sliced.headers.get("content-length"))
    assert scenario.debug_lines("Inline first block") == 0
    assert scenario.errors() == []
