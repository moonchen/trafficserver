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
"""Concurrent slice block requests for the same uncached block fetch it from the origin once, when the rule allows read
retries."""

from collections import Counter
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import shlex
import sys
import time

import pytest

from tools.uranium.services import ATS, ATSFactory, Curl, ProcessService, ServiceFactory

TEST_DIRECTORY = Path(__file__).parent
BLOCK = 1000
SIZE = 3 * BLOCK
ALPHABET = b"abcdefghijklmnopqrstuvwxyz0123456789"
HOSTS = ("sliced", "inline")
READ_RETRIES = 5


def body_for(size: int) -> bytes:
    """Return the origin's body for an object of the given size.

    :param size: Object length in bytes.
    """

    return (ALPHABET * (size // len(ALPHABET) + 1))[:size]


class Scenario:
    """An origin and a Traffic Server with a slice rule and an inline slice rule."""

    def __init__(self, ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, *, read_retry_action: int | None = 6) -> None:
        """Configure the origin and the remap rules.

        :param ats_factory: Factory for isolated Traffic Server instances.
        :param services: Factory owning support services and their cleanup.
        :param curl: Transport-aware curl command runner.
        :param read_retry_action: The proxy.config.http.cache.open_write_fail_action that conf_remap sets on both rules,
            with read retries, or None to leave the rules at the production settings.
        """

        self.curl = curl
        self.directory = ats_factory.run_directory
        self.origin_log = self.directory / "origin.jsonl"
        port = services.allocate_port()
        self.origin: ProcessService = services.process(
            "origin",
            (sys.executable, TEST_DIRECTORY / "delay_origin.py", str(port), str(self.origin_log)),
            ready_port=port,
        )
        self.ats: ATS = ats_factory.create("ts")
        for plugin in ("slice.so", "cache_range_requests.so", "conf_remap.so"):
            if not self.ats.plugin_exists(plugin):
                pytest.skip(f"{plugin} is required")
        slice_args = f"@plugin=slice.so @pparam=--blockbytes-test={BLOCK}"
        if read_retry_action is not None:
            slice_args = (
                "@plugin=conf_remap.so "
                f"@pparam=proxy.config.http.cache.open_write_fail_action={read_retry_action} "
                f"@pparam=proxy.config.http.cache.max_open_read_retries={READ_RETRIES} {slice_args}")
        self.ats.remap_config.add_lines(
            (
                f"map http://sliced/ http://127.0.0.1:{port}/ {slice_args} @plugin=cache_range_requests.so",
                f"map http://inline/ http://127.0.0.1:{port}/ {slice_args} @pparam=--inline-first-block "
                "@plugin=cache_range_requests.so",
            ))
        self.ats.records.update(
            {
                "proxy.config.diags.debug.enabled": 1,
                "proxy.config.diags.debug.tags": "slice|http_cache",
                # Production settings: a request that loses the cache write lock goes to the origin without
                # caching, unless the rule allows read retries.
                "proxy.config.cache.enable_read_while_writer": 2,
                "proxy.config.http.cache.open_write_fail_action": 2,
                "proxy.config.http.cache.max_open_read_retries": -1,
            })
        self.origin.start()
        self.ats.start()

    def get(self, host: str, path: str, name: str) -> tuple[int, bytes]:
        """Send a whole-object GET through Traffic Server's forward-proxy listener.

        :param host: Remap host: ``sliced`` or ``inline``.
        :param path: Origin path selecting the delay, the name and the size.
        :param name: Name of the body file, unique among concurrent requests.
        :return: curl's exit status and the body.
        """

        body_file = self.directory / f"{name}.out"
        body_file.unlink(missing_ok=True)
        arguments = [
            "--silent", "--output",
            str(body_file), "--max-time", "20", "--proxy", f"http://127.0.0.1:{self.ats.http_port}", f"http://{host}{path}"
        ]
        result = self.curl.run_for(self.ats, shlex.join(arguments))
        return result.returncode, body_file.read_bytes() if body_file.exists() else b""

    def get_all(self, host: str, path: str, count: int, *, writer_first: bool = False) -> list[tuple[int, bytes]]:
        """Send count GETs at once, or one first and the rest once its first block request reached the origin.

        :param host: Remap host.
        :param path: Origin path.
        :param count: Number of requests.
        :param writer_first: Whether the first request takes the first block's cache write before the others start.
        """

        with ThreadPoolExecutor(count) as pool:
            futures = []
            for i in range(count):
                futures.append(pool.submit(self.get, host, path, f"client{i}"))
                if i == 0 and writer_first:
                    self.wait_for_origin_requests(path, 1)
            return [f.result() for f in futures]

    def wait_for_origin_requests(self, path: str, count: int) -> None:
        """Wait until the origin logged at least a number of requests for a path.

        :param path: Origin path.
        :param count: Number of requests.
        """

        deadline = time.monotonic() + 20
        while sum(self.block_requests(path).values()) < count:
            assert time.monotonic() < deadline, self.block_requests(path)
            time.sleep(0.02)

    def block_requests(self, path: str) -> Counter:
        """Count the origin requests for a path by their Range.

        :param path: Origin path to select.
        """

        if not self.origin_log.exists():
            return Counter()
        records = [json.loads(line) for line in self.origin_log.read_text().splitlines()]
        return Counter(r["range"] for r in records if r["path"] == path)

    def errors(self) -> list[str]:
        """Return the ERROR lines of diags.log."""

        text = self.ats.diags_log.read_text(errors="replace") if self.ats.diags_log.exists() else ""
        return [line for line in text.splitlines() if "ERROR:" in line]


def blocks(size: int) -> list[str]:
    """Return the Range of every block request slice sends for an object.

    :param size: Object length in bytes.
    """

    return [f"bytes={beg}-{beg + BLOCK - 1}" for beg in range(0, size, BLOCK)]


@pytest.mark.parametrize("action", (5, 6))
@pytest.mark.parametrize("host", HOSTS)
def test_slice_collapse_slow_writer(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, host: str, action: int) -> None:
    """With read retries on the rule, requests that find a block's writer before its first bytes arrive wait for it
    instead of fetching the block.

    The origin answers after 1.5 s, longer than one read-while-writer wait (0.9 s), so the followers need more than
    one cache read.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param host: Remap host.
    :param action: The rule's proxy.config.http.cache.open_write_fail_action.
    """

    scenario = Scenario(ats_factory, services, curl, read_retry_action=action)
    path = f"/1500/slow/{SIZE}"
    for returncode, body in scenario.get_all(host, path, 4, writer_first=True):
        assert returncode == 0
        assert body == body_for(SIZE)
    assert scenario.block_requests(path) == Counter(blocks(SIZE))
    assert scenario.errors() == []


@pytest.mark.parametrize("host", HOSTS)
def test_slice_collapse_slow_writer_off(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, host: str) -> None:
    """Without read retries on the rule, a request that waited for a writer longer than one read-while-writer wait
    fetches the block itself.

    The origin holds the first request's first block until the three others have asked for it too, so they find a
    writer that has no data yet.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param host: Remap host.
    """

    scenario = Scenario(ats_factory, services, curl, read_retry_action=None)
    path = f"/0/gate4/{SIZE}"
    for returncode, body in scenario.get_all(host, path, 4, writer_first=True):
        assert returncode == 0
        assert body == body_for(SIZE)
    assert scenario.block_requests(path)[blocks(SIZE)[0]] == 4


@pytest.mark.parametrize("host", HOSTS)
def test_slice_collapse_burst(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, host: str) -> None:
    """Requests sent at the same moment fetch each block from the origin once, whichever of them misses first.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param host: Remap host.
    """

    scenario = Scenario(ats_factory, services, curl)
    path = f"/200/burst/{SIZE}"
    for returncode, body in scenario.get_all(host, path, 8):
        assert returncode == 0
        assert body == body_for(SIZE)
    assert scenario.block_requests(path) == Counter(blocks(SIZE))
    assert scenario.errors() == []


@pytest.mark.parametrize("host", HOSTS)
def test_slice_collapse_writer_aborts(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, host: str) -> None:
    """When the request writing a block loses its origin connection, the requests waiting for it fetch the block again
    and get the whole object.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param host: Remap host.
    """

    scenario = Scenario(ats_factory, services, curl)
    path = f"/500/cut/{SIZE}"
    results = scenario.get_all(host, path, 4, writer_first=True)
    # The first request's own block was cut short; the followers waited for it and then fetched the block again.
    for returncode, body in results[1:]:
        assert returncode == 0
        assert body == body_for(SIZE)
    assert scenario.block_requests(path)[blocks(SIZE)[0]] == 2
