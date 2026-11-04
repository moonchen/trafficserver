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
"""The prefetch plugin's next-object fetches in a slice rule are stored as slice blocks."""

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
PATTERN = r"/(.*seg-)(\d+)(.*)/$1{$2+1}$3/"


def body_for(size: int) -> bytes:
    """Return the origin's body for an object of the given size.

    :param size: Object length in bytes.
    """

    return (ALPHABET * (size // len(ALPHABET) + 1))[:size]


class Scenario:
    """An origin and a Traffic Server whose slice rules also prefetch the next segment."""

    def __init__(self, ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
        """Configure the origin and the remap rules.

        :param ats_factory: Factory for isolated Traffic Server instances.
        :param services: Factory owning support services and their cleanup.
        :param curl: Transport-aware curl command runner.
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
        for plugin in ("slice.so", "cache_range_requests.so", "prefetch.so"):
            if not self.ats.plugin_exists(plugin):
                pytest.skip("slice.so, cache_range_requests.so and prefetch.so are required")
        slice_args = f"@plugin=slice.so @pparam=--blockbytes-test={BLOCK}"
        prefetch_args = (
            "@plugin=prefetch.so @pparam=--front=true @pparam=--api-header=X-Prefetch "
            f"@pparam=--fetch-policy=simple @pparam=--fetch-path-pattern={PATTERN} @pparam=--fetch-count=1")
        self.ats.remap_config.add_lines(
            (
                f"map http://sliced/ http://127.0.0.1:{port}/ {slice_args} {prefetch_args} @plugin=cache_range_requests.so",
                f"map http://inline/ http://127.0.0.1:{port}/ {slice_args} @pparam=--inline-first-block {prefetch_args} "
                "@plugin=cache_range_requests.so",
            ))
        self.ats.records.update({
            "proxy.config.diags.debug.enabled": 1,
            "proxy.config.diags.debug.tags": "slice|prefetch",
        })
        self.origin.start()
        self.ats.start()

    def get(self, host: str, path: str) -> bytes:
        """Send a whole-object GET through Traffic Server's forward-proxy listener and return the body.

        :param host: Remap host: ``sliced`` or ``inline``.
        :param path: Origin path.
        """

        body_file = self.directory / "body.out"
        body_file.unlink(missing_ok=True)
        arguments = [
            "--silent", "--fail", "--output",
            str(body_file), "--max-time", "10", "--proxy", f"http://127.0.0.1:{self.ats.http_port}", f"http://{host}{path}"
        ]
        result = self.curl.run_for(self.ats, shlex.join(arguments))
        assert result.returncode == 0, result.output
        return body_file.read_bytes()

    def origin_ranges(self, path: str) -> list[str | None]:
        """Return the Range of every origin request for a path, in order.

        :param path: Origin path to select.
        """

        if not self.origin_log.exists():
            return []
        records = [json.loads(line) for line in self.origin_log.read_text().splitlines()]
        return [r["range"] for r in records if r["path"] == path]

    def wait_for_origin_requests(self, path: str, count: int) -> None:
        """Wait until the origin logged a number of requests for a path.

        :param path: Origin path to select.
        :param count: Number of requests.
        """

        deadline = time.monotonic() + 10
        while len(self.origin_ranges(path)) < count:
            assert time.monotonic() < deadline, self.origin_ranges(path)
            time.sleep(0.05)


@pytest.mark.parametrize("host", ("sliced", "inline"))
def test_slice_next_object_prefetch(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, host: str) -> None:
    """A prefetch copies a block request without its Range; slice fetches it as blocks, so the next client request
    for that object hits the cache.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param host: Remap host.
    """

    scenario = Scenario(ats_factory, services, curl)
    blocks = [f"bytes={beg}-{beg + BLOCK - 1}" for beg in range(0, SIZE, BLOCK)]
    first, second = f"/0/seg-1/{SIZE}", f"/0/seg-2/{SIZE}"
    assert scenario.get(host, first) == body_for(SIZE)
    scenario.wait_for_origin_requests(second, len(blocks))
    assert scenario.get(host, second) == body_for(SIZE)
    assert sorted(scenario.origin_ranges(second)) == blocks
