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
"""background_fetch does not fetch the whole object for slice's block requests."""

import json
from pathlib import Path
import shlex
import sys
import time

import pytest

from tools.uranium.services import ATSFactory, Curl, ServiceFactory, wait_for_file_lines

TEST_DIRECTORY = Path(__file__).parent
BLOCK = 1000
SIZE = 4 * BLOCK
ALPHABET = b"abcdefghijklmnopqrstuvwxyz0123456789"


def body_for(size: int) -> bytes:
    """Return the origin's body for an object of the given size.

    :param size: Object length in bytes.
    """

    return (ALPHABET * (size // len(ALPHABET) + 1))[:size]


@pytest.mark.parametrize("placement", ("rule", "global"))
def test_slice_background_fetch_skips_blocks(ats_factory: ATSFactory, services: ServiceFactory, placement: str) -> None:
    """Inline's first block is the client's own transaction, with the block's Range. background_fetch, between slice
    and cache_range_requests or as a global plugin, must not take it for a client range request.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param placement: ``rule``: background_fetch between slice and cache_range_requests; ``global``: in plugin.config.
    """

    directory = ats_factory.run_directory
    origin_log = directory / "origin.jsonl"
    port = services.allocate_port()
    origin = services.process(
        "origin",
        (sys.executable, TEST_DIRECTORY / "inline_origin.py", str(port), str(origin_log)),
        ready_port=port,
    )
    ats = ats_factory.create("ts")
    for plugin in ("slice.so", "cache_range_requests.so", "background_fetch.so"):
        if not ats.plugin_exists(plugin):
            pytest.skip("slice.so, cache_range_requests.so and background_fetch.so are required")
    bgf = "@plugin=background_fetch.so" if placement == "rule" else ""
    ats.remap_config.add_lines(
        (
            f"map http://inline/ http://127.0.0.1:{port}/ @plugin=slice.so @pparam=--blockbytes-test={BLOCK} "
            f"@pparam=--inline-first-block {bgf} @plugin=cache_range_requests.so",
            f"map http://plain/ http://127.0.0.1:{port}/ {bgf}",
        ))
    if placement == "global":
        ats.plugin_config.add_line("background_fetch.so")
    ats.records.update(
        {
            "proxy.config.diags.debug.enabled": 1,
            "proxy.config.diags.debug.tags": "background_fetch|slice",
            "proxy.config.http.cache.required_headers": 0,
        })
    origin.start()
    ats.start()
    curl = Curl(directory)

    def get_range(host: str, path: str, beg: int, end: int) -> None:
        body_file = directory / "body.out"
        body_file.unlink(missing_ok=True)
        arguments = [
            "--silent", "--show-error", "--fail", "--output",
            str(body_file), "--max-time", "10", "--proxy", f"http://127.0.0.1:{ats.http_port}", "--range", f"{beg}-{end - 1}",
            f"http://{host}{path}"
        ]
        result = curl.run_for(ats, shlex.join(arguments))
        assert result.returncode == 0, result.output
        assert body_file.read_bytes() == body_for(SIZE)[beg:end]

    def origin_ranges(path: str) -> list[str | None]:
        if not origin_log.exists():
            return []
        records = [json.loads(line) for line in origin_log.read_text().splitlines()]
        return [r["range"] for r in records if r.get("path") == path and "event" not in r]

    # Without slice, a range response makes background_fetch fetch the whole object in this placement.
    control = f"/control/{SIZE}"
    get_range("plain", control, 1500, 1600)
    deadline = time.monotonic() + 10
    while None not in origin_ranges(control):
        assert time.monotonic() < deadline, origin_ranges(control)
        time.sleep(0.05)

    path = f"/inline/{SIZE}"
    get_range("inline", path, 1500, 1600)
    # A background fetch would start before the client's response, and reach the origin for block 0 at once.
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        assert origin_ranges(path) == [f"bytes={BLOCK}-{2 * BLOCK - 1}"]
        time.sleep(0.05)
    wait_for_file_lines(ats.traffic_out, "Skipping a slice block request", 1)
