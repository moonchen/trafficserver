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
"""A request that a child sends upstream as the client's own request, because the block will not be stored, reaches a
parent that runs slice as an ordinary request, not as one of slice's block requests."""

import json
from pathlib import Path
import re
import shlex
import sys

import pytest

from tools.uranium.services import ATS, ATSFactory, Curl, ServiceFactory

TEST_DIRECTORY = Path(__file__).parent
ALPHABET = b"abcdefghijklmnopqrstuvwxyz0123456789"
BLOCK = 100
SIZE = 350
CRR = "@plugin=cache_range_requests.so"
PROMOTE = "@plugin=cache_promote.so @pparam=--policy=lru @pparam=--hits=3 @pparam=--internal-enabled"


def body_for(size: int) -> bytes:
    """Return the origin's body for an object of the given size.

    :param size: Object length in bytes.
    """

    return (ALPHABET * (size // len(ALPHABET) + 1))[:size]


def get(curl: Curl, ats: ATS, directory: Path, url: str, *extra: str) -> tuple[int, dict[str, str], bytes]:
    """Send one GET through a Traffic Server's forward-proxy listener.

    :param curl: Transport-aware curl command runner.
    :param ats: Traffic Server to send it to.
    :param directory: Directory for the body file.
    :param url: Request URL.
    :param extra: More curl arguments.
    :return: The status, the headers and the body.
    """

    body_file = directory / "body.out"
    body_file.unlink(missing_ok=True)
    arguments = [
        "--silent", "--dump-header", "/dev/stdout", "--output",
        str(body_file), "--max-time", "10", "--proxy", f"http://127.0.0.1:{ats.http_port}", *extra, url
    ]
    result = curl.run_for(ats, shlex.join(arguments))
    assert result.returncode == 0, result
    lines = [b for b in re.split(r"\r?\n\r?\n", result.stdout) if b.startswith("HTTP/")][-1].splitlines()
    headers = {}
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers[name.strip().lower()] = value.strip()
    return int(lines[0].split()[1]), headers, body_file.read_bytes() if body_file.exists() else b""


@pytest.mark.parametrize("child", ("sliced", "inline"))
def test_slice_two_tier_unstored(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, child: str) -> None:
    """The child does not store the object yet (cache_promote), so it asks its parent for the client's range, and for
    the whole object without a Range. The parent slices both as ordinary requests: the origin gets only block
    requests, and the parent stores the blocks.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param child: ``sliced`` for slice's intercept, ``inline`` for --inline-first-block, in the child.
    """

    directory = ats_factory.run_directory
    origin_log = directory / "origin.jsonl"
    origin_port = services.allocate_port()
    origin = services.process(
        "origin",
        (sys.executable, TEST_DIRECTORY / "inline_origin.py", str(origin_port), str(origin_log)),
        ready_port=origin_port,
    )
    parent = ats_factory.create("parent")
    child_ats = ats_factory.create("child")
    for plugin in ("slice.so", "cache_range_requests.so", "cache_promote.so"):
        if not child_ats.plugin_exists(plugin):
            pytest.skip(f"{plugin} is required")

    slice_args = f"@plugin=slice.so @pparam=--blockbytes-test={BLOCK}"
    target = f"http://127.0.0.1:{origin_port}/"
    parent.remap_config.add_lines(
        (
            f"map http://127.0.0.1:{parent.http_port}/ {target} {slice_args} {CRR}",
            # Looks up a block's key in the parent's cache.
            f"map http://probe/ {target} {CRR}",
        ))
    inline = " @pparam=--inline-first-block" if child == "inline" else ""
    child_ats.remap_config.add_line(
        f"map http://{child}/ http://127.0.0.1:{parent.http_port}/ {slice_args}{inline} {PROMOTE} {CRR}")
    for ats in (parent, child_ats):
        ats.records.update(
            {
                "proxy.config.diags.debug.enabled": 1,
                "proxy.config.diags.debug.tags": "slice|cache_range_requests|cache_promote",
                "proxy.config.http.cache.required_headers": 0,
            })
    origin.start()
    parent.start()
    child_ats.start()

    path = f"/normal/{SIZE}"
    status, headers, body = get(curl, child_ats, directory, f"http://{child}{path}", "--range", "110-119")
    assert (status, headers.get("content-range"), body) == (206, f"bytes 110-119/{SIZE}", body_for(SIZE)[110:120])
    status, headers, body = get(curl, child_ats, directory, f"http://{child}{path}")
    assert (status, "content-range" in headers, body) == (200, False, body_for(SIZE))

    records = [json.loads(line) for line in origin_log.read_text().splitlines()]
    requests = [r["range"] for r in records if r["path"] == path and "event" not in r]
    # The parent fetched each block once, for the range and then for the whole object.
    assert sorted(requests) == [f"bytes={k * BLOCK}-{(k + 1) * BLOCK - 1}" for k in range(4)], requests
    assert "GET with the skip header but no Range" not in parent.traffic_out.read_text(errors="replace")
    child_text = child_ats.traffic_out.read_text(errors="replace")
    assert child_text.count("Upstream gets the client's request, without slice's headers") == 2
    for k in range(4):
        b = k * BLOCK
        status, _, _ = get(
            curl, parent, directory, f"http://probe{path}", "--header", "Cache-Control: only-if-cached", "--range",
            f"{b}-{b + BLOCK - 1}")
        assert status == 206, k
