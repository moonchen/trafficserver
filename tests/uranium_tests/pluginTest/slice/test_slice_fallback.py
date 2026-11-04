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
"""Slice asks upstream for no more than the client needs when a block would not be stored, and keeps one complete
copy of an object whose upstream ignores Range, under the URL's own key."""

from dataclasses import dataclass
import json
from pathlib import Path
import re
import shlex
import sys

import pytest

from tools.uranium.services import ATS, ATSFactory, Curl, ProcessService, ServiceFactory

TEST_DIRECTORY = Path(__file__).parent
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


CRR = "@plugin=cache_range_requests.so"
CACHEKEY = "@plugin=cachekey.so @pparam=--include-headers=Range"
# How a rule keys a block: cache_range_requests adds the Range to the URL, or cachekey adds a Range element.
KEYINGS = {
    "crr": {
        "block": CRR,
        "url": ""
    },
    "cachekey": {
        "block": f"{CACHEKEY} {CRR} @pparam=--no-modify-cachekey",
        "url": CACHEKEY
    },
}


class Scenario:
    """An origin, remap rules under test, and two rules that only look into the cache."""

    def __init__(
            self,
            ats_factory: ATSFactory,
            services: ServiceFactory,
            curl: Curl,
            block: int,
            rules: dict[str, str],
            keying: str = "crr") -> None:
        """Configure the origin and the remap rules.

        :param ats_factory: Factory for isolated Traffic Server instances.
        :param services: Factory owning support services and their cleanup.
        :param curl: Transport-aware curl command runner.
        :param block: Slice block size in bytes.
        :param rules: Plugin chain of each remap host under test.
        :param keying: Key of KEYINGS, for the rules that only look into the cache.
        """

        self.curl = curl
        self.block = block
        self.directory = ats_factory.run_directory
        self.origin_log = self.directory / "origin.jsonl"
        port = services.allocate_port()
        self.origin: ProcessService = services.process(
            "origin",
            (sys.executable, TEST_DIRECTORY / "inline_origin.py", str(port), str(self.origin_log)),
            ready_port=port,
        )
        self.ats: ATS = ats_factory.create("ts")
        for plugin in ("slice.so", "cache_range_requests.so", "cache_promote.so", "cachekey.so"):
            if not self.ats.plugin_exists(plugin):
                pytest.skip(f"{plugin} is required")
        target = f"http://127.0.0.1:{port}/"
        lines = [f"map http://{host}/ {target} {chain}" for host, chain in rules.items()]
        # probe looks up a block's key, as the rules under test form it; plain looks up the URL's own key.
        lines.append(f"map http://probe/ {target} {KEYINGS[keying]['block']}")
        lines.append(f"map http://plain/ {target} {KEYINGS[keying]['url']}".rstrip())
        self.ats.remap_config.add_lines(tuple(lines))
        self.ats.records.update(
            {
                "proxy.config.diags.debug.enabled": 1,
                "proxy.config.diags.debug.tags": "slice|cache_promote|cache_range_requests",
                "proxy.config.http.cache.required_headers": 0,
            })
        self.origin.start()
        self.ats.start()

    def get(self, host: str, path: str, byte_range: str | None = None) -> Response:
        """Send one GET through Traffic Server's forward-proxy listener.

        :param host: Remap host.
        :param path: Origin path selecting the behavior and size.
        :param byte_range: The client's Range, without "bytes=", or None for the whole object.
        """

        return self._request(host, path, () if byte_range is None else ("--range", byte_range))

    def stored(self, path: str, block: int | None) -> int:
        """Return the status of a cache-only lookup: 200 for a complete copy, 206 for a block, 504 for nothing.

        :param path: Origin path.
        :param block: Block number, or None for the URL's own key.
        """

        only_cached = ("--header", "Cache-Control: only-if-cached")
        if block is None:
            return self._request("plain", path, only_cached).status
        b = block * self.block
        return self._request("probe", path, (*only_cached, "--range", f"{b}-{b + self.block - 1}")).status

    def origin_requests(self, path: str) -> list[dict[str, str | None]]:
        """Return the requests the origin logged for a path.

        :param path: Origin path to select.
        """

        if not self.origin_log.exists():
            return []
        records = [json.loads(line) for line in self.origin_log.read_text().splitlines()]
        return [r for r in records if r.get("path") == path and "event" not in r]

    def origin_bytes(self, path: str) -> int:
        """Return the body bytes the origin sent for a path.

        :param path: Origin path, /<mode>/<size>.
        """

        mode, size = path.strip("/").split("/")
        total = 0
        for i, request in enumerate(self.origin_requests(path)):
            m = re.fullmatch(r"bytes=(\d+)-(\d*)", request["range"] or "")
            if m is None or mode == "ignore":
                total += int(size)
            else:
                end = int(m.group(2)) + 1 if m.group(2) else int(size)
                total += max(0, min(end, int(size)) - int(m.group(1)))
        return total

    def errors(self) -> list[str]:
        """Stop Traffic Server and return the ERROR lines of its diagnostic log."""

        self.ats.stop()
        return [line for line in self.ats.diags_log.read_text(errors="replace").splitlines() if "ERROR:" in line]

    def debug_lines(self, text: str) -> int:
        """Count debug lines that contain the text.

        :param text: Text to count.
        """

        return self.ats.traffic_out.read_text(errors="replace").count(text)

    def _request(self, host: str, path: str, extra: tuple[str, ...]) -> Response:
        body_file = self.directory / "body.out"
        body_file.unlink(missing_ok=True)
        arguments = [
            "--silent", "--dump-header", "/dev/stdout", "--output",
            str(body_file), "--max-time", "10", "--proxy", f"http://127.0.0.1:{self.ats.http_port}", *extra, f"http://{host}{path}"
        ]
        result = self.curl.run_for(self.ats, shlex.join(arguments))
        assert result.returncode == 0, result
        blocks = [b for b in re.split(r"\r?\n\r?\n", result.stdout) if b.startswith("HTTP/")]
        lines = blocks[-1].splitlines()
        headers = {}
        for line in lines[1:]:
            name, _, value = line.partition(":")
            headers[name.strip().lower()] = value.strip()
        return Response(int(lines[0].split()[1]), headers, body_file.read_bytes() if body_file.exists() else b"")


def assert_whole(response: Response, size: int) -> None:
    """Require a 200 with the whole object.

    :param response: Response to check.
    :param size: Object length in bytes.
    """

    assert (response.status, "content-range" in response.headers) == (200, False), response
    assert response.body == body_for(size), response


def assert_range(response: Response, size: int, beg: int, end: int) -> None:
    """Require a 206 for the half-open range [beg, end) of the object.

    :param response: Response to check.
    :param size: Object length in bytes.
    :param beg: First byte of the range.
    :param end: Byte after the last byte of the range.
    """

    assert response.status == 206, response
    assert response.headers.get("content-range") == f"bytes {beg}-{end - 1}/{size}", response
    assert response.body == body_for(size)[beg:end], response


PROMOTE = "@plugin=cache_promote.so @pparam=--policy=lru @pparam=--hits=3 @pparam=--internal-enabled"
PROMOTE_BLOCK = 100
PROMOTE_SIZE = 350


@pytest.mark.parametrize("host", ("sliced", "inline"))
def test_slice_promote_per_object(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, host: str) -> None:
    """Under cache_promote, an unpromoted range costs upstream only the range, and the object's blocks are stored from
    the request that promotes the object on, because cache_promote counts slice's block requests per object.

    Ranges of 10 bytes cycle over the four blocks three times, with --hits=3.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param host: ``sliced`` for slice's intercept, ``inline`` for --inline-first-block.
    """

    slice_args = f"@plugin=slice.so @pparam=--blockbytes-test={PROMOTE_BLOCK}"
    if host == "inline":
        slice_args += " @pparam=--inline-first-block"
    scenario = Scenario(ats_factory, services, curl, PROMOTE_BLOCK, {host: f"{slice_args} {PROMOTE} {CRR}"})
    path = f"/normal/{PROMOTE_SIZE}"
    for i in range(12):
        beg = (i % 4) * PROMOTE_BLOCK + 10
        assert_range(scenario.get(host, path, f"{beg}-{beg + 9}"), PROMOTE_SIZE, beg, beg + 10)

    requests = [r["range"] for r in scenario.origin_requests(path)]
    # The first two requests are not promoted: upstream gets the client's ranges.
    assert requests[:2] == ["bytes=10-19", "bytes=110-119"], requests
    # The third promotes the object. Every block is then fetched once, whole, and stored.
    assert sorted(requests[2:]) == sorted(f"bytes={k * PROMOTE_BLOCK}-{(k + 1) * PROMOTE_BLOCK - 1}" for k in range(4)), requests
    assert scenario.origin_bytes(path) == 20 + PROMOTE_SIZE
    assert [scenario.stored(path, k) for k in range(4)] == [206] * 4
    assert scenario.errors() == []


@pytest.mark.parametrize("host", ("sliced", "inline"))
def test_slice_promote_whole_get(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, host: str) -> None:
    """An unpromoted whole-object GET goes upstream as one GET without Range, as it would without slice.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param host: ``sliced`` for slice's intercept, ``inline`` for --inline-first-block.
    """

    slice_args = f"@plugin=slice.so @pparam=--blockbytes-test={PROMOTE_BLOCK}"
    if host == "inline":
        slice_args += " @pparam=--inline-first-block"
    scenario = Scenario(ats_factory, services, curl, PROMOTE_BLOCK, {host: f"{slice_args} {PROMOTE} {CRR}"})
    path = f"/normal/{PROMOTE_SIZE}"
    assert_whole(scenario.get(host, path), PROMOTE_SIZE)
    assert [r["range"] for r in scenario.origin_requests(path)] == [None]
    assert [scenario.stored(path, k) for k in range(4)] == [504] * 4
    assert scenario.errors() == []


def test_slice_promote_unsliced(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """Without slice, cache_promote counts requests by their cache key and stores the object once promoted.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    scenario = Scenario(ats_factory, services, curl, PROMOTE_BLOCK, {"promoted": PROMOTE})
    path = "/normal/40"
    for _ in range(4):
        assert_whole(scenario.get("promoted", path), 40)
    # Not promoted twice, promoted and stored by the third, a hit for the fourth.
    assert len(scenario.origin_requests(path)) == 3
    assert scenario.stored(path, None) == 200
    assert scenario.errors() == []


def test_slice_promote_later_blocks(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """Plain slicing, with block 0 already stored: a later block that is not promoted costs upstream only the part of it
    that the client needs.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    slice_args = f"@plugin=slice.so @pparam=--blockbytes-test={PROMOTE_BLOCK}"
    rules = {"warm": f"{slice_args} {CRR}", "sliced": f"{slice_args} {PROMOTE} {CRR}"}
    scenario = Scenario(ats_factory, services, curl, PROMOTE_BLOCK, rules)
    path = f"/normal/{PROMOTE_SIZE}"
    # Stores block 0 without cache_promote.
    assert_range(scenario.get("warm", path, "10-19"), PROMOTE_SIZE, 10, 20)
    assert_range(scenario.get("sliced", path, "210-219"), PROMOTE_SIZE, 210, 220)
    assert_range(scenario.get("sliced", path, "150-249"), PROMOTE_SIZE, 150, 250)
    assert_range(scenario.get("sliced", path, "210-219"), PROMOTE_SIZE, 210, 220)
    # Not promoted for block 2, then for block 1; promoted, and stored, for block 2 by the third block request.
    assert [r["range"] for r in scenario.origin_requests(path)] == ["bytes=0-99", "bytes=210-219", "bytes=150-199", "bytes=200-299"]
    assert [scenario.stored(path, k) for k in range(4)] == [206, 504, 206, 504]
    assert scenario.errors() == []


def test_slice_promote_later_blocks_inline(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl) -> None:
    """--inline-first-block, with the first block already stored: a later block that is not promoted costs upstream only
    the part of it that the client needs, and is stored whole once the object is promoted.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    """

    slice_args = f"@plugin=slice.so @pparam=--blockbytes-test={PROMOTE_BLOCK} @pparam=--inline-first-block"
    rules = {"warm": f"{slice_args} {CRR}", "inline": f"{slice_args} {PROMOTE} {CRR}"}
    scenario = Scenario(ats_factory, services, curl, PROMOTE_BLOCK, rules)
    path = f"/normal/{PROMOTE_SIZE}"
    # Stores block 1 without cache_promote.
    assert_range(scenario.get("warm", path, "110-119"), PROMOTE_SIZE, 110, 120)
    for _ in range(3):
        assert_range(scenario.get("inline", path, "150-249"), PROMOTE_SIZE, 150, 250)
    # Block 2 is not promoted twice, then promoted and stored by the third block request.
    assert [r["range"] for r in scenario.origin_requests(path)
           ] == ["bytes=100-199", "bytes=200-249", "bytes=200-249", "bytes=200-299"]
    assert [scenario.stored(path, k) for k in range(4)] == [504, 206, 206, 504]
    assert scenario.errors() == []


WHOLE_BLOCK = 7
# The existing slice reads block 0 first, or the block that holds the range's start (relative); inline serves that block
# in the client's transaction.
FIRST_BLOCKS = {"sliced": "", "relative": "@pparam=--ref-relative", "inline": "@pparam=--inline-first-block"}


def whole_rules(host: str, keying: str = "crr") -> dict[str, str]:
    """Return the remap rule for an upstream that may ignore Range.

    :param host: Key of FIRST_BLOCKS.
    :param keying: Key of KEYINGS.
    """

    slice_args = f"@plugin=slice.so @pparam=--blockbytes-test={WHOLE_BLOCK} {FIRST_BLOCKS[host]}".rstrip()
    return {host: f"{slice_args} {KEYINGS[keying]['block']}"}


def first_block_range(host: str, beg: int) -> str:
    """Return the Range of the first block that a rule requests for a range that starts at beg.

    :param host: Key of FIRST_BLOCKS.
    :param beg: First byte of the client's range.
    """

    b = 0 if host == "sliced" else beg // WHOLE_BLOCK * WHOLE_BLOCK
    return f"bytes={b}-{b + WHOLE_BLOCK - 1}"


@pytest.mark.parametrize("keying", KEYINGS)
@pytest.mark.parametrize("host", FIRST_BLOCKS)
def test_slice_whole_object_one_copy(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, host: str, keying: str) -> None:
    """An upstream that ignores Range, first asked for the block that holds byte 15: the object is stored once, under the
    URL's own key, and every later request is served from it. A PURGE through slice removes it.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param host: Key of FIRST_BLOCKS.
    :param keying: Key of KEYINGS.
    """

    scenario = Scenario(ats_factory, services, curl, WHOLE_BLOCK, whole_rules(host, keying), keying)
    size = 31
    path = f"/ignore/{size}"
    # Without slice, a range miss gets the 200 too.
    assert_whole(scenario.get(host, path, "15-20"), size)
    assert_range(scenario.get(host, path, "8-10"), size, 8, 11)
    assert_range(scenario.get(host, path, "22-24"), size, 22, 25)
    assert_range(scenario.get(host, path, "28-"), size, 28, 31)
    assert_range(scenario.get(host, path, "0-3"), size, 0, 4)
    assert_whole(scenario.get(host, path), size)

    assert [r["range"] for r in scenario.origin_requests(path)] == [first_block_range(host, 15)]
    assert scenario.origin_bytes(path) == size
    assert [scenario.stored(path, k) for k in range(5)] == [504] * 5
    assert scenario.stored(path, None) == 200
    # Each request's first block missed and looked up the URL's own key; the five after the first found the copy.
    assert scenario.debug_lines("looking up the URL's own key") == 6
    assert scenario.debug_lines("from the complete copy") == 5

    purge = scenario._request(host, path, ("--request", "PURGE"))
    assert purge.status == 200, purge
    assert scenario.stored(path, None) == 504
    assert scenario.errors() == []


@pytest.mark.parametrize("keying", KEYINGS)
def test_slice_url_key_shared(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, keying: str) -> None:
    """The URL's own key that slice derives from a block's key is the key of the same request without slice: a complete
    copy stored by a rule without slice serves slice's requests, whatever the rule's first block.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param keying: Key of KEYINGS.
    """

    rules = {host: chain for name in FIRST_BLOCKS for host, chain in whole_rules(name, keying).items()}
    scenario = Scenario(ats_factory, services, curl, WHOLE_BLOCK, rules, keying)
    size = 31
    path = f"/normal/{size}"
    assert_whole(scenario.get("plain", path), size)
    for host in FIRST_BLOCKS:
        assert_range(scenario.get(host, path, "15-20"), size, 15, 21)
        assert_range(scenario.get(host, path, "3-"), size, 3, size)
        assert_whole(scenario.get(host, path), size)
    assert [r["range"] for r in scenario.origin_requests(path)] == [None]
    assert scenario.errors() == []


@pytest.mark.parametrize("host", ("sliced", "inline"))
def test_slice_url_key_copy_too_short(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, host: str) -> None:
    """A range that starts past the end of the copy under the URL's own key goes upstream, and the object's new length
    holds it.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param host: ``sliced`` or ``inline``.
    """

    scenario = Scenario(ats_factory, services, curl, WHOLE_BLOCK, whole_rules(host))
    # 20 bytes for the first request, 40 after.
    path = "/grow/20"
    assert_whole(scenario.get("plain", path), 20)
    assert_range(scenario.get(host, path, "5-8"), 20, 5, 9)
    assert_range(scenario.get(host, path, "25-30"), 40, 25, 31)
    first = ["bytes=0-6"] if host == "sliced" else []
    assert [r["range"] for r in scenario.origin_requests(path)] == [None, *first, "bytes=21-27", "bytes=28-34"]
    # The first block and every later block that missed found the copy too short.
    assert scenario.debug_lines("starts past the end of the complete copy") == (3 if host == "sliced" else 2)
    assert scenario.errors() == []


@pytest.mark.parametrize("host", FIRST_BLOCKS)
def test_slice_url_key_lookup_normal(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, host: str) -> None:
    """An upstream that honors Range: every block that misses looks up the URL's own key once, finds nothing there, and
    is fetched and stored as a block.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param host: Key of FIRST_BLOCKS.
    """

    scenario = Scenario(ats_factory, services, curl, WHOLE_BLOCK, whole_rules(host))
    size = 31
    path = f"/normal/{size}"
    assert_range(scenario.get(host, path, "15-20"), size, 15, 21)
    assert_range(scenario.get(host, path, "8-17"), size, 8, 18)
    assert_range(scenario.get(host, path, "15-20"), size, 15, 21)

    requests = [r["range"] for r in scenario.origin_requests(path)]
    blocks = {"sliced": [0, 2, 1], "relative": [2, 1], "inline": [2, 1]}[host]
    assert requests == [f"bytes={k * WHOLE_BLOCK}-{(k + 1) * WHOLE_BLOCK - 1}" for k in blocks]
    assert scenario.debug_lines("looking up the URL's own key") == len(blocks)
    assert scenario.debug_lines("No complete copy") == 0
    assert [scenario.stored(path, k) for k in sorted(blocks)] == [206] * len(blocks)
    assert scenario.stored(path, None) == 504
    assert scenario.errors() == []
