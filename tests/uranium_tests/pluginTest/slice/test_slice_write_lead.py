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
"""Slice's block requests read a block from the origin and write it to cache at the origin's pace, even when the
block's client reads it slowly."""

from pathlib import Path
import threading
import time

import pytest

from tools.uranium.services import ATS, ATSFactory, ServiceFactory
from uranium_tests.cache.write_lead_helpers import KiB, MiB, RECORDS, Origin, get, run_together

BLOCK = 1 * MiB
# A conf_remap after slice sets the lead back to 0 for the block requests, as without slice's setting.
NO_LEAD = "@plugin=conf_remap.so @pparam=proxy.config.http.cache.max_write_lead=0"
RULES = {
    "sliced": "",
    "inline": "@pparam=--inline-first-block",
    "sliced-nolead": NO_LEAD,
    "inline-nolead": f"@pparam=--inline-first-block {NO_LEAD}",
}


def configure(ats_factory: ATSFactory, services: ServiceFactory, rule: str, block: int) -> tuple[ATS, Origin]:
    """Start an origin and a Traffic Server with one slice rule for http://<rule>/.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param rule: One of RULES.
    :param block: Slice block size.
    """

    ats = ats_factory.create("ts", enable_cache=True)
    if not all(ats.plugin_exists(p) for p in ("slice.so", "cache_range_requests.so", "conf_remap.so")):
        pytest.skip("slice.so, cache_range_requests.so and conf_remap.so are required")
    origin = Origin(services, Path(ats_factory.run_directory))
    ats.remap_config.add_line(
        f"map http://{rule}/ http://127.0.0.1:{origin.port}/ @plugin=slice.so @pparam=--blockbytes={block} {RULES[rule]} "
        "@plugin=cache_range_requests.so")
    ats.records.update({
        "proxy.config.diags.debug.enabled": 1,
        "proxy.config.diags.debug.tags": "slice|http_tunnel",
        **RECORDS,
    })
    origin.start()
    ats.start()
    return ats, origin


@pytest.mark.parametrize("rule", RULES)
def test_slice_write_lead_slow_leader(ats_factory: ATSFactory, services: ServiceFactory, rule: str) -> None:
    """Requests that read a one-block object while a stalled client's block request writes it finish at the origin's
    pace.

    Inline mode serves such an object without a transform, so without the lead the block's cache write waits for the
    stalled client.  The existing slice reads every block at the origin's pace either way.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param rule: One of RULES.
    """

    ats, origin = configure(ats_factory, services, rule, 4 * MiB)
    size = 3 * MiB
    path = f"/8192/leader/{size}"
    leader = lambda: get(ats.http_port, rule, path, stall_after=3 * MiB // 2, stall_for=5.0)
    follower = lambda: get(ats.http_port, rule, path)
    first, *followers = run_together([(0.0, leader)] + [(0.5, follower)] * 3)

    assert first["complete"], first
    for result in followers:
        if rule == "inline-nolead":
            assert not result["complete"] or result["t_end"] > first["t_resume"] - 0.5, result
        else:
            assert result["complete"], result
            assert result["t_end"] < first["t_resume"] - 3.0, result
    assert len(origin.requests(path)) == 1


@pytest.mark.parametrize("rule", ("sliced", "inline"))
def test_slice_write_lead_bound(ats_factory: ATSFactory, services: ServiceFactory, rule: str) -> None:
    """Every block request may read a block ahead of its client, and a client that stops reading makes slice read at
    most two blocks ahead of it.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param rule: Slice rule.
    """

    ats, origin = configure(ats_factory, services, rule, BLOCK)
    size = 8 * BLOCK
    path = f"/0/bound/{size}"
    read = 256 * KiB
    results = []
    leader = threading.Thread(
        target=lambda: results.append(get(ats.http_port, rule, path, stall_after=read, stall_for=3.0)), daemon=True)
    leader.start()
    time.sleep(2.0)
    ahead = origin.sent(path) - read
    leader.join()

    assert results[0]["complete"], results[0]
    assert ahead <= 2 * BLOCK + 3 * MiB // 2
    traffic_out = ats.traffic_out.read_text(errors="replace")
    assert traffic_out.count(f"reads up to {BLOCK} bytes ahead of its slowest consumer") == size // BLOCK


@pytest.mark.parametrize("rule", ("sliced", "inline"))
def test_slice_write_lead_client_abort(ats_factory: ATSFactory, services: ServiceFactory, rule: str) -> None:
    """A client that resets its connection early in the first block leaves the block's fill to complete.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param rule: Slice rule.
    """

    ats, origin = configure(ats_factory, services, rule, 2 * MiB)
    size = 4 * MiB
    path = f"/2048/abort/{size}"
    first = get(ats.http_port, rule, path, close_after=256 * KiB)
    assert first["outcome"] == "reset", first
    time.sleep(0.5)
    origin.wait_idle(path)

    second = get(ats.http_port, rule, path)
    assert second["complete"], second
    block0 = [r for r in origin.requests(path) if r["range"] == f"bytes=0-{2 * MiB - 1}"]
    assert len(block0) == 1, origin.requests(path)
    assert block0[0]["complete"]
