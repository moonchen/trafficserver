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
"""With proxy.config.http.cache.max_write_lead, a slow client does not pace the cache write of its response."""

from pathlib import Path
import threading
import time

import pytest

from tools.uranium.services import ATS, ATSFactory, Curl, ServiceFactory
from uranium_tests.cache.write_lead_helpers import KiB, MiB, RECORDS, Origin, body, get, run_together

LEAD = 8 * MiB


def configure(ats_factory: ATSFactory, services: ServiceFactory, records: dict, *, enable_tls: bool = False) -> tuple[ATS, Origin]:
    """Start an origin and a Traffic Server that maps http://plain/, and https://plain/ with TLS, to it.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param records: More records.yaml settings.
    :param enable_tls: Whether Traffic Server also listens for TLS.
    """

    ats = ats_factory.create("ts", enable_tls=enable_tls, enable_cache=True)
    origin = Origin(services, Path(ats_factory.run_directory))
    ats.remap_config.add_line(f"map http://plain/ http://127.0.0.1:{origin.port}/")
    if enable_tls:
        ats.add_default_ssl_files()
        ats.remap_config.add_line(f"map https://plain:{ats.https_port}/ http://127.0.0.1:{origin.port}/")
    ats.records.update(
        {
            "proxy.config.diags.debug.enabled": 1,
            "proxy.config.diags.debug.tags": "http_tunnel|http_cache",
            **RECORDS,
            **records,
        })
    origin.start()
    ats.start()
    return ats, origin


@pytest.mark.parametrize(
    ("lead", "flow_control"),
    (pytest.param(0, 0, id="off"), pytest.param(LEAD, 0, id="on"), pytest.param(LEAD, 1, id="on-flow-control")),
)
def test_cache_write_lead_followers(ats_factory: ATSFactory, services: ServiceFactory, lead: int, flow_control: int) -> None:
    """Requests that read an object while a stalled client's transaction writes it finish at the origin's pace.

    Without a lead they read only as far as the stalled client has, and wait for it or fail.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param lead: proxy.config.http.cache.max_write_lead.
    :param flow_control: proxy.config.http.flow_control.enabled.
    """

    ats, origin = configure(
        ats_factory, services, {
            "proxy.config.http.cache.max_write_lead": lead,
            "proxy.config.http.flow_control.enabled": flow_control,
        })
    size = 4 * MiB
    path = f"/8192/followers/{size}"
    leader = lambda: get(ats.http_port, "plain", path, stall_after=2 * MiB, stall_for=5.0)
    follower = lambda: get(ats.http_port, "plain", path)
    first, *followers = run_together([(0.0, leader)] + [(0.5, follower)] * 3)

    assert first["complete"], first
    for result in followers:
        if lead:
            assert result["complete"], result
            assert result["t_end"] < first["t_resume"] - 3.0, result
        else:
            assert not result["complete"] or result["t_end"] > first["t_resume"] - 0.5, result
    assert len(origin.requests(path)) == 1


@pytest.mark.parametrize("lead", (pytest.param(0, id="off"), pytest.param(4 * MiB, id="on")))
def test_cache_write_lead_bound(ats_factory: ATSFactory, services: ServiceFactory, lead: int) -> None:
    """A client that stops reading makes Traffic Server read at most the lead ahead of it.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param lead: proxy.config.http.cache.max_write_lead.
    """

    ats, origin = configure(ats_factory, services, {"proxy.config.http.cache.max_write_lead": lead})
    size = 16 * MiB
    path = f"/0/bound/{size}"
    read = 256 * KiB
    results = []
    leader = threading.Thread(
        target=lambda: results.append(get(ats.http_port, "plain", path, stall_after=read, stall_for=3.0)), daemon=True)
    leader.start()
    time.sleep(2.0)
    ahead = origin.sent(path) - read
    leader.join()

    assert results[0]["complete"], results[0]
    # Socket buffers on both sides, the default buffer water mark and partly filled buffer blocks: about 0.9 MiB here.
    slack = 3 * MiB // 2
    assert lead <= ahead <= lead + slack


@pytest.mark.parametrize("lead", (pytest.param(0, id="off"), pytest.param(LEAD, id="on")))
def test_cache_write_lead_client_abort(ats_factory: ATSFactory, services: ServiceFactory, lead: int) -> None:
    """With a lead, the background fill threshold counts the bytes read from the origin, which are ahead of the client.

    The client aborts when the origin has sent about 65% of the object and the client has read less than 15%. With
    the threshold at 50%, only the lead lets the fill go on and store the object.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param lead: proxy.config.http.cache.max_write_lead.
    """

    ats, origin = configure(
        ats_factory, services, {
            "proxy.config.http.cache.max_write_lead": lead,
            "proxy.config.cache.enable_read_while_writer": 0,
            "proxy.config.http.background_fill_completed_threshold": 0.5,
        })
    size = 4 * MiB
    path = f"/2048/abort/{size}"
    read = 256 * KiB
    first = get(ats.http_port, "plain", path, stall_after=read, stall_for=1.3, close_after=read + 16 * KiB)
    assert first["outcome"] == "reset", first
    origin.wait_idle(path)

    second = get(ats.http_port, "plain", path)
    assert second["complete"], second
    assert len(origin.requests(path)) == (1 if lead else 2)


def test_cache_write_lead_cache_write_fails(ats_factory: ATSFactory, services: ServiceFactory) -> None:
    """When the cache write fails, the read waits for the client again, and the client still gets the whole body.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    """

    ats, origin = configure(
        ats_factory, services, {
            "proxy.config.http.cache.max_write_lead": 16 * MiB,
            "proxy.config.cache.enable_read_while_writer": 0,
            "proxy.config.cache.max_doc_size": 1 * MiB,
        })
    size = 8 * MiB
    path = f"/4096/fails/{size}"
    results = []
    leader = threading.Thread(
        target=lambda: results.append(get(ats.http_port, "plain", path, stall_after=256 * KiB, stall_for=3.0)), daemon=True)
    leader.start()
    # The origin would have sent the whole object by now if the lead had stayed.
    time.sleep(2.5)
    sent = origin.sent(path)
    leader.join()

    assert results[0]["complete"], results[0]
    assert sent < 4 * MiB
    assert get(ats.http_port, "plain", path)["complete"]
    assert len(origin.requests(path)) == 2


@pytest.mark.parametrize("lead", (pytest.param(0, id="off"), pytest.param(LEAD, id="on")))
def test_cache_write_lead_http2(ats_factory: ATSFactory, services: ServiceFactory, curl: Curl, lead: int) -> None:
    """A slow HTTP/2 client gets the whole body, and with a lead the requests that read the object while it is
    written do not wait for it.

    :param ats_factory: Factory for isolated Traffic Server instances.
    :param services: Factory owning support services and their cleanup.
    :param curl: Transport-aware curl command runner.
    :param lead: proxy.config.http.cache.max_write_lead.
    """

    if not curl.supports("http2") or curl.uses_uds:
        pytest.skip("needs curl with HTTP/2 over a TCP listener")
    ats, origin = configure(ats_factory, services, {"proxy.config.http.cache.max_write_lead": lead}, enable_tls=True)
    size = 4 * MiB
    path = f"/8192/h2/{size}"
    output = Path(ats_factory.run_directory) / "h2.out"

    def leader() -> dict:
        result = curl.run(
            f"--http2 --insecure --silent --limit-rate {512 * KiB} --output {output} "
            f"--resolve plain:{ats.https_port}:127.0.0.1 https://plain:{ats.https_port}{path}",
            timeout=30)
        return {"returncode": result.returncode}

    follower = lambda: get(ats.http_port, "plain", path)
    first, *followers = run_together([(0.0, leader)] + [(0.5, follower)] * 3)

    assert first["returncode"] == 0
    assert output.read_bytes() == body(0, size)
    for result in followers:
        assert result["complete"], result
        # The slow client needs 8 s for the object, the origin 0.5 s.
        if lead:
            assert result["t_end"] - result["t_start"] < 2.0, result
        else:
            assert result["t_end"] - result["t_start"] > 4.0, result
    assert len(origin.requests(path)) == 1
