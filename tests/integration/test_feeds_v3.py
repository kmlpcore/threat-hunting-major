"""v3 exit criterion: a new connector is added without changes outside engine/ti/connectors/.
Plus the modern connectors (TAXII 2.1 / STIX 2.1, OTX, AbuseIPDB) and push feeds."""
import json
import sys
import textwrap
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

import engine.ti.connectors as connectors_pkg
from engine.cli import LocalClient
from engine.cqrs.commands import PullFeed
from engine.ti import tables as T
from engine.ti.connectors.sdk import make_connector, registry

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="PyIceberg local IO needs POSIX paths")


@pytest.fixture(scope="module")
def client(pipeline):
    c = LocalClient.__new__(LocalClient)
    c.rt = pipeline
    return c


def test_modern_connectors_parse_their_samples():
    counts = {}
    for name in ("taxii21", "otx", "abuseipdb", "webhook"):
        c = make_connector(name)
        assert c.feed_generation == "modern"
        counts[name] = [i for raw in c.fetch(None) for i in c.parse(raw)]
    assert len(counts["taxii21"]) == 3 and len(counts["otx"]) == 2 and len(counts["abuseipdb"]) == 2
    taxii = {i.value: i for i in counts["taxii21"]}
    assert taxii["203.0.113.200"].tlp == "TLP:GREEN" and taxii["203.0.113.200"].type == "ipv4"
    assert counts["otx"][0].attack_techniques == ["T1071.004"]


def test_new_connector_needs_no_changes_outside_connectors(pipeline, client, tmp_path):
    sample = tmp_path / "dropin.txt"
    sample.write_text("dropin-decoy.example\n198.51.100.77\n")
    module = Path(connectors_pkg.__path__[0]) / "zz_dropin_test.py"
    module.write_text(textwrap.dedent(f'''
        from engine.ti.connectors.sdk import FeedConnector, Indicator


        class DropIn(FeedConnector):
            name = "zz_dropin"
            version = "1"
            feed_generation = "modern"
            default_config = {{"enabled": True, "sample": "{sample.as_posix()}", "tlp": "TLP:GREEN"}}

            def fetch(self, since):
                return [self.http.get(self.config["sample"])]

            def parse(self, raw):
                return [Indicator(value=line.strip(), tags=["drop-in"])
                        for line in raw.body.decode().splitlines() if line.strip()]
    '''))
    try:
        registry.cache_clear()
        assert "zz_dropin" in registry()
        client.wait([client.submit(PullFeed(connector="zz_dropin"))])
        pipeline.drain(pipeline=True)
        rows, _ = T.read_all(pipeline.settings, T.TACTICAL)
        mine = {r["value"]: r for r in rows if r["source"] == "zz_dropin"}
        assert set(mine) == {"dropin-decoy.example", "198.51.100.77"}
        assert mine["198.51.100.77"]["org_sightings"] > 0           # cryptomining pool, swept from the logs
    finally:
        module.unlink()
        registry.cache_clear()


def test_push_feed_goes_through_the_same_path(pipeline):
    from engine.api.command_api import create_app
    api = TestClient(create_app(pipeline))
    payload = {"indicators": [{"value": "203.0.113.81", "type": "ipv4", "threat_type": "botnet_cc",
                               "confidence": 80, "tlp": "TLP:GREEN", "malware_family": "PushedFamily"}]}
    r = api.post("/ti/push/webhook", content=json.dumps(payload))
    assert r.status_code == 202 and r.json()["payload_uri"].startswith("incoming/feeds/webhook/")
    assert api.post("/ti/push/nope", content="{}").status_code == 404
    pipeline.drain(pipeline=True)
    rows, _ = T.read_all(pipeline.settings, T.TACTICAL)
    pushed = [x for x in rows if x["source"] == "webhook" and x["value"] == "203.0.113.81"]
    assert pushed and pushed[0]["malware_family"] == "PushedFamily" and pushed[0]["org_sightings"] > 0


def test_taxii21_pagination_and_auth(monkeypatch):
    pages = []

    def handler(request: httpx.Request):
        pages.append(dict(request.url.params))
        assert request.headers["accept"].startswith("application/taxii+json")
        assert request.headers["authorization"] == "Bearer tok"
        more = "next" not in request.url.params
        return httpx.Response(200, json={"more": more, "next": "p2" if more else None, "objects": [
            {"type": "indicator", "id": f"indicator--{len(pages)}", "pattern_type": "stix",
             "pattern": f"[ipv4-addr:value = '192.0.2.{len(pages)}']", "valid_from": "2026-10-01T00:00:00Z"}]})
    monkeypatch.setenv("TI_FEEDS_OFFLINE", "0")
    monkeypatch.setenv("TAXII21_TOKEN", "tok")
    c = make_connector("taxii21", transport=httpx.MockTransport(handler))
    c.config["url"] = "https://taxii.example/api1/"
    values = [i.value for raw in c.fetch(None) for i in c.parse(raw)]
    assert values == ["192.0.2.1", "192.0.2.2"] and pages[1]["next"] == "p2"
