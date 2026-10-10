"""M7 exit criterion: a ThreatFox IOC planted in generated logs is ingested, swept, and appears in
ti.tactical.org_sightings, ti.operational (origin=feed_match) and ti.strategic. Plus the connector
SDK, warninglists, TLP enforcement, analyst indicators, budget deferral and the scheduler."""
import json
import sys
import uuid

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from engine.cli import LocalClient
from engine.common.db import rule_runs
from engine.cqrs.commands import PullFeed, RecordIndicator, ReleaseDeferred
from engine.ti import tables as T
from engine.ti.connectors.sdk import make_connector, registry

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="PyIceberg local IO needs POSIX paths")
EXPECTED = {"threatfox": 7, "urlhaus": 3, "malwarebazaar": 4, "feodo": 2, "sslbl": 2, "csv_blocklist": 5, "misp": 2,
            "stix1_taxii1": 3, "cisa_kev": 2, "mitre_attack": 0}


@pytest.fixture(scope="module")
def client(pipeline):
    c = LocalClient.__new__(LocalClient)
    c.rt = pipeline
    return c


def tactical(pipeline, value=None):
    rows, _ = T.read_all(pipeline.settings, T.TACTICAL)
    return [r for r in rows if value is None or r["value"] == value]


def test_every_legacy_connector_parses_its_sample():
    found = registry()
    assert set(EXPECTED) <= set(found)
    for name, n in EXPECTED.items():
        c = make_connector(name)
        records = [i for raw in c.fetch(None) for i in c.parse(raw)]
        assert len(records) == n, (name, len(records))


@pytest.fixture(scope="module")
def threatfox_pulled(pipeline, client):
    client.wait([client.submit(PullFeed(connector="threatfox"))])
    pipeline.drain(pipeline=True)                 # sweep -> sightings -> rollups
    return pipeline


def test_threatfox_ioc_is_ingested_swept_and_sighted(threatfox_pulled):
    p = threatfox_pulled
    c2 = tactical(p, "203.0.113.80:80")
    assert c2 and c2[0]["source"] == "threatfox" and c2[0]["malware_family"] == "Cobalt Strike"
    assert c2[0]["org_sightings"] > 0 and c2[0]["org_first_sighting"] is not None
    assert tactical(p, "update-check.badcdn.example")[0]["org_sightings"] > 0
    assert tactical(p, "198.51.100.199:443")[0]["org_sightings"] == 0          # decoy: never in the logs
    assert tactical(p, "1.1.1.1:443")[0]["status"] == "false_positive"          # warninglist
    with p.engine.connect() as conn:
        sweep = conn.execute(select(rule_runs).where(rule_runs.c.origin == "feed_sweep")).first()
    assert sweep.status == "succeeded" and sweep.plan["tiers"] == [3] and sweep.approval_level == "auto"
    assert 0 < sweep.bytes_restored < sweep.plan["full_rehydration_bytes"]
    op, _ = T.read_all(p.settings, T.OPERATIONAL)
    feed = [r for r in op if r["origin"] == "feed_match"]
    assert any(r["threat_family"] == "Cobalt Strike" and c2[0]["indicator_id"] in r["matched_indicator_ids"]
               for r in feed)
    st, _ = T.read_all(p.settings, T.STRATEGIC)
    cs = [r for r in st if r["threat_family"] == "Cobalt Strike" and r["period_type"] == "month"]
    assert cs and sum(r["feed_indicator_hits"] for r in cs) > 0


def test_repeat_pull_finds_nothing_new_and_queues_no_sweep(threatfox_pulled, client):
    p = threatfox_pulled
    with p.engine.connect() as conn:
        before = len(conn.execute(select(rule_runs).where(rule_runs.c.origin == "feed_sweep")).all())
    client.wait([client.submit(PullFeed(connector="threatfox"))])
    with p.engine.connect() as conn:
        after = len(conn.execute(select(rule_runs).where(rule_runs.c.origin == "feed_sweep")).all())
    assert before == after


def test_tlp_is_enforced_on_export_and_llm_egress(threatfox_pulled, client):
    p = threatfox_pulled
    client.wait([client.submit(PullFeed(connector="misp"))])
    red = tactical(p, "login-portal.decoy.example")
    assert red and red[0]["tlp"] == "TLP:RED"
    api = TestClient(__import__("engine.api.query_api", fromlist=["x"]).create_app(p))
    exported = api.get("/ti/export?tlp_max=TLP:AMBER").json()
    assert "login-portal.decoy.example" not in {x["value"] for x in exported["items"]}
    assert exported["withheld_by_tlp"] >= 1
    from engine.ti.bundler import Redactor
    with p.engine.connect() as conn:
        r = Redactor(conn, p.settings)
    assert "login-portal.decoy.example" in r.restricted
    assert r.value("dns.question.name", "login-portal.decoy.example").startswith("ioc_")
    feeds = api.get("/ti/feeds").json()
    assert {f["connector"]: f for f in feeds["items"]}["threatfox"]["pulls"] >= 1


def test_analyst_indicator_triggers_a_sweep(threatfox_pulled, client):
    p = threatfox_pulled
    client.wait([client.submit(RecordIndicator(value="203.0.113.66", threat_type="brute_force", analyst="alice"))])
    p.drain(pipeline=True)
    row = tactical(p, "203.0.113.66")
    assert row and row[0]["source"] == "analyst" and row[0]["org_sightings"] >= 100   # brute force burst


def test_budget_deferral_and_release(threatfox_pulled, client, monkeypatch):
    from engine.cost import estimator
    p = threatfox_pulled
    real = estimator.thresholds()
    monkeypatch.setattr(estimator, "thresholds", lambda: {**real, "daily_budget": 0})
    client.wait([client.submit(PullFeed(connector="csv_blocklist"))])
    with p.engine.connect() as conn:
        deferred = conn.execute(select(rule_runs).where(rule_runs.c.status == "deferred_budget")).all()
    assert deferred
    monkeypatch.setattr(estimator, "thresholds", lambda: real)
    client.wait([client.submit(ReleaseDeferred(day=str(uuid.uuid4())))])
    p.drain(pipeline=True)
    with p.engine.connect() as conn:
        run = conn.execute(select(rule_runs).where(rule_runs.c.run_id == deferred[0].run_id)).one()
    assert run.status == "succeeded"
    assert tactical(p, "files-share.example")[0]["org_sightings"] > 0


def test_scheduler_submits_due_pulls_once(threatfox_pulled):
    from engine.ti.scheduler import due
    names = {c.connector for c in due(threatfox_pulled.engine)}
    assert "threatfox" not in names and "urlhaus" in names and "misp" not in names   # misp disabled


def test_threatfox_api_mode_over_http(monkeypatch):
    seen = {}

    def handler(request: httpx.Request):
        seen["auth"] = request.headers.get("auth-key")
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"query_status": "ok", "data": [
            {"id": "1", "ioc": "192.0.2.10:443", "ioc_type": "ip:port", "threat_type": "botnet_cc",
             "malware_printable": "Synthetic", "confidence_level": 50, "first_seen": "2026-10-01 00:00:00 UTC"}]})
    monkeypatch.setenv("TI_FEEDS_OFFLINE", "0")
    monkeypatch.setenv("THREATFOX_AUTH_KEY", "test-key")
    c = make_connector("threatfox", transport=httpx.MockTransport(handler))
    records = [i for raw in c.fetch(None) for i in c.parse(raw)]
    assert seen == {"auth": "test-key", "body": {"query": "get_iocs", "days": 1}}
    assert records[0].type == "ip:port" and records[0].malware_family == "Synthetic"
