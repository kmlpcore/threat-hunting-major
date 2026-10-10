"""M5 exit criteria: the benchmark corpus runs; every run reports tiers, coverage %, bytes,
estimated and actual cost; reruns at pinned snapshots are identical. Plus fidelity: rules
answered at tier 1/2 lose nothing against a full rehydration."""
import json
import sys
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from benchmarks.fidelity import compare, corpus, raw_baseline, submit_corpus
from engine.cli import LocalClient
from engine.common.db import rule_runs, snapshot_leases
from engine.cqrs.commands import ApproveRun, SubmitRule
from engine.rules.compiler import CompileError, compile_sigma

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="PyIceberg local IO needs POSIX paths")

START = datetime(2026, 9, 7, tzinfo=timezone.utc)
END = datetime(2026, 9, 13, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def client(pipeline):
    c = LocalClient.__new__(LocalClient)
    c.rt = pipeline
    return c


@pytest.fixture(scope="module")
def corpus_runs(client):
    return submit_corpus(client, START, END, corpus())


def test_unsupported_sigma_is_rejected_at_submit(pipeline):
    bad = """
title: x
logsource: {category: process_creation, product: windows}
detection:
  sel: {NoSuchField: 1}
  condition: sel
"""
    with pytest.raises(CompileError) as exc:
        compile_sigma(bad)
    assert "NoSuchField" in str(exc.value)
    from engine.api.command_api import create_app
    resp = TestClient(create_app(pipeline)).post("/commands/SubmitRule", json={
        "rule_yaml": bad, "start": START.isoformat(), "end": END.isoformat()})
    assert resp.status_code == 422 and "NoSuchField" in json.dumps(resp.json())


def test_corpus_runs_and_reports_tiers_coverage_bytes_and_costs(corpus_runs):
    assert len(corpus_runs) == len(corpus())
    for name, run in corpus_runs.items():
        assert run["status"] == "succeeded", (name, run)
        assert run["tiers"] and run["coverage_pct"] is not None
        assert run["estimated_cost"] is not None and run["actual_cost"] is not None
        assert run["bytes_scanned"] is not None and run["bytes_restored"] is not None
    tiers = {n: max(r["tiers"]) for n, r in corpus_runs.items()}
    assert tiers["win_office_spawns_shell"] == 1 and tiers["win_psexec_service"] == 1
    assert tiers["win_password_spray"] == 2 and tiers["dns_tunnelling"] == 2
    assert tiers["dns_ioc_domains"] == 3 and tiers["ecs_documentation_range_traffic"] == 3
    t12 = sum(1 for t in tiers.values() if t <= 2)
    detail = {n: (t, r["estimated_cost"], r["steps"][0]["capability"]) for n, r in corpus_runs.items()
              for t in [max(r["tiers"])]}
    assert t12 / len(tiers) >= 0.70, detail              # plan.md 11: tier-hit rate target


def test_expensive_scan_needed_approval(corpus_runs):
    broad = corpus_runs["ecs_documentation_range_traffic"]
    assert broad["approval_level"] in ("hunter", "manager")
    assert {a["approver"] for a in broad["approvals"]} >= {"benchmark-hunter"}
    ioc = corpus_runs["dns_ioc_domains"]
    assert ioc["approval_level"] == "auto"
    assert 0 < ioc["bytes_restored"] < broad["bytes_restored"]


def test_tier12_recall_is_complete_against_full_rehydration(pipeline, corpus_runs, client):
    with pipeline.engine.connect() as conn:
        for name, text in corpus():
            run = corpus_runs[name]
            hits = client.query(f"/rules/{run['rule_id']}/runs/{run['run_id']}/hits?limit=20000")["items"]
            raw = raw_baseline(conn, pipeline.store, pipeline.settings, text, START, END)
            c = compare(hits, raw)
            if raw:
                assert c["entity_recall"] == 1.0, (name, c)
            if "event_recall" in c and c["event_recall"] is not None:
                assert c["event_recall"] == 1.0, (name, c)
    spray = corpus_runs["win_password_spray"]
    hits = client.query(f"/rules/{spray['rule_id']}/runs/{spray['run_id']}/hits")["items"]
    assert any(json.loads(h["group_key"])["source.ip"] == "198.51.100.23" for h in hits)


def test_replay_at_pinned_snapshots_is_identical(pipeline, client, corpus_runs):
    original = corpus_runs["win_encoded_powershell"]
    with pipeline.engine.connect() as conn:
        leases = conn.execute(select(snapshot_leases).where(snapshot_leases.c.run_id == original["run_id"])).all()
    assert leases, "executor must lease the snapshots it read"
    replay_id = str(uuid.uuid4())
    text = dict(corpus())["win_encoded_powershell"]
    client.wait([client.submit(SubmitRule(rule_yaml=text, start=START, end=END, run_id=replay_id,
                                          replay_of=original["run_id"]))])
    with pipeline.engine.connect() as conn:
        rows = {r.run_id: r for r in conn.execute(select(rule_runs).where(
            rule_runs.c.run_id.in_([original["run_id"], replay_id])))}
    assert rows[replay_id].status == "succeeded"
    assert rows[replay_id].hits_hash == rows[original["run_id"]].hits_hash
    assert {k: v for k, v in rows[replay_id].snapshot_ids.items() if k != "raw"} == \
        {k: v for k, v in rows[original["run_id"]].snapshot_ids.items() if k != "raw"}


def test_safety_cap_blocks_regardless_of_approval(pipeline, client, monkeypatch):
    from engine.cost import estimator
    real = estimator.thresholds()
    monkeypatch.setattr(estimator, "thresholds", lambda: {**real, "max_restore_bytes": 1})
    run_id = str(uuid.uuid4())
    text = dict(corpus())["dns_ioc_domains"]
    client.wait([client.submit(SubmitRule(rule_yaml=text, start=START, end=END, run_id=run_id))])
    client.wait([client.submit(ApproveRun(run_id=run_id, approver="someone", role="manager"))])
    with pipeline.engine.connect() as conn:
        run = conn.execute(select(rule_runs).where(rule_runs.c.run_id == run_id)).one()
    assert run.status == "blocked" and run.approval_level == "blocked" and run.hits is None


def test_query_api_exposes_runs_estimates_and_costs(pipeline, corpus_runs):
    from engine.api.query_api import create_app
    api = TestClient(create_app(pipeline))
    run = corpus_runs["win_brute_force"]
    est = api.get(f"/rules/{run['rule_id']}/runs/{run['run_id']}/estimate").json()
    assert est["estimate"]["currency"] == "USD" and est["estimate"]["pricing_version"]
    costs = api.get("/costs").json()
    assert costs["runs"] >= len(corpus_runs) and costs["estimate_error"]["median"] is not None
    assert api.get("/rules").json()["items"]
