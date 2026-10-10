"""M8 exit criteria: a simulated 15-year partition layout is queryable and the year-on-year
strategic comparison works. Plus retention enforcement, legal hold, snapshot tagging/expiry
with reproducible replays, compaction and the readability drill.

Named to run last: it adds history to the shared dataset and ages it with `as_of`."""
import argparse
import sys
import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from benchmarks.fidelity import corpus, submit_corpus
from engine.cli import LocalClient, cmd_history
from engine.common import stages
from engine.common.catalog import get_catalog, read_table
from engine.common.db import partitions, rule_runs, snapshot_leases
from engine.cqrs.commands import ApplyRetention, CompactTable, ReadabilityDrill, SetLegalHold, SubmitRule
from engine.retention.policy import RetentionPolicyError, validate

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="PyIceberg local IO needs POSIX paths")
YEARS = ["2012", "2021", "2025"]
FULL_START = datetime(2011, 10, 15, tzinfo=timezone.utc)
FULL_END = datetime(2026, 12, 31, tzinfo=timezone.utc)
FUTURE = "2027-10-01"                     # 15 years after this, 2012-09-08 is past retention


@pytest.fixture(scope="module")
def client(pipeline):
    c = LocalClient.__new__(LocalClient)
    c.rt = pipeline
    return c


@pytest.fixture(scope="module")
def history(pipeline, client, pl_settings):
    out = cmd_history(argparse.Namespace(years=15, anchor="2026-09-08", days=1, users=10, seed=3, only=YEARS,
                                         local=True), pl_settings)
    pipeline.drain(pipeline=True)
    return out


@pytest.fixture(scope="module")
def long_runs(history, client, pipeline):
    rules = [r for r in corpus() if r[0] in ("win_brute_force", "win_password_spray", "win_encoded_powershell",
                                             "dns_tunnelling", "win_miner_commandline", "net_smb_fanout")]
    runs = submit_corpus(client, FULL_START, FULL_END, rules)
    pipeline.drain(pipeline=True)
    return runs


def test_policy_never_goes_below_15_years():
    with pytest.raises(RetentionPolicyError):
        validate({"minimum_years": 10, "layers": {}})
    with pytest.raises(RetentionPolicyError):
        validate({"minimum_years": 15, "layers": {"raw": {"years": 7}}})
    with pytest.raises(RetentionPolicyError):
        validate({"minimum_years": 15, "layers": {}, "overrides": [{"layer": "raw", "years": 3}]})


def test_multi_year_layout_is_sealed_and_queryable(history, pipeline, long_runs):
    with pipeline.engine.connect() as conn:
        years = {r.date[:4] for r in conn.execute(select(partitions.c.date))}
        unsealed = conn.execute(select(partitions).where(partitions.c.sealed.is_(False))).all()
    assert set(YEARS) | {"2026"} <= years and not unsealed
    status = TestClient(__import__("engine.api.query_api", fromlist=["x"]).create_app(pipeline)).get("/retention").json()
    assert status["minimum_years"] == 15 and status["span_years"] > 14
    assert all(layer["years"] >= 15 for layer in status["layers"].values())
    for name, run in long_runs.items():
        assert run["status"] == "succeeded", name
    hits, _ = read_table(get_catalog(pipeline.settings), "results.rule_hits")
    brute = long_runs["win_brute_force"]["run_id"]
    days = {d for d, r in zip(hits.column("day").to_pylist(), hits.column("run_id").to_pylist()) if r == brute}
    assert {d[:4] for d in days} >= {"2021", "2025", "2026"}


def test_year_on_year_strategic_comparison(long_runs, pipeline):
    api = TestClient(__import__("engine.api.query_api", fromlist=["x"]).create_app(pipeline))
    res = api.get("/ti/strategic?period=year&compare=yoy").json()
    rows = {(r["period_start"][:4], r["tactic"]): r for r in res["comparison"]}
    cred = rows[("2026", "credential-access")]
    assert cred["same_period_last_year"] > 0 and cred["previous_period"] > 0
    assert {y for y, _ in rows} >= {"2012", "2021", "2025", "2026"}


def test_readability_drill_reads_every_year_and_fails_loudly(history, pipeline, client):
    cid = client.submit(ReadabilityDrill(partitions_per_year=3))
    assert client.wait([cid])[cid]["status"] == "succeeded"
    with pipeline.engine.connect() as conn:
        latest = max(stages.runs(conn, "readability").values(), key=lambda r: r.finished_at)
    assert latest.generation == "ok" and {2012, 2021, 2025, 2026} <= set(latest.detail["years"])
    # corrupt one archived object of 2021: the drill must fail and say where
    with pipeline.engine.connect() as conn:
        victims = conn.execute(select(partitions).where(partitions.c.date.like("2021-%"))).all()
    from engine.common.db import partition_files
    with pipeline.engine.connect() as conn:
        files = [f.file for p in victims for f in conn.execute(
            select(partition_files).where(partition_files.c.partition_id == p.partition_id))]
    original = {f: pipeline.store.get_bytes(f) for f in files}
    try:
        for f in files:
            pipeline.store.put_bytes(f, b"not parquet")
        cid = client.submit(ReadabilityDrill(partitions_per_year=1000))
        status = client.wait([cid])[cid]
        assert status["status"] in ("failed", "retrying") and "readability drill failed" in status["error"]
    finally:
        for f, data in original.items():
            pipeline.store.put_bytes(f, data)


def test_retention_respects_legal_hold_then_removes_expired_days(long_runs, pipeline, client):
    cat = get_catalog(pipeline.settings)

    def days_2012():
        t, _ = read_table(cat, "summary.auth_hourly")
        return {d for d in t.column("day").to_pylist() if d.startswith("2012")}
    assert days_2012()
    client.wait([client.submit(SetLegalHold(scope="source=windows_security/date=2012-09-08", reason="case 42",
                                            actor="legal"))])
    client.wait([client.submit(ApplyRetention(layer="summary", as_of=FUTURE))])
    assert days_2012(), "held day must survive retention"
    client.wait([client.submit(SetLegalHold(scope="source=windows_security/date=2012-09-08", reason="case 42",
                                            actor="legal", on=False))])
    client.wait([client.submit(ApplyRetention(layer="summary", as_of=FUTURE, slot=str(uuid.uuid4())))])
    assert not days_2012()
    raw = client.wait([cid := client.submit(ApplyRetention(layer="raw", as_of=FUTURE, dry_run=True))])[cid]
    assert raw["status"] == "succeeded" and raw["detail"]["deleted_objects"] > 0 and raw["detail"]["dry_run"]


def test_result_snapshots_are_tagged_and_replays_survive_expiry(long_runs, pipeline, client):
    run = long_runs["win_encoded_powershell"]
    client.wait([client.submit(ApplyRetention(layer="summary", as_of="2030-01-01", slot=str(uuid.uuid4())))])
    with pipeline.engine.connect() as conn:
        leases = conn.execute(select(snapshot_leases).where(snapshot_leases.c.run_id == run["run_id"])).all()
    hv = get_catalog(pipeline.settings).load_table("summary.high_value_events")
    assert leases and all(lease.tagged for lease in leases)
    assert f"run-{run['run_id']}" in hv.metadata.refs
    replay = str(uuid.uuid4())
    client.wait([client.submit(SubmitRule(rule_yaml=dict(corpus())["win_encoded_powershell"], start=FULL_START,
                                          end=FULL_END, run_id=replay, replay_of=run["run_id"]))])
    with pipeline.engine.connect() as conn:
        rows = {r.run_id: r for r in conn.execute(select(rule_runs).where(rule_runs.c.run_id.in_([run["run_id"], replay])))}
    assert rows[replay].status == "succeeded" and rows[replay].hits_hash == rows[run["run_id"]].hits_hash


def test_compaction_reduces_files(long_runs, pipeline, client):
    cid = client.submit(CompactTable(table="results.rule_hits"))
    res = client.wait([cid])[cid]
    assert res["status"] == "succeeded" and res["detail"]["files_after"] <= res["detail"]["files_before"]
