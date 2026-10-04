"""M1 exit criteria on a small run: every source lands, 100% ECS-valid, ground truth landed."""
import argparse
from datetime import date

from fastapi.testclient import TestClient

from benchmarks.ground_truth_check import check
from engine.api.query_api import create_app as query_app
from engine.cli import LocalClient, cmd_ecs_check, cmd_ingest
from engine.generator.emitters import SOURCES
from engine.generator.run import generate


def test_generate_ingest_validate(settings, runtime):
    manifest = generate(settings, runtime.store, run_id="t", start=date(2026, 9, 7), days=5, users=10, seed=7)
    assert set(manifest["records_by_source"]) == set(SOURCES)
    assert (settings.ground_truth_dir / "t" / "labels.json").exists()
    assert not runtime.store.list(settings.buckets.incoming, suffix="labels.json")   # labels never in storage

    client = LocalClient.__new__(LocalClient)
    client.rt = runtime
    result = cmd_ingest(argparse.Namespace(run_id="t", local=True), settings, client)
    assert result["outcome"] == {"succeeded": len(manifest["batches"])}

    report = cmd_ecs_check(None, settings)
    assert report["rows"] == manifest["records"] and report["valid_pct"] == 100.0

    gt = check(settings, "t")
    assert gt["all_events_landed"] and gt["scenarios"] >= 5

    q = TestClient(query_app(runtime))
    parts = q.get("/partitions", params={"source": "zeek_conn"}).json()
    assert parts["total"] > 0 and parts["projected_at"]
    pid = parts["items"][0]["partition_id"]
    health = q.get(f"/partitions/{pid}/health").json()
    assert health["stages"]["landed"] and not health["sealed"]
    batches = q.get("/batches", params={"source": "proxy"}).json()["items"]
    assert all(b["rows_invalid"] == 0 for b in batches)
    assert all("host:unresolved" not in (b["resolution"] or {}) for b in batches)


def test_reingest_is_idempotent(settings, runtime):
    generate(settings, runtime.store, run_id="r", start=date(2026, 9, 7), days=2, users=4, seed=1)
    client = LocalClient.__new__(LocalClient)
    client.rt = runtime
    args = argparse.Namespace(run_id="r", local=True)
    cmd_ingest(args, settings, client)
    rows_before = cmd_ecs_check(None, settings)["rows"]
    cmd_ingest(args, settings, client)   # same idempotency keys → no new commands
    assert cmd_ecs_check(None, settings)["rows"] == rows_before
