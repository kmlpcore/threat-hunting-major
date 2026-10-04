"""M2-M4 exit criteria end-to-end in local mode (SQLite catalog + local files).

Runs on Linux (the engine container): PyIceberg's local file IO does not support
Windows drive paths. In compose the same code runs against Lakekeeper + MinIO.
"""
import argparse
import sys
from datetime import date

import pytest
from sqlalchemy import select

from engine.cli import LocalClient, cmd_ingest
from engine.common import catalog as catalog_mod
from engine.common.catalog import get_catalog, read_table, table_stats
from engine.common.db import partitions, seal_manifest, stage_runs
from engine.cqrs.commands import RegisterFeature
from engine.generator.run import generate
from engine.indexer.search import Searcher
from engine.summary.tables import TABLES

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="PyIceberg local IO needs POSIX paths")


@pytest.fixture(scope="module")
def settings(tmp_path_factory):
    from engine.common.config import Settings
    tmp = tmp_path_factory.mktemp("pipeline")
    return Settings.from_env().with_overrides(
        database_url=f"sqlite:///{(tmp / 'engine.db').as_posix()}", bus_url="memory://", storage_backend="local",
        local_storage_root=tmp / "objects", ground_truth_dir=tmp / "gt", lakekeeper_url=None)


@pytest.fixture(scope="module")
def runtime(settings):
    from engine.cqrs.runtime import Runtime
    return Runtime.from_settings(settings, create_tables=True)


@pytest.fixture(scope="module")
def pipeline(settings, runtime):
    catalog_mod.reset_catalog()
    generate(settings, runtime.store, run_id="p", start=date(2026, 9, 7), days=6, users=10, seed=3)
    client = LocalClient.__new__(LocalClient)
    client.rt = runtime
    cmd_ingest(argparse.Namespace(run_id="p", local=True), settings, client)
    runtime.drain(pipeline=True)
    yield runtime
    catalog_mod.reset_catalog()


def test_m2_summaries_carry_policy_version_and_ratio(pipeline, settings):
    cat = get_catalog(settings)
    stats = {t.identifier: table_stats(cat, t.identifier) for t in TABLES.values()}
    assert all(s["rows"] > 0 for s in stats.values()), stats
    auth, _ = read_table(cat, "summary.auth_hourly")
    assert set(auth.column("policy_version").to_pylist()) == {"1.0.0"}
    with pipeline.engine.connect() as conn:
        raw_bytes = sum(r.bytes for r in conn.execute(select(partitions)))
    assert sum(s["bytes"] for s in stats.values()) < raw_bytes


def test_m3_ioc_sweep_full_recall_and_bm25(pipeline, settings):
    s = Searcher(pipeline.engine, pipeline.store, settings, settings.local_storage_root / "cache")
    res = s.ioc_sweep("203.0.113.80")              # encoded PowerShell C2, day 2
    assert res["stats"]["hits"] >= 3                # dns answer + conn + proxy
    assert res["stats"]["partitions_after_bloom"] < res["stats"]["partitions_in_range"]
    assert res["stats"]["bytes_restored"] < res["stats"]["full_rehydration_bytes"]
    text = s.text_search("powershell enc hidden bypass", limit=10)
    assert any("powershell" in (e.get("process.command_line") or "").lower() for e in text["events"])


def test_m4_features_never_read_raw_and_partitions_seal(pipeline, settings):
    with pipeline.engine.connect() as conn:
        feature_runs = conn.execute(select(stage_runs).where(stage_runs.c.stage == "features")).all()
        assert feature_runs and all(r.detail["raw_bytes_read"] == 0 for r in feature_runs)
        n_parts = conn.execute(select(partitions)).all()
        sealed = [p for p in n_parts if p.sealed]
    assert len(sealed) == len(n_parts)
    tags = pipeline.store.get_tags(f"{settings.buckets.raw}/{sealed[0].partition_id}/"
                                   f"part-p-{sealed[0].source}-{sealed[0].date.replace('-', '')}.parquet")
    assert tags["sealed"] == "true"


def test_m4_backfill_of_new_feature_version_touches_no_raw(pipeline, settings):
    raw_before = pipeline.store.bytes_read[settings.buckets.raw]
    pipeline.submit(RegisterFeature(feature="dns_beaconing", version="1"))
    pipeline.drain(pipeline=True)
    with pipeline.engine.connect() as conn:
        runs = conn.execute(select(stage_runs).where(stage_runs.c.scope.like("dns_beaconing@1/%"))).all()
        conn_days = {p.date for p in conn.execute(select(partitions).where(partitions.c.source == "zeek_conn"))}
    assert len(runs) == len(conn_days) and all(r.detail["raw_bytes_read"] == 0 for r in runs)
    assert pipeline.store.bytes_read[settings.buckets.raw] == raw_before
    rows, _ = read_table(get_catalog(settings), "artefacts.dns_beaconing")
    assert ("198.51.100.77", 3333) in set(zip(rows.column("dest_ip").to_pylist(), rows.column("dest_port").to_pylist()))


def test_m4_late_data_lands_beside_sealed_partition_and_reseals(pipeline, settings):
    from engine.cqrs.commands import IngestBatch
    from engine.generator.emitters import Sink
    import random
    from datetime import datetime, timezone
    sink = Sink(rng=random.Random(1))
    sink.metric(datetime(2026, 9, 8, 10, 33, tzinfo=timezone.utc), "APP01", 50.0, 50.0, 1, 1, 600)
    uri = f"{settings.buckets.incoming}/late/batch.jsonl.gz"
    pipeline.store.put_jsonl_gz(uri, [e.record for e in sink.entries["host_metrics"]])
    pipeline.submit(IngestBatch(batch_id="late-1", batch_uri=uri, source="host_metrics"))
    pipeline.drain(pipeline=True)
    pid = "source=host_metrics/date=2026-09-08/hour=10"
    assert pipeline.store.exists(f"{settings.buckets.raw}/late/{pid}/part-late-1.parquet")
    with pipeline.engine.connect() as conn:
        versions = [r.seal_version for r in conn.execute(
            select(seal_manifest).where(seal_manifest.c.partition_id == pid))]
    assert sorted(versions) == [1, 2]
