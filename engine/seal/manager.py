"""Seal manager (plan.md section 3.7).

A partition (source/date/hour) is sealed when
  1. its source-day summaries are current (same generation + drop-policy version),
  2. its source-day index is current,
  3. every active feature version that reads its source is current for that day,
  4. hour end + grace <= max(source watermark, now - max lateness).

Sealing writes a manifest (row counts, files + ETags, job versions, Iceberg
snapshot ids) and tags each raw file `sealed=true`; the bucket lifecycle rule
transitions only tagged objects. Late data after a seal changes the partition's
generation → stages rebuild → the partition is re-sealed with seal_version + 1.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import yaml
from sqlalchemy import func, select
from sqlalchemy.engine import Connection

from engine.common import stages
from engine.common.config import REPO_ROOT
from engine.common.db import as_utc, partition_files, partitions, seal_manifest, upsert, utcnow
from engine.common.events import PartitionSealed
from engine.common.storage import ObjectStore
from engine.features.definitions import active_features
from engine.indexer.fts_tantivy import INDEX_VERSION
from engine.summary.policy import load_policy

log = logging.getLogger(__name__)


@lru_cache
def lifecycle_policy() -> dict:
    return yaml.safe_load((REPO_ROOT / "policies" / "lifecycle.yaml").read_text())


def hour_end(partition_id: str) -> datetime:
    _, d, h = (x.split("=", 1)[1] for x in partition_id.split("/"))
    return datetime.fromisoformat(f"{d}T{h}:00:00+00:00") + timedelta(hours=1)


@dataclass
class Readiness:
    partition_id: str
    ready: bool
    reasons: list[str]
    generation: str
    seal_version: int          # version the next seal would get
    already_sealed: bool


def watermarks(conn: Connection) -> dict[str, datetime]:
    return {r.source: as_utc(r.wm) for r in conn.execute(
        select(partitions.c.source, func.max(partitions.c.max_ts).label("wm")).group_by(partitions.c.source))}


def readiness(conn: Connection, partition_id: str, *, day_gens=None, part_gens=None, runs=None, feats=None,
              wms=None, now: datetime | None = None) -> Readiness:
    pol = lifecycle_policy()["seal"]
    source, day, _ = (x.split("=", 1)[1] for x in partition_id.split("/"))
    day_gens = day_gens if day_gens is not None else stages.day_generations(conn)
    part_gens = part_gens if part_gens is not None else stages.partition_generations(conn)
    runs = runs if runs is not None else stages.runs(conn)
    feats = feats if feats is not None else active_features(conn)
    wms = wms if wms is not None else watermarks(conn)
    now = now or utcnow()
    gen = part_gens.get(partition_id, "")
    dgen = day_gens.get((source, day), "")
    reasons = []

    if not stages.is_current(runs.get(("summary", f"{source}/{day}")), dgen, load_policy().version):
        reasons.append("summary not current")
    if not stages.is_current(runs.get(("index", f"{source}/{day}")), dgen, INDEX_VERSION):
        reasons.append("index not current")
    for f in feats:
        if source in f.input_sources:
            r = runs.get(("features", f"{f.key}/{day}"))
            if r is None or r.status != "succeeded" or r.version != f.definition_hash or \
                    (r.detail or {}).get("source_generations", {}).get(source) not in (None, dgen):
                reasons.append(f"feature {f.key} not current")
    end = hour_end(partition_id)
    wm = wms.get(source)
    complete_at = max(wm or end, now - timedelta(hours=pol["max_lateness_hours"]))
    if end + timedelta(hours=pol["grace_hours"]) > complete_at:
        reasons.append("within watermark grace window")

    latest = conn.execute(select(seal_manifest.c.seal_version, seal_manifest.c.generation)
                          .where(seal_manifest.c.partition_id == partition_id)
                          .order_by(seal_manifest.c.seal_version.desc()).limit(1)).first()
    already = latest is not None and latest.generation == gen
    if already:
        reasons.append("already sealed at this generation")
    return Readiness(partition_id, not reasons, reasons, gen, (latest.seal_version + 1) if latest else 1, already)


def seal_partition(conn: Connection, store: ObjectStore, partition_id: str, command_id: str) -> PartitionSealed:
    r = readiness(conn, partition_id)
    if not r.ready:
        raise RuntimeError(f"partition {partition_id} not ready to seal: {', '.join(r.reasons)}")
    source, day, _ = (x.split("=", 1)[1] for x in partition_id.split("/"))
    files = conn.execute(select(partition_files).where(partition_files.c.partition_id == partition_id)).all()
    runs = stages.runs(conn)
    feats = [f for f in active_features(conn) if source in f.input_sources]

    file_entries = []
    tag = lifecycle_policy()["archive"]["tag"]
    for f in files:
        store.set_tags(f.file, {tag["key"]: tag["value"], "seal_version": str(r.seal_version),
                                "partition": partition_id.replace("/", "_")})
        file_entries.append({"file": f.file, "bytes": f.bytes, "rows": f.rows, "batch_id": f.batch_id,
                             "late": "/late/" in f.file})
    summary = runs.get(("summary", f"{source}/{day}"))
    snapshot_ids = {t: v.get("snapshot_id") for t, v in ((summary.detail or {}).get("tables") or {}).items()}
    for f in feats:
        fr = runs.get(("features", f"{f.key}/{day}"))
        snapshot_ids[f"{f.output_table}#{f.version}"] = (fr.detail or {}).get("snapshot_id") if fr else None
    job_versions = {
        "ecs_mapping_versions": sorted({row.ecs_mapping_version for row in files}),
        "drop_policy": load_policy().version, "index": INDEX_VERSION,
        "features": {f.key: f.definition_hash for f in feats},
        "lifecycle_policy": lifecycle_policy()["version"],
    }
    rows = sum(f.rows for f in files)
    conn.execute(seal_manifest.insert().values(
        partition_id=partition_id, seal_version=r.seal_version, generation=r.generation, rows=rows,
        files=file_entries, job_versions=job_versions, snapshot_ids=snapshot_ids, sealed_at=utcnow(),
        command_id=command_id))
    upsert(conn, partitions, {"partition_id": partition_id}, {"sealed": True, "seal_version": r.seal_version})
    log.info("sealed %s v%d (%d files, %d rows)", partition_id, r.seal_version, len(files), rows)
    return PartitionSealed(partition_id=partition_id, source=source, day=day, seal_version=r.seal_version,
                           generation=r.generation, rows=rows, files=file_entries, job_versions=job_versions,
                           snapshot_ids={k: v for k, v in snapshot_ids.items()})
