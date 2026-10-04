"""Stage bookkeeping shared by summary, index, features and seal.

A *generation* fingerprints the inputs a stage was built from. For a (source, day)
it is a hash of that day's landed raw files; late data adds a file, the generation
changes, and every downstream stage (summary → index → features → seal) becomes
stale and is rebuilt. Stage results are idempotent per (stage, scope, generation, version).
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import date, timedelta

from sqlalchemy import select
from sqlalchemy.engine import Connection

from engine.common.db import partition_files, stage_runs, upsert, utcnow


def _h(parts) -> str:
    return hashlib.sha256("|".join(map(str, parts)).encode()).hexdigest()[:16]


def day_files(conn: Connection, source: str, day: str) -> list:
    prefix = f"source={source}/date={day}/"
    return conn.execute(select(partition_files).where(partition_files.c.partition_id.like(prefix + "%"))
                        .order_by(partition_files.c.partition_id, partition_files.c.batch_id)).all()


def day_generations(conn: Connection) -> dict[tuple[str, str], str]:
    """{(source, day): generation} for every landed source-day."""
    groups: dict[tuple[str, str], list] = defaultdict(list)
    for r in conn.execute(select(partition_files.c.partition_id, partition_files.c.batch_id, partition_files.c.rows,
                                 partition_files.c.file)):
        src, d, _ = (x.split("=", 1)[1] for x in r.partition_id.split("/"))
        groups[(src, d)].append((r.partition_id, r.batch_id, r.rows, r.file))
    return {k: _h(sorted(v)) for k, v in groups.items()}


def partition_generations(conn: Connection) -> dict[str, str]:
    groups: dict[str, list] = defaultdict(list)
    for r in conn.execute(select(partition_files.c.partition_id, partition_files.c.batch_id, partition_files.c.rows,
                                 partition_files.c.file)):
        groups[r.partition_id].append((r.batch_id, r.rows, r.file))
    return {k: _h(sorted(v)) for k, v in groups.items()}


def combine(generations: list[str]) -> str:
    return _h(sorted(generations))


def record(conn: Connection, stage: str, scope: str, generation: str, version: str, detail: dict,
           command_id: str | None) -> None:
    upsert(conn, stage_runs, {"stage": stage, "scope": scope}, {
        "generation": generation, "version": version, "status": "succeeded", "detail": detail,
        "command_id": command_id, "finished_at": utcnow()})


def runs(conn: Connection, stage: str | None = None) -> dict[tuple[str, str], object]:
    q = select(stage_runs)
    if stage:
        q = q.where(stage_runs.c.stage == stage)
    return {(r.stage, r.scope): r for r in conn.execute(q)}


def is_current(run, generation: str, version: str) -> bool:
    return run is not None and run.status == "succeeded" and run.generation == generation and run.version == version


def window(day: str, days: int) -> list[str]:
    d = date.fromisoformat(day)
    return [(d - timedelta(days=i)).isoformat() for i in range(days, -1, -1)]
