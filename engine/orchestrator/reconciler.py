"""Pipeline orchestrator (process manager on the command side).

Each pass compares what has landed with what has been built and submits the
missing work as commands:

    landed source-day ──► BuildSummaries ─┐
                     └──► BuildIndex ─────┤
    summaries for a feature's window ──► ExtractFeatures (per active feature, per day)
    all of the above current + watermark ──► SealPartition

Commands carry deterministic idempotency keys built from input *generations*, so
running the reconciler repeatedly (or several replicas of it) is safe, and late data
(which changes a generation) automatically re-triggers the affected stages.

Plan.md names Dagster for orchestration; a reconciler loop covers M2-M4 without
another platform. Dagster can later drive the same commands.
"""
from __future__ import annotations

import logging
from collections import Counter
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.engine import Engine

from engine.common import stages
from engine.common.db import features, partitions
from engine.cqrs.commands import BuildIndex, BuildSummaries, ExtractFeatures, RegisterFeature, SealPartition
from engine.cqrs.writer_queue import requeue_failed, submit
from engine.features.definitions import active_features, load_definitions
from engine.indexer.fts_tantivy import INDEX_VERSION
from engine.seal.manager import readiness, watermarks
from engine.summary.policy import load_policy
from engine.summary.tables import TABLES

log = logging.getLogger(__name__)
PIPELINE_COMMANDS = ["BuildSummaries", "BuildIndex", "ExtractFeatures", "SealPartition", "RegisterFeature"]


class Reconciler:
    def __init__(self, engine: Engine, max_attempts: int = 3, retry_after: timedelta = timedelta(minutes=2)):
        self.engine = engine
        self.retry_after = retry_after
        self.max_attempts = max_attempts
        self._submitted: set[str] = set()
        self._bootstrapped = False

    def _submit(self, cmd) -> bool:
        key = cmd.idempotency_key()
        if key in self._submitted:
            return False
        res = submit(self.engine, cmd, submitted_by="orchestrator", idempotency_key=key,
                     max_attempts=self.max_attempts)
        self._submitted.add(key)
        return not res.duplicate

    def bootstrap_features(self) -> int:
        """Register every feature marked `active: true` in policies/features.yaml."""
        with self.engine.connect() as conn:
            registered = {(r.name, r.version) for r in conn.execute(select(features.c.name, features.c.version))}
        n = 0
        for d in load_definitions().values():
            if d.active and (d.name, d.version) not in registered:
                n += self._submit(RegisterFeature(feature=d.name, version=d.version))
        self._bootstrapped = True
        return n

    def run_once(self) -> int:
        if not self._bootstrapped:
            return self.bootstrap_features()
        requeued = requeue_failed(self.engine, PIPELINE_COMMANDS, self.retry_after, max_total_attempts=12)
        if requeued:
            log.warning("requeued %d failed pipeline commands", requeued)
        submitted: Counter[str] = Counter()
        policy_version = load_policy().version
        with self.engine.connect() as conn:
            day_gens = stages.day_generations(conn)
            part_gens = stages.partition_generations(conn)
            runs = stages.runs(conn)
            feats = active_features(conn)
            wms = watermarks(conn)
            sealed = {r.partition_id: r for r in conn.execute(select(partitions))}

        # 1) summaries + index per landed source-day
        pending_summary = set()
        for (source, day), gen in sorted(day_gens.items()):
            if not stages.is_current(runs.get(("summary", f"{source}/{day}")), gen, policy_version):
                pending_summary.add((source, day))
                if self._submit(BuildSummaries(source=source, day=day, generation=gen)):
                    submitted["BuildSummaries"] += 1
            if not stages.is_current(runs.get(("index", f"{source}/{day}")), gen, INDEX_VERSION):
                if self._submit(BuildIndex(source=source, day=day, generation=gen)):
                    submitted["BuildIndex"] += 1

        # 2) features per day, once every input source-day in the window has current summaries
        all_days = sorted({d for _, d in day_gens})
        for f in feats:
            for day in all_days:
                window = stages.window(day, f.window_days)
                inputs = [(s, d) for s in f.input_sources for d in window if (s, d) in day_gens]
                if not any(d == day for _, d in inputs):
                    continue                       # nothing landed for this feature's sources on that day
                if any(i in pending_summary for i in inputs):
                    continue                       # wait for summaries
                fgen = stages.combine([f"{s}/{d}:{day_gens[(s, d)]}" for s, d in inputs])
                run = runs.get(("features", f"{f.key}/{day}"))
                if run is None or run.generation != fgen or run.version != f.definition_hash:
                    if self._submit(ExtractFeatures(feature=f.name, version=f.version, day=day, generation=fgen)):
                        submitted["ExtractFeatures"] += 1

        # 3) seal partitions whose stages are all current
        with self.engine.connect() as conn:
            for pid in sorted(part_gens):
                r = readiness(conn, pid, day_gens=day_gens, part_gens=part_gens, runs=runs, feats=feats, wms=wms)
                if r.ready and self._submit(SealPartition(partition_id=pid, generation=r.generation)):
                    submitted["SealPartition"] += 1

        if submitted:
            log.info("reconciler submitted %s", dict(submitted))
        return sum(submitted.values())


def stage_tables_for_source(source: str) -> list[str]:
    return [t.identifier for t in TABLES.values() if t.source == source]
