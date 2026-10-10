"""Projectors: consume domain events and maintain read models.

Each event is applied exactly once per projector: the processed_events marker is
written in the same transaction as the read-model change, and the bus message is
acked only after commit.
"""
from __future__ import annotations

import logging
from typing import Callable

from sqlalchemy import func, select
from sqlalchemy.engine import Connection, Engine

from engine.common.bus import EVENTS_STREAM, EventBus
from engine.common.db import (as_utc, processed_events, rm_activity, rm_batch_status, rm_command_status,
                              rm_feature_days, rm_features, rm_inventory, rm_partition_batches, rm_partition_health,
                              rm_feeds, rm_pings, rm_rule_runs, rm_rules, rm_seals, upsert, utcnow)
from engine.common.events import (ArtefactsBuilt, BatchNormalised, CommandCompleted, CommandFailed, Envelope,
                                  FeatureRegistered, IndexBuilt, InventoryLoaded, PartitionSealed, PingRecorded,
                                  FeedPulled, RuleEvaluated, RulePlanned, RuleSubmitted, RunApproved, RunQueued,
                                  SummariesBuilt)

log = logging.getLogger(__name__)
Projection = Callable[[Connection, Envelope], None]


def project_command_completed(conn: Connection, env: Envelope) -> None:
    e: CommandCompleted = env.unwrap()
    upsert(conn, rm_command_status, {"command_id": e.command_id}, {
        "command_type": e.command_type, "status": "succeeded", "attempts": e.attempts, "detail": e.detail,
        "error": None, "updated_at": env.occurred_at, "projected_at": utcnow()})


def project_command_failed(conn: Connection, env: Envelope) -> None:
    e: CommandFailed = env.unwrap()
    upsert(conn, rm_command_status, {"command_id": e.command_id}, {
        "command_type": e.command_type, "status": "retrying" if e.will_retry else "failed", "attempts": e.attempts,
        "error": e.error, "updated_at": env.occurred_at, "projected_at": utcnow()})


def project_ping(conn: Connection, env: Envelope) -> None:
    e: PingRecorded = env.unwrap()
    upsert(conn, rm_pings, {"command_id": env.command_id},
           {"message": e.message, "recorded_at": e.recorded_at, "projected_at": utcnow()})


def project_inventory(conn: Connection, env: Envelope) -> None:
    e: InventoryLoaded = env.unwrap()
    now = utcnow()
    for kind in ("identities", "aliases", "assets", "static_leases"):
        upsert(conn, rm_inventory, {"kind": kind}, {"count": getattr(e, kind), "loaded_at": env.occurred_at,
                                                    "projected_at": now})


def project_batch(conn: Connection, env: Envelope) -> None:
    e: BatchNormalised = env.unwrap()
    now = utcnow()
    upsert(conn, rm_batch_status, {"batch_id": e.batch_id}, {
        "source": e.source, "ecs_mapping_version": e.ecs_mapping_version, "rows_in": e.rows_in,
        "rows_out": e.rows_out, "rows_invalid": e.rows_invalid, "partitions": len(e.partitions),
        "resolution": e.resolution, "landed_at": env.occurred_at, "projected_at": now})
    for pw in e.partitions:
        upsert(conn, rm_partition_batches, {"partition_id": pw.partition_id, "batch_id": e.batch_id}, {
            "rows": pw.rows, "bytes": pw.bytes, "min_ts": pw.min_ts, "max_ts": pw.max_ts,
            "ecs_mapping_version": e.ecs_mapping_version, "projected_at": now})
        # Re-aggregate from the per-batch projection so replays and late batches stay correct.
        rows = conn.execute(select(rm_partition_batches)
                            .where(rm_partition_batches.c.partition_id == pw.partition_id)
                            .order_by(rm_partition_batches.c.batch_id)).all()
        existing = conn.execute(select(rm_partition_health.c.stages, rm_partition_health.c.sealed)
                                .where(rm_partition_health.c.partition_id == pw.partition_id)).first()
        stages = {"landed": True, "summary": False, "index": False, "features": {}, "sealed": False,
                  **(existing.stages if existing else {})}
        if pw.partition_id in e.late_partitions or (existing and existing.stages and existing.stages.get("summary")):
            # New data invalidates downstream stages until they are rebuilt (and resealed if sealed).
            stages.update({"summary": False, "index": False, "features": {},
                           "reseal_pending": bool(existing and existing.sealed)})
            if pw.partition_id in e.late_partitions:
                stages["late_data"] = True
        upsert(conn, rm_partition_health, {"partition_id": pw.partition_id}, {
            "source": pw.source, "date": pw.date, "hour": pw.hour,
            "rows": sum(r.rows for r in rows), "files": len(rows), "bytes": sum(r.bytes for r in rows),
            "batches": [r.batch_id for r in rows],
            "min_ts": min(as_utc(r.min_ts) for r in rows), "max_ts": max(as_utc(r.max_ts) for r in rows),
            "ecs_mapping_versions": sorted({r.ecs_mapping_version for r in rows}), "stages": stages,
            "sealed": bool(existing.sealed) if existing else False, "projected_at": now})


def _set_stage(conn: Connection, partition_ids: list[str], key: str, value) -> None:
    now = utcnow()
    for pid in partition_ids:
        r = conn.execute(select(rm_partition_health.c.stages).where(rm_partition_health.c.partition_id == pid)).first()
        if r is None:
            continue
        st = dict(r.stages or {})
        if isinstance(value, tuple):          # ("features", name@version)
            feats = dict(st.get("features") or {})
            feats[value[1]] = True
            st["features"] = feats
        else:
            st[key] = value
        conn.execute(rm_partition_health.update().where(rm_partition_health.c.partition_id == pid)
                     .values(stages=st, projected_at=now))


def project_summaries(conn: Connection, env: Envelope) -> None:
    e: SummariesBuilt = env.unwrap()
    _set_stage(conn, e.partitions, "summary", True)


def project_index(conn: Connection, env: Envelope) -> None:
    e: IndexBuilt = env.unwrap()
    _set_stage(conn, e.partitions, "index", True)


def project_feature_registered(conn: Connection, env: Envelope) -> None:
    e: FeatureRegistered = env.unwrap()
    existing = conn.execute(select(rm_features).where(rm_features.c.feature == e.feature,
                                                      rm_features.c.version == e.version)).first()
    if existing is None:
        conn.execute(rm_features.insert().values(
            feature=e.feature, version=e.version, output_table=e.output_table, inputs=e.inputs,
            registered_at=env.occurred_at, days_built=0, rows=0, raw_bytes_read=0, projected_at=utcnow()))


def project_artefacts(conn: Connection, env: Envelope) -> None:
    e: ArtefactsBuilt = env.unwrap()
    pids = [r.partition_id for r in conn.execute(
        select(rm_partition_health.c.partition_id).where(rm_partition_health.c.date == e.day,
                                                         rm_partition_health.c.source.in_(e.input_sources)))]
    _set_stage(conn, pids, "features", ("features", f"{e.feature}@{e.version}"))
    upsert(conn, rm_feature_days, {"feature": e.feature, "version": e.version, "day": e.day},
           {"rows": e.rows, "raw_bytes_read": e.raw_bytes_read, "input_bytes": e.input_bytes,
            "snapshot_id": e.snapshot_id, "built_at": env.occurred_at})
    agg = conn.execute(select(func.count(), func.sum(rm_feature_days.c.rows),
                              func.sum(rm_feature_days.c.raw_bytes_read))
                       .where(rm_feature_days.c.feature == e.feature, rm_feature_days.c.version == e.version)).one()
    conn.execute(rm_features.update().where(rm_features.c.feature == e.feature, rm_features.c.version == e.version)
                 .values(days_built=agg[0], rows=agg[1] or 0, raw_bytes_read=agg[2] or 0,
                         last_built_at=env.occurred_at, projected_at=utcnow()))


def project_sealed(conn: Connection, env: Envelope) -> None:
    e: PartitionSealed = env.unwrap()
    now = utcnow()
    r = conn.execute(select(rm_partition_health.c.stages).where(
        rm_partition_health.c.partition_id == e.partition_id)).first()
    if r is not None:
        st = {**(r.stages or {}), "sealed": True, "reseal_pending": False, "seal_version": e.seal_version}
        conn.execute(rm_partition_health.update().where(rm_partition_health.c.partition_id == e.partition_id)
                     .values(stages=st, sealed=True, projected_at=now))
    upsert(conn, rm_seals, {"partition_id": e.partition_id}, {
        "seal_version": e.seal_version, "source": e.source, "date": e.day, "rows": e.rows, "files": e.files,
        "job_versions": e.job_versions, "snapshot_ids": e.snapshot_ids, "sealed_at": env.occurred_at,
        "projected_at": now})


def _rule_run(conn: Connection, run_id: str, values: dict) -> None:
    upsert(conn, rm_rule_runs, {"run_id": run_id}, {**values, "projected_at": utcnow()})


def project_rule_submitted(conn: Connection, env: Envelope) -> None:
    e: RuleSubmitted = env.unwrap()
    existing = conn.execute(select(rm_rules.c.runs).where(rm_rules.c.rule_id == e.rule_id)).first()
    upsert(conn, rm_rules, {"rule_id": e.rule_id}, {
        "title": e.title, "level": e.level, "origin": e.origin, "version_hash": e.rule_version_hash, "tags": e.tags,
        "techniques": e.techniques, "sources": e.sources, "kind": e.kind,
        "runs": (existing.runs if existing else 0) + 1, "last_run_id": e.run_id, "last_status": "submitted",
        "updated_at": env.occurred_at, "projected_at": utcnow()})
    _rule_run(conn, e.run_id, {"rule_id": e.rule_id, "title": e.title, "origin": e.origin, "status": "submitted",
                               "range_start": e.range_start, "range_end": e.range_end, "replay_of": e.replay_of,
                               "approvals": [], "submitted_at": env.occurred_at})


def project_rule_planned(conn: Connection, env: Envelope) -> None:
    e: RulePlanned = env.unwrap()
    _rule_run(conn, e.run_id, {"rule_id": e.rule_id, "status": e.status, "tiers": e.tiers,
                               "coverage_pct": e.coverage_pct, "steps": e.steps,
                               "estimate": {**e.estimate, "approval_reasons": e.approval_reasons},
                               "approval_level": e.approval_level, "estimated_cost": e.estimate.get("total"),
                               "cost_currency": e.estimate.get("currency"),
                               "pricing_version": e.estimate.get("pricing_version")})
    conn.execute(rm_rules.update().where(rm_rules.c.rule_id == e.rule_id, rm_rules.c.last_run_id == e.run_id)
                 .values(last_status=e.status, projected_at=utcnow()))


def project_run_approved(conn: Connection, env: Envelope) -> None:
    e: RunApproved = env.unwrap()
    _rule_run(conn, e.run_id, {"approvals": e.approvals})


def project_run_queued(conn: Connection, env: Envelope) -> None:
    e: RunQueued = env.unwrap()
    r = conn.execute(select(rm_rule_runs.c.rule_id).where(rm_rule_runs.c.run_id == e.run_id)).first()
    _rule_run(conn, e.run_id, {"rule_id": r.rule_id if r else "?", "status": "queued",
                               "execute_command_id": e.command_id})


def project_rule_evaluated(conn: Connection, env: Envelope) -> None:
    e: RuleEvaluated = env.unwrap()
    _rule_run(conn, e.run_id, {"rule_id": e.rule_id, "status": e.status, "hits": e.hits,
                               "bytes_scanned": e.bytes_scanned, "bytes_restored": e.bytes_restored,
                               "files_restored": e.files_restored, "actual_cost": e.actual_cost,
                               "estimated_cost": e.estimated_cost, "cost_currency": e.currency,
                               "snapshot_ids": e.snapshot_ids, "hits_hash": e.hits_hash,
                               "duration_ms": e.duration_ms, "finished_at": env.occurred_at})
    conn.execute(rm_rules.update().where(rm_rules.c.rule_id == e.rule_id, rm_rules.c.last_run_id == e.run_id)
                 .values(last_status=e.status, last_hits=e.hits, projected_at=utcnow()))


def project_feed_pulled(conn: Connection, env: Envelope) -> None:
    e: FeedPulled = env.unwrap()
    prev = conn.execute(select(rm_feeds).where(rm_feeds.c.connector == e.connector)).first()
    upsert(conn, rm_feeds, {"connector": e.connector}, {
        "generation": e.generation, "version": e.version, "offline": e.offline, "last_pull_at": env.occurred_at,
        "pulls": (prev.pulls if prev else 0) + 1, "records": e.records, "indicators_new": e.indicators_new,
        "indicators_total_new": (prev.indicators_total_new if prev else 0) + e.indicators_new,
        "suppressed": e.suppressed, "last_sweep_run_id": e.sweep_run_id or (prev.last_sweep_run_id if prev else None),
        "cursor": e.cursor, "projected_at": utcnow()})


def _activity_summary(env: Envelope) -> str:
    p = env.payload
    t = env.event_type
    if t == "BatchNormalised":
        late = f", {len(p.get('late_partitions') or [])} late" if p.get("late_partitions") else ""
        return f"landed {p['rows_out']:,} {p['source']} rows into {len(p['partitions'])} partitions{late}"
    if t == "SummariesBuilt":
        rows = sum(v.get("rows", 0) for v in p["tables"].values())
        return f"summarised {p['source']} {p['day']}: {p['raw_rows']:,} raw rows -> {rows:,} summary rows"
    if t == "IndexBuilt":
        return f"indexed {p['source']} {p['day']}: {p['docs']:,} docs, {p['bloom_filters']} bloom filters"
    if t == "FeatureRegistered":
        return f"feature {p['feature']}@{p['version']} registered (backfill scheduled)"
    if t == "ArtefactsBuilt":
        return (f"artefact {p['feature']}@{p['version']} {p['day']}: {p['rows']:,} rows, "
                f"raw bytes read {p['raw_bytes_read']}")
    if t == "PartitionSealed":
        return f"sealed {p['partition_id']} v{p['seal_version']} ({p['rows']:,} rows, {len(p['files'])} files tagged)"
    if t == "RuleSubmitted":
        return f"rule submitted: {p['title']} ({p['origin']}, run {p['run_id'][:8]})"
    if t == "RulePlanned":
        return (f"run {p['run_id'][:8]} planned: tiers {p['tiers']}, coverage {p['coverage_pct']}%, est. "
                f"{p['estimate']['total']:.2f} {p['estimate']['currency']}, approval {p['approval_level']} -> {p['status']}")
    if t == "RunApproved":
        return f"run {p['run_id'][:8]} approved by {p['approver']} ({p['role']}); policy satisfied: {p['satisfied']}"
    if t == "RestoreRequested":
        return f"run {p['run_id'][:8]} restored {p['files']} objects ({p['bytes']:,} B; {p['modelled_bytes'] / 2**30:,.1f} GB modelled)"
    if t == "RuleEvaluated":
        return (f"run {p['run_id'][:8]} evaluated: {p['hits']} hits on tiers {p['tiers_used']}, actual "
                f"{p['actual_cost']:.2f} vs est. {p['estimated_cost']:.2f} {p['currency']}")
    if t == "BehaviorPatternRecorded":
        return (f"TI {p['origin']} observation: {p['title']} on {p.get('entity_pseudonym')} "
                f"[{', '.join(p['techniques'][:4])}] -> {p['status']}")
    if t == "PatternReviewed":
        return f"TI review: {p['target_id'][:16]} {p['verdict']} by {p['reviewer']} ({p['observations']} rows)"
    if t == "StrategicRollupBuilt":
        return f"ti.strategic {p['period_type']} rollup: {p['rows']} rows over {p['periods']} periods"
    if t == "FeedPulled":
        sweep = f", retro-sweep of {p['swept']} queued" if p.get("sweep_run_id") else ""
        return (f"feed {p['connector']} pulled{' (offline sample)' if p['offline'] else ''}: {p['records']} records, "
                f"{p['indicators_new']} new, {p['suppressed']} warninglisted{sweep}")
    if t == "IndicatorRecorded":
        return f"indicator {p['type']} {p['value']} from {p['source']} ({p['threat_type'] or '-'}, {p['status']})"
    if t == "RetentionApplied":
        return (f"retention {p['layer']} ({p['years']}y, cutoff {p['cutoff']}{', dry run' if p['dry_run'] else ''}): "
                f"{p['deleted_rows']} rows / {p['deleted_objects']} objects removed, {p['retained_by_lock']} kept by "
                f"WORM, {p['retained_by_hold']} by legal hold; snapshots tagged {p['tagged_snapshots']}, expired "
                f"{p['expired_snapshots']}")
    if t == "ReadabilityChecked":
        status = "OK" if not p["failures"] else f"{len(p['failures'])} FAILURES"
        return (f"readability drill {status}: {p['partitions']} partitions over {len(p['years'])} years, "
                f"{p['files_read']} files ({p['archived_objects_read']} from archive)")
    if t == "TableCompacted":
        return f"compacted {p['table']}: {p['files_before']} -> {p['files_after']} files"
    if t == "LegalHoldChanged":
        return f"legal hold {'placed on' if p['on'] else 'released from'} {p['scope']} by {p['actor']}"
    if t == "CommandFailed":
        return f"{p['command_type']} failed (attempt {p['attempts']}): {p['error'][:160]}"
    if t == "PingRecorded":
        return f"ping: {p['message']}"
    if t == "InventoryLoaded":
        return f"inventory loaded: {p['identities']} identities, {p['assets']} assets"
    return t


def project_activity(conn: Connection, env: Envelope) -> None:
    conn.execute(rm_activity.insert().values(event_id=env.event_id, event_type=env.event_type,
                                             summary=_activity_summary(env), occurred_at=env.occurred_at,
                                             projected_at=utcnow()))


PROJECTIONS: dict[str, list[Projection]] = {
    "CommandCompleted": [project_command_completed],
    "CommandFailed": [project_command_failed, project_activity],
    "PingRecorded": [project_ping, project_activity],
    "InventoryLoaded": [project_inventory, project_activity],
    "BatchNormalised": [project_batch, project_activity],
    "SummariesBuilt": [project_summaries, project_activity],
    "IndexBuilt": [project_index, project_activity],
    "FeatureRegistered": [project_feature_registered, project_activity],
    "ArtefactsBuilt": [project_artefacts, project_activity],
    "PartitionSealed": [project_sealed, project_activity],
    "RuleSubmitted": [project_rule_submitted, project_activity],
    "RulePlanned": [project_rule_planned, project_activity],
    "RunApproved": [project_run_approved, project_activity],
    "RunQueued": [project_run_queued],
    "RestoreRequested": [project_activity],
    "RuleEvaluated": [project_rule_evaluated, project_activity],
    "BehaviorPatternRecorded": [project_activity],
    "PatternReviewed": [project_activity],
    "StrategicRollupBuilt": [project_activity],
    "FeedPulled": [project_feed_pulled, project_activity],
    "IndicatorRecorded": [project_activity],
    "RetentionApplied": [project_activity],
    "TableCompacted": [project_activity],
    "ReadabilityChecked": [project_activity],
    "LegalHoldChanged": [project_activity],
}



class Projector:
    def __init__(self, engine: Engine, bus: EventBus, name: str = "readmodel", consumer: str = "projector-1",
                 stream: str = EVENTS_STREAM):
        self.engine, self.bus, self.name, self.consumer, self.stream = engine, bus, name, consumer, stream

    def apply(self, env: Envelope) -> bool:
        with self.engine.begin() as conn:
            done = conn.execute(select(func.count()).select_from(processed_events).where(
                processed_events.c.projector == self.name, processed_events.c.event_id == env.event_id)).scalar()
            if done:
                return False
            for projection in PROJECTIONS.get(env.event_type, []):
                projection(conn, env)
            conn.execute(processed_events.insert().values(projector=self.name, event_id=env.event_id,
                                                          processed_at=utcnow()))
        return True

    def run_once(self, block_ms: int = 1000) -> int:
        messages = self.bus.read_group(self.stream, self.name, self.consumer, count=100, block_ms=block_ms)
        for message_id, data in messages:
            self.apply(Envelope.model_validate(data))
            self.bus.ack(self.stream, self.name, message_id)
        return len(messages)
