"""Command handlers. A handler may write objects to storage (idempotently, with
deterministic keys) and metadata through `ctx.conn`; it returns the events to put
in the outbox. The writer commits all of that in one transaction."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from sqlalchemy.engine import Connection

from engine.common.config import Settings
from engine.common.db import utcnow
from engine.common.events import Event, PingRecorded
from engine.common.storage import ObjectStore
from engine.cqrs.commands import IngestBatch, LoadInventory, Ping


@dataclass
class HandlerContext:
    conn: Connection
    command_id: str
    settings: Settings
    store: ObjectStore


@dataclass
class HandlerResult:
    events: list[Event] = field(default_factory=list)
    detail: dict[str, Any] = field(default_factory=dict)


def handle_ping(cmd: Ping, ctx: HandlerContext) -> HandlerResult:
    return HandlerResult(events=[PingRecorded(message=cmd.message, recorded_at=utcnow())],
                         detail={"message": cmd.message})


def handle_load_inventory(cmd: LoadInventory, ctx: HandlerContext) -> HandlerResult:
    from engine.normaliser.inventory import load_inventory
    event = load_inventory(ctx.conn, ctx.store, cmd.uri)
    return HandlerResult(events=[event], detail=event.model_dump(exclude={"uri"}))


def handle_ingest_batch(cmd: IngestBatch, ctx: HandlerContext) -> HandlerResult:
    from engine.normaliser.ingest import ingest_batch
    event = ingest_batch(ctx.conn, ctx.store, ctx.settings, cmd.batch_id, cmd.batch_uri, cmd.source, ctx.command_id)
    return HandlerResult(events=[event], detail={
        "batch_id": event.batch_id, "rows_out": event.rows_out, "rows_invalid": event.rows_invalid,
        "partitions": len(event.partitions)})


def handle_build_summaries(cmd, ctx: HandlerContext) -> HandlerResult:
    from engine.summary.builder import build_summaries
    e = build_summaries(ctx.conn, ctx.store, ctx.settings, cmd.source, cmd.day, cmd.generation, ctx.command_id)
    return HandlerResult(events=[e], detail={"source": e.source, "day": e.day, "raw_rows": e.raw_rows,
                                             "tables": {k: v["rows"] for k, v in e.tables.items()}})


def handle_build_index(cmd, ctx: HandlerContext) -> HandlerResult:
    from engine.indexer.build import build_index
    e = build_index(ctx.conn, ctx.store, ctx.settings, cmd.source, cmd.day, cmd.generation, ctx.command_id)
    return HandlerResult(events=[e], detail={"source": e.source, "day": e.day, "docs": e.docs,
                                             "index_bytes": e.index_bytes})


def handle_register_feature(cmd, ctx: HandlerContext) -> HandlerResult:
    from engine.common.events import FeatureRegistered
    from engine.features.definitions import get_definition, register
    d = get_definition(cmd.feature, cmd.version)
    new = register(ctx.conn, d)
    e = FeatureRegistered(feature=d.name, version=d.version, definition_hash=d.definition_hash,
                          inputs=list(d.inputs), output_table=d.output_table, window_days=d.window_days,
                          newly_registered=new)
    return HandlerResult(events=[e], detail={"feature": d.key, "newly_registered": new})


def handle_extract_features(cmd, ctx: HandlerContext) -> HandlerResult:
    from engine.features.extractor import extract
    e = extract(ctx.conn, ctx.store, ctx.settings, cmd.feature, cmd.version, cmd.day, cmd.generation,
                ctx.command_id)
    return HandlerResult(events=[e], detail={"feature": f"{e.feature}@{e.version}", "day": e.day, "rows": e.rows,
                                             "raw_bytes_read": e.raw_bytes_read})


def handle_seal_partition(cmd, ctx: HandlerContext) -> HandlerResult:
    from engine.seal.manager import seal_partition
    e = seal_partition(ctx.conn, ctx.store, cmd.partition_id, ctx.command_id)
    return HandlerResult(events=[e], detail={"partition_id": e.partition_id, "seal_version": e.seal_version})


HANDLERS: dict[str, Callable[[Any, HandlerContext], HandlerResult]] = {
    "BuildSummaries": handle_build_summaries,
    "BuildIndex": handle_build_index,
    "RegisterFeature": handle_register_feature,
    "ExtractFeatures": handle_extract_features,
    "SealPartition": handle_seal_partition,
    "Ping": handle_ping,
    "LoadInventory": handle_load_inventory,
    "IngestBatch": handle_ingest_batch,
}
