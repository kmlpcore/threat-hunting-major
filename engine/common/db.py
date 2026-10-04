"""Postgres metadata, outbox and read-model tables (SQLAlchemy Core).

Two Postgres schemas keep the sides apart:
- meta:      write side (command queue, outbox, batches, partitions, entity tables)
- readmodel: query side (projections; only projectors write here)

SQLite (local mode) has no schemas, so they are translated away at connect time.
"""
from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import (JSON, BigInteger, Boolean, Column, DateTime, Integer, MetaData, String, Table, Text,
                        UniqueConstraint, create_engine, event, text)
from sqlalchemy.engine import Connection, Engine

metadata = MetaData()
TS = DateTime(timezone=True)
ID = String(64)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def as_utc(value: datetime | None) -> datetime | None:
    """SQLite returns naive datetimes; everything we store is UTC."""
    if value is None:
        return None
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value.astimezone(timezone.utc)


# --------------------------------------------------------------------------- write side (meta)
commands = Table(
    "commands", metadata,
    Column("seq", Integer, primary_key=True, autoincrement=True),
    Column("command_id", ID, nullable=False, unique=True),
    Column("command_type", String(64), nullable=False),
    Column("queue", String(64), nullable=False, index=True),
    Column("payload", JSON, nullable=False),
    Column("idempotency_key", String(512), nullable=False, unique=True),
    Column("status", String(16), nullable=False, index=True),  # queued | running | succeeded | failed
    Column("attempts", Integer, nullable=False, default=0),
    Column("max_attempts", Integer, nullable=False, default=3),
    Column("not_before", TS, nullable=False),
    Column("submitted_by", String(128)),
    Column("submitted_at", TS, nullable=False),
    Column("started_at", TS),
    Column("finished_at", TS),
    Column("error", Text),
    schema="meta",
)

outbox = Table(
    "outbox", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("event_id", ID, nullable=False, unique=True),
    Column("event_type", String(64), nullable=False),
    Column("envelope", JSON, nullable=False),
    Column("created_at", TS, nullable=False),
    Column("published_at", TS, index=True),
    schema="meta",
)

batches = Table(
    "batches", metadata,
    Column("batch_id", String(256), primary_key=True),
    Column("source", String(64), nullable=False),
    Column("batch_uri", String(1024), nullable=False),
    Column("ecs_mapping_version", String(32), nullable=False),
    Column("rows_in", BigInteger, nullable=False),
    Column("rows_out", BigInteger, nullable=False),
    Column("rows_invalid", BigInteger, nullable=False),
    Column("partitions", JSON, nullable=False),
    Column("quarantine_uri", String(1024)),
    Column("resolution", JSON),  # entity-resolution stats
    Column("command_id", ID, nullable=False),
    Column("landed_at", TS, nullable=False),
    schema="meta",
)

partition_files = Table(
    "partition_files", metadata,
    Column("partition_id", String(256), primary_key=True),
    Column("batch_id", String(256), primary_key=True),
    Column("file", String(1024), nullable=False),
    Column("rows", BigInteger, nullable=False),
    Column("bytes", BigInteger, nullable=False),
    Column("min_ts", TS, nullable=False),
    Column("max_ts", TS, nullable=False),
    Column("ecs_mapping_version", String(32), nullable=False),
    Column("written_at", TS, nullable=False),
    schema="meta",
)

partitions = Table(
    "partitions", metadata,
    Column("partition_id", String(256), primary_key=True),  # source=<src>/date=<d>/hour=<hh>
    Column("source", String(64), nullable=False, index=True),
    Column("date", String(10), nullable=False),
    Column("hour", String(2), nullable=False),
    Column("rows", BigInteger, nullable=False),
    Column("files", Integer, nullable=False),
    Column("bytes", BigInteger, nullable=False),
    Column("min_ts", TS),
    Column("max_ts", TS),
    Column("ecs_mapping_versions", JSON, nullable=False),
    Column("sealed", Boolean, nullable=False, default=False),
    Column("seal_version", Integer, nullable=False, default=0),
    Column("updated_at", TS, nullable=False),
    schema="meta",
)

identities = Table(
    "identities", metadata,
    Column("user_id", String(128), primary_key=True),  # SID for AD principals
    Column("name", String(128), nullable=False),        # canonical sAMAccountName, lower-case
    Column("domain", String(128)),
    Column("upn", String(256)),
    Column("display_name", String(256)),
    Column("department", String(64)),
    Column("kind", String(16), nullable=False),          # human | service | builtin
    Column("is_admin", Boolean, nullable=False, default=False),
    Column("updated_at", TS, nullable=False),
    schema="meta",
)

identity_aliases = Table(
    "identity_aliases", metadata,
    Column("alias", String(256), primary_key=True),  # lower-case: sam, DOMAIN\sam, upn, SID, cloud principal
    Column("user_id", String(128), nullable=False),
    schema="meta",
)

assets = Table(
    "assets", metadata,
    Column("host_name", String(128), primary_key=True),  # short, lower-case
    Column("host_id", String(64), nullable=False),
    Column("fqdn", String(256)),
    Column("asset_class", String(32), nullable=False),
    Column("business_unit", String(64)),
    Column("os", String(64)),
    Column("static_ip", String(64)),
    Column("owner_user_id", String(128)),
    Column("updated_at", TS, nullable=False),
    schema="meta",
)

ip_leases = Table(
    "ip_leases", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("ip", String(64), nullable=False, index=True),
    Column("host_name", String(128), nullable=False),
    Column("mac", String(32)),
    Column("start", TS, nullable=False),
    Column("end", TS, nullable=False),
    Column("source_event_id", String(64), nullable=False),
    UniqueConstraint("source_event_id", name="uq_lease_event"),
    schema="meta",
)

# --------------------------------------------------------------------------- query side (readmodel)
processed_events = Table(
    "processed_events", metadata,
    Column("projector", String(64), primary_key=True),
    Column("event_id", ID, primary_key=True),
    Column("processed_at", TS, nullable=False),
    schema="readmodel",
)

rm_command_status = Table(
    "command_status", metadata,
    Column("command_id", ID, primary_key=True),
    Column("command_type", String(64), nullable=False),
    Column("status", String(16), nullable=False),
    Column("attempts", Integer),
    Column("detail", JSON),
    Column("error", Text),
    Column("updated_at", TS, nullable=False),
    Column("projected_at", TS, nullable=False),
    schema="readmodel",
)

rm_pings = Table(
    "pings", metadata,
    Column("command_id", ID, primary_key=True),
    Column("message", Text, nullable=False),
    Column("recorded_at", TS, nullable=False),
    Column("projected_at", TS, nullable=False),
    schema="readmodel",
)

rm_batch_status = Table(
    "batch_status", metadata,
    Column("batch_id", String(256), primary_key=True),
    Column("source", String(64), nullable=False),
    Column("ecs_mapping_version", String(32), nullable=False),
    Column("rows_in", BigInteger, nullable=False),
    Column("rows_out", BigInteger, nullable=False),
    Column("rows_invalid", BigInteger, nullable=False),
    Column("partitions", Integer, nullable=False),
    Column("resolution", JSON),
    Column("landed_at", TS, nullable=False),
    Column("projected_at", TS, nullable=False),
    schema="readmodel",
)

rm_partition_health = Table(
    "partition_health", metadata,
    Column("partition_id", String(256), primary_key=True),
    Column("source", String(64), nullable=False, index=True),
    Column("date", String(10), nullable=False),
    Column("hour", String(2), nullable=False),
    Column("rows", BigInteger, nullable=False),
    Column("files", Integer, nullable=False),
    Column("bytes", BigInteger, nullable=False),
    Column("batches", JSON, nullable=False),
    Column("min_ts", TS),
    Column("max_ts", TS),
    Column("ecs_mapping_versions", JSON, nullable=False),
    Column("stages", JSON, nullable=False),  # {"landed": true, "summary": false, "index": false, ...}
    Column("sealed", Boolean, nullable=False),
    Column("projected_at", TS, nullable=False),
    schema="readmodel",
)

rm_partition_batches = Table(
    "partition_batches", metadata,
    Column("partition_id", String(256), primary_key=True),
    Column("batch_id", String(256), primary_key=True),
    Column("rows", BigInteger, nullable=False),
    Column("bytes", BigInteger, nullable=False),
    Column("min_ts", TS, nullable=False),
    Column("max_ts", TS, nullable=False),
    Column("ecs_mapping_version", String(32), nullable=False),
    Column("projected_at", TS, nullable=False),
    schema="readmodel",
)

rm_inventory = Table(
    "inventory", metadata,
    Column("kind", String(32), primary_key=True),  # identities | aliases | assets | static_leases
    Column("count", Integer, nullable=False),
    Column("loaded_at", TS, nullable=False),
    Column("projected_at", TS, nullable=False),
    schema="readmodel",
)

# --------------------------------------------------------------------------- M2-M4 write side
stage_runs = Table(
    "stage_runs", metadata,
    Column("stage", String(32), primary_key=True),      # summary | index | features
    Column("scope", String(256), primary_key=True),     # <source>/<date>  or  <feature>@<version>/<date>
    Column("generation", String(64), nullable=False),   # hash of the inputs it was built from
    Column("version", String(64), nullable=False),      # policy / index / feature version
    Column("status", String(16), nullable=False),
    Column("detail", JSON),
    Column("command_id", ID),
    Column("finished_at", TS, nullable=False),
    schema="meta",
)

features = Table(
    "features", metadata,
    Column("name", String(64), primary_key=True),
    Column("version", String(32), primary_key=True),
    Column("definition_hash", String(64), nullable=False),
    Column("inputs", JSON, nullable=False),
    Column("output_table", String(128), nullable=False),
    Column("window_days", Integer, nullable=False),
    Column("status", String(16), nullable=False),        # active | retired
    Column("registered_at", TS, nullable=False),
    schema="meta",
)

seal_manifest = Table(
    "seal_manifest", metadata,
    Column("partition_id", String(256), primary_key=True),
    Column("seal_version", Integer, primary_key=True),
    Column("generation", String(64), nullable=False),
    Column("rows", BigInteger, nullable=False),
    Column("files", JSON, nullable=False),              # [{file, bytes, etag, late}]
    Column("job_versions", JSON, nullable=False),       # ecs mapping, drop policy, index, features
    Column("snapshot_ids", JSON, nullable=False),       # iceberg table -> snapshot id
    Column("sealed_at", TS, nullable=False),
    Column("command_id", ID, nullable=False),
    schema="meta",
)

# --------------------------------------------------------------------------- M2-M4 query side
rm_activity = Table(
    "activity", metadata,
    Column("id", Integer, primary_key=True, autoincrement=True),
    Column("event_id", ID, nullable=False),
    Column("event_type", String(64), nullable=False),
    Column("summary", Text, nullable=False),
    Column("occurred_at", TS, nullable=False),
    Column("projected_at", TS, nullable=False),
    schema="readmodel",
)

rm_features = Table(
    "feature_registry", metadata,
    Column("feature", String(64), primary_key=True),
    Column("version", String(32), primary_key=True),
    Column("output_table", String(128), nullable=False),
    Column("inputs", JSON, nullable=False),
    Column("registered_at", TS, nullable=False),
    Column("days_built", Integer, nullable=False),
    Column("rows", BigInteger, nullable=False),
    Column("raw_bytes_read", BigInteger, nullable=False),
    Column("last_built_at", TS),
    Column("projected_at", TS, nullable=False),
    schema="readmodel",
)

rm_feature_days = Table(
    "feature_days", metadata,
    Column("feature", String(64), primary_key=True),
    Column("version", String(32), primary_key=True),
    Column("day", String(10), primary_key=True),
    Column("rows", BigInteger, nullable=False),
    Column("raw_bytes_read", BigInteger, nullable=False),
    Column("input_bytes", BigInteger, nullable=False),
    Column("snapshot_id", BigInteger),
    Column("built_at", TS, nullable=False),
    schema="readmodel",
)

rm_seals = Table(
    "seals", metadata,
    Column("partition_id", String(256), primary_key=True),
    Column("seal_version", Integer, nullable=False),
    Column("source", String(64), nullable=False),
    Column("date", String(10), nullable=False),
    Column("rows", BigInteger, nullable=False),
    Column("files", JSON, nullable=False),
    Column("job_versions", JSON, nullable=False),
    Column("snapshot_ids", JSON, nullable=False),
    Column("sealed_at", TS, nullable=False),
    Column("projected_at", TS, nullable=False),
    schema="readmodel",
)

SCHEMAS = ("meta", "readmodel")


def make_engine(url: str) -> Engine:
    if url.startswith("sqlite"):
        if url.startswith("sqlite:///") and ":memory:" not in url:
            from pathlib import Path
            Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
        eng = create_engine(url, connect_args={"check_same_thread": False, "timeout": 30})
        eng = eng.execution_options(schema_translate_map={s: None for s in SCHEMAS})

        @event.listens_for(eng, "connect")
        def _sqlite_pragmas(dbapi_conn, _):  # pragma: no cover - trivial
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

        return eng
    return create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=5)


def create_all(engine: Engine) -> None:
    if engine.dialect.name == "postgresql":
        with engine.begin() as conn:
            for schema in SCHEMAS:
                conn.execute(text(f'CREATE SCHEMA IF NOT EXISTS "{schema}"'))
    metadata.create_all(engine)


def is_postgres(conn: Connection | Engine) -> bool:
    return conn.dialect.name == "postgresql"


def upsert(conn: Connection, table: Table, keys: dict, values: dict) -> None:
    """Portable upsert; fine because each table has a single writer."""
    where = [table.c[k] == v for k, v in keys.items()]
    result = conn.execute(table.update().where(*where).values(**values))
    if result.rowcount == 0:
        conn.execute(table.insert().values(**keys, **values))
