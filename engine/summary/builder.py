"""BuildSummaries(source, day): raw ECS rows for one source-day → Iceberg summary tables.

Every write replaces exactly the rows for that day (and source, for the shared
high_value_events table), so rebuilds after late data or a policy change are idempotent.
"""
from __future__ import annotations

import logging
import math
from collections import Counter

import duckdb
import pyarrow as pa
from sqlalchemy.engine import Connection

from engine.common import stages
from engine.common.catalog import ensure_table, get_catalog, replace_rows
from engine.common.config import Settings
from engine.common.db import utcnow
from engine.common.events import SummariesBuilt
from engine.common.storage import ObjectStore
from engine.summary.policy import high_value_where, load_policy
from engine.summary.tables import HIGH_VALUE, TABLES

log = logging.getLogger(__name__)


def entropy(s: str | None) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def normalise_arrow(t: pa.Table) -> pa.Table:
    """DuckDB → Iceberg-friendly types: UTC microsecond timestamps, plain strings, no string views."""
    fields = []
    for f in t.schema:
        typ = f.type
        if pa.types.is_timestamp(typ):
            typ = pa.timestamp("us", tz="UTC")
        elif pa.types.is_large_string(typ) or typ == pa.string_view():
            typ = pa.string()
        elif pa.types.is_list(typ) or pa.types.is_large_list(typ):
            inner = typ.value_type
            if pa.types.is_large_string(inner) or inner == pa.string_view():
                inner = pa.string()
            typ = pa.list_(inner)
        elif pa.types.is_decimal(typ):
            typ = pa.float64()
        elif pa.types.is_integer(typ):
            typ = pa.int64()
        elif pa.types.is_floating(typ):
            typ = pa.float64()
        fields.append(pa.field(f.name, typ, nullable=True))
    return t.cast(pa.schema(fields))


ENTROPY_MACRO = """
CREATE MACRO entropy(s) AS CASE WHEN s IS NULL OR length(s) = 0 THEN 0.0::DOUBLE ELSE
  list_sum(list_transform(list_distinct(string_split(s, '')), lambda c:
    -(length(list_filter(string_split(s, ''), lambda x: x = c))::DOUBLE / length(s))
     * log2(length(list_filter(string_split(s, ''), lambda x: x = c))::DOUBLE / length(s))))::DOUBLE END
"""


def connect() -> duckdb.DuckDBPyConnection:
    """DuckDB session for summary/feature SQL. Shannon entropy is a SQL macro (no Python UDF)."""
    con = duckdb.connect()
    con.execute("SET TimeZone = 'UTC'")
    con.execute(ENTROPY_MACRO)
    return con


def run_sql(con: duckdb.DuckDBPyConnection, sql: str) -> pa.Table:
    res = con.execute(sql)
    return res.to_arrow_table() if hasattr(res, "to_arrow_table") else res.fetch_arrow_table()


def load_day(conn: Connection, store: ObjectStore, source: str, day: str) -> tuple[pa.Table, int, list[str]]:
    """All raw files (including late arrivals) for a source-day, without event.original."""
    files = stages.day_files(conn, source, day)
    tables, nbytes = [], 0
    for f in files:
        t = store.read_parquet(f.file)
        tables.append(t.drop_columns([c for c in ("event.original",) if c in t.column_names]))
        nbytes += f.bytes
    raw = pa.concat_tables(tables) if tables else pa.table({})
    return raw, nbytes, sorted({f.partition_id for f in files})


def with_lineage(t: pa.Table, day: str, policy_version: str, built_at) -> pa.Table:
    n = t.num_rows
    t = t.append_column("day", pa.array([day] * n, pa.string()))
    t = t.append_column("policy_version", pa.array([policy_version] * n, pa.string()))
    return t.append_column("built_at", pa.array([built_at] * n, pa.timestamp("us", tz="UTC")))


def build_summaries(conn: Connection, store: ObjectStore, settings: Settings, source: str, day: str,
                    generation: str, command_id: str) -> SummariesBuilt:
    policy = load_policy()
    sp = policy.for_source(source)
    built_at = utcnow()
    results: dict[str, dict] = {}
    raw_rows, raw_bytes, partitions = 0, 0, [p for p in {f.partition_id for f in stages.day_files(conn, source, day)}]

    if sp.action == "aggregate":
        raw, raw_bytes, partitions = load_day(conn, store, source, day)
        raw_rows = raw.num_rows
        catalog = get_catalog(settings)
        con = connect()
        con.register("raw", raw)
        for name in sp.tables:
            spec = TABLES[name]
            out = with_lineage(normalise_arrow(run_sql(con, spec.sql)), day, policy.version, built_at)
            table = ensure_table(catalog, spec.identifier, out.schema)
            snap = replace_rows(table, out, day=day)
            results[spec.identifier] = {"rows": out.num_rows, "snapshot_id": snap}

        where = high_value_where(sp)
        hv = run_sql(con, f"SELECT * FROM raw WHERE {where}") if where else raw.slice(0, 0)
        hv = normalise_arrow(hv)
        hv = hv.append_column("source", pa.array([source] * hv.num_rows, pa.string()))
        hv = with_lineage(hv, day, policy.version, built_at)
        # The shared table's schema is the full ECS row; align (missing columns → null).
        table = ensure_table(catalog, HIGH_VALUE, hv.schema, partition_by=("day", "source"))
        target = table.schema().as_arrow()
        hv = pa.table({f.name: hv.column(f.name).cast(f.type) if f.name in hv.column_names
                       else pa.nulls(hv.num_rows, f.type) for f in target}, schema=target)
        snap = replace_rows(table, hv, day=day, source=source)
        results[HIGH_VALUE] = {"rows": hv.num_rows, "snapshot_id": snap}
        con.close()

    summary_rows = sum(r["rows"] for r in results.values())
    stages.record(conn, "summary", f"{source}/{day}", generation, policy.version,
                  {"tables": results, "raw_rows": raw_rows, "raw_bytes": raw_bytes, "action": sp.action},
                  command_id)
    log.info("summaries %s/%s: %d raw rows -> %d summary rows in %d tables", source, day, raw_rows, summary_rows,
             len(results))
    return SummariesBuilt(source=source, day=day, generation=generation, policy_version=policy.version,
                          action=sp.action, raw_rows=raw_rows, raw_bytes=raw_bytes,
                          partitions=sorted(partitions), tables=results)
