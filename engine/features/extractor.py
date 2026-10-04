"""ExtractFeatures(feature, version, day): summary tables → artefact table rows for one day.

Reads Iceberg summary tables only. The whole build runs under `store.deny_raw()`
and also checks that every data file Iceberg read lives in the warehouse bucket,
so "a backfill never touches raw" is enforced, not just intended.
"""
from __future__ import annotations

import logging

import pyarrow as pa
from pyiceberg.expressions import And, GreaterThanOrEqual, LessThanOrEqual
from sqlalchemy.engine import Connection

from engine.common import stages
from engine.common.catalog import ensure_table, get_catalog, replace_rows
from engine.common.config import Settings
from engine.common.db import utcnow
from engine.common.events import ArtefactsBuilt
from engine.common.storage import ObjectStore
from engine.features.definitions import get_definition
from engine.summary.builder import connect, normalise_arrow, run_sql
from engine.summary.tables import TABLES

log = logging.getLogger(__name__)


class RawAccessViolation(RuntimeError):
    pass


def _load_input(catalog, settings: Settings, table: str, start: str, end: str) -> tuple[pa.Table, int | None, int]:
    from pyiceberg.exceptions import NoSuchTableError
    try:
        tbl = catalog.load_table(TABLES[table].identifier)
    except NoSuchTableError:
        return pa.table({"day": pa.array([], pa.string())}), None, 0
    snap = tbl.current_snapshot()
    if snap is None:
        return tbl.schema().as_arrow().empty_table(), None, 0
    scan = tbl.scan(row_filter=And(GreaterThanOrEqual("day", start), LessThanOrEqual("day", end)),
                    snapshot_id=snap.snapshot_id)
    tasks = list(scan.plan_files())
    for t in tasks:
        loc = t.file.file_path
        if f"/{settings.buckets.raw}/" in loc or loc.split("://", 1)[-1].startswith(f"{settings.buckets.raw}/"):
            raise RawAccessViolation(f"feature input resolved to a raw file: {loc}")
    return scan.to_arrow(), snap.snapshot_id, sum(t.file.file_size_in_bytes for t in tasks)


def extract(conn: Connection, store: ObjectStore, settings: Settings, name: str, version: str, day: str,
            generation: str, command_id: str) -> ArtefactsBuilt:
    d = get_definition(name, version)
    catalog = get_catalog(settings)
    days = stages.window(day, d.window_days)
    raw_before = store.bytes_read[settings.buckets.raw]
    input_snapshots, input_bytes = {}, 0
    with store.deny_raw():
        con = connect()
        for t in d.inputs:
            data, snap, nbytes = _load_input(catalog, settings, t, days[0], days[-1])
            input_snapshots[TABLES[t].identifier] = snap
            input_bytes += nbytes
            con.register(t, data)
        out = normalise_arrow(run_sql(con, d.sql.replace("{day}", day)))
        con.close()
        n = out.num_rows
        out = out.append_column("day", pa.array([day] * n, pa.string()))
        out = out.append_column("feature_version", pa.array([version] * n, pa.string()))
        out = out.append_column("built_at", pa.array([utcnow()] * n, pa.timestamp("us", tz="UTC")))
        table = ensure_table(catalog, d.output_table, out.schema, partition_by=("day",))
        snap = replace_rows(table, out, day=day, feature_version=version)
    raw_bytes_read = store.bytes_read[settings.buckets.raw] - raw_before
    gens = stages.day_generations(conn)

    stages.record(conn, "features", f"{d.key}/{day}", generation, d.definition_hash,
                  {"rows": n, "snapshot_id": snap, "input_snapshots": input_snapshots, "input_bytes": input_bytes,
                   "raw_bytes_read": raw_bytes_read, "window": [days[0], days[-1]],
                   "source_generations": {s: gens.get((s, day)) for s in d.input_sources}}, command_id)
    log.info("feature %s day %s: %d rows from %d summary bytes, raw bytes read: %d", d.key, day, n, input_bytes,
             raw_bytes_read)
    return ArtefactsBuilt(feature=name, version=version, day=day, generation=generation, rows=n,
                          output_table=d.output_table, snapshot_id=snap, input_snapshots=input_snapshots,
                          input_bytes=input_bytes, raw_bytes_read=raw_bytes_read, input_sources=list(d.input_sources))
