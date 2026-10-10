"""Tiered executor (plan.md section 3.8, "Executor").

Runs a planned rule:
  * pins the Iceberg snapshot of every derived table at start (or reuses the snapshots of
    the run being replayed) and reads only those snapshots, so a long run never sees a
    half-written table and a result is reproducible forever (NFR6);
  * records a lease per pinned snapshot, which maintenance turns into an Iceberg tag so
    snapshot expiry never removes it (plan.md 4.3.5, 12.3);
  * restores only the raw objects / row groups the plan located (tier 3) and evaluates the
    full predicate on them;
  * writes results.rule_hits and results.rule_runs and measures what it actually touched,
    priced with the same model as the estimate.
"""
from __future__ import annotations

import hashlib
import json
import logging
import time
from datetime import datetime, timezone

import pyarrow as pa
from pyiceberg.expressions import And, EqualTo, In
from sqlalchemy.engine import Connection

from engine.common.catalog import ensure_table, get_catalog, replace_rows
from engine.common.config import Settings
from engine.common.db import snapshot_leases, upsert, utcnow
from engine.common.storage import ObjectStore
from engine.cost import estimator as est
from engine.normaliser import ecs
from engine.rules.capabilities import AGG_CAPABILITIES, DIMENSION_TABLES
from engine.rules.compiler import CompiledRule, compile_sigma, q
from engine.summary.builder import connect, run_sql
from engine.summary.tables import HIGH_VALUE

log = logging.getLogger(__name__)

HITS_TABLE = "results.rule_hits"
RUNS_TABLE = "results.rule_runs"
OUTPUT_FIELDS = ["@timestamp", "event.id", "event.dataset", "event.action", "event.code", "event.outcome",
                 "host.name", "user.name", "source.ip", "destination.ip", "destination.port", "process.name",
                 "process.parent.name", "process.command_line", "dns.question.name", "url.full", "url.domain",
                 "http.request.method", "http.request.bytes", "group.name", "user.target.name", "related.ip",
                 "process.hash.sha256", "file.hash.sha256", "dns.question.registered_domain", "url.registered_domain",
                 "destination.domain", "related.hash"]
EVIDENCE_FIELDS = ["event.action", "event.code", "process.name", "process.parent.name", "process.command_line",
                   "dns.question.name", "url.full", "destination.port", "http.request.method", "http.request.bytes",
                   "group.name", "user.target.name"]

HIT_SCHEMA = pa.schema([
    ("run_id", pa.string()), ("rule_id", pa.string()), ("rule_version_hash", pa.string()), ("tier", pa.int64()),
    ("capability", pa.string()), ("exact", pa.bool_()), ("hit_key", pa.string()), ("entity_key", pa.string()),
    ("event_id", pa.string()), ("ts", pa.timestamp("us", tz="UTC")), ("day", pa.string()),
    ("host_name", pa.string()), ("user_name", pa.string()), ("source_ip", pa.string()),
    ("destination_ip", pa.string()), ("group_key", pa.string()), ("count", pa.int64()), ("evidence", pa.string()),
    ("observables", pa.list_(pa.string())),
])
RUN_SCHEMA = pa.schema([
    ("run_id", pa.string()), ("rule_id", pa.string()), ("rule_version_hash", pa.string()), ("origin", pa.string()),
    ("plan", pa.string()), ("tiers_used", pa.list_(pa.int64())), ("coverage_pct", pa.float64()),
    ("snapshot_ids", pa.string()), ("bytes_scanned", pa.int64()), ("bytes_restored", pa.int64()),
    ("files_restored", pa.int64()), ("estimated_cost", pa.float64()), ("actual_cost", pa.float64()),
    ("cost_currency", pa.string()), ("pricing_version", pa.string()), ("approved_by", pa.list_(pa.string())),
    ("duration_ms", pa.int64()), ("status", pa.string()), ("hits", pa.int64()), ("hits_hash", pa.string()),
    ("range_start", pa.timestamp("us", tz="UTC")), ("range_end", pa.timestamp("us", tz="UTC")),
    ("finished_at", pa.timestamp("us", tz="UTC")), ("day", pa.string()),
])


def _jsonable(v):
    if isinstance(v, datetime):
        return v.astimezone(timezone.utc).isoformat()
    if isinstance(v, list):
        return [_jsonable(x) for x in v]
    return v


def _entity(row: dict) -> str | None:
    for k in ("host.name", "user.name", "source.ip"):
        if row.get(k):
            return str(row[k]).lower()
    return None


def _day(ts) -> str | None:
    return ts.astimezone(timezone.utc).date().isoformat() if isinstance(ts, datetime) else None


def _observables(row: dict) -> list[str]:
    vals = set()
    for k in ("source.ip", "destination.ip", "dns.question.name", "url.domain", "process.hash.sha256",
              "file.hash.sha256", "dns.question.registered_domain", "url.registered_domain", "destination.domain"):
        v = row.get(k)
        for x in (v if isinstance(v, list) else [v]):
            if x:
                vals.add(str(x).lower())
    for k in ("related.ip", "related.hash"):
        for x in row.get(k) or []:
            vals.add(str(x).lower())
    return sorted(vals)


class Executor:
    def __init__(self, conn: Connection, store: ObjectStore, settings: Settings):
        self.conn, self.store, self.settings = conn, store, settings
        self.catalog = get_catalog(settings)
        self.cols = set(ecs.catalog().fields)

    # ------------------------------------------------------------------ table reads at pinned snapshots
    def _pin(self, table: str, pinned: dict) -> int | None:
        if table in pinned:
            return pinned[table]
        from pyiceberg.exceptions import NoSuchTableError
        try:
            t = self.catalog.load_table(table)
        except NoSuchTableError:
            return None
        snap = t.current_snapshot()
        pinned[table] = snap.snapshot_id if snap else None
        return pinned[table]

    def _read(self, table: str, snapshot_id: int | None, days: list[str], filters: dict) -> tuple[pa.Table, int]:
        if snapshot_id is None:
            return pa.table({}), 0
        t = self.catalog.load_table(table)
        filt = In("day", days)
        for k, v in filters.items():
            filt = And(filt, In(k, v) if isinstance(v, list) else EqualTo(k, v))
        scan = t.scan(row_filter=filt, snapshot_id=snapshot_id)
        nbytes = sum(f.file.file_size_in_bytes for f in scan.plan_files())
        return scan.to_arrow(), nbytes

    # ------------------------------------------------------------------ steps
    def _event_hits(self, rule: CompiledRule, data: pa.Table, start: datetime, end: datetime, step: dict) -> list[dict]:
        if data.num_rows == 0:
            return []
        con = connect()
        con.register("raw", data)
        sql = (f'SELECT * FROM raw WHERE {rule.sql_where()} AND "@timestamp" >= {q(start.isoformat())}::TIMESTAMPTZ '
               f'AND "@timestamp" <= {q(end.isoformat())}::TIMESTAMPTZ')
        rows = run_sql(con, sql).to_pylist()
        con.close()
        return [self._event_hit(r, step) for r in rows]

    def _event_hit(self, r: dict, step: dict) -> dict:
        ts = r.get("@timestamp")
        ent = _entity(r)
        day = _day(ts)
        return {"tier": step["tier"], "capability": step["capability"], "exact": True, "hit_key": r.get("event.id"),
                "entity_key": f"{ent}@{day}", "event_id": r.get("event.id"), "ts": ts, "day": day,
                "host_name": r.get("host.name"), "user_name": r.get("user.name"), "source_ip": r.get("source.ip"),
                "destination_ip": r.get("destination.ip"), "group_key": None, "count": 1,
                "evidence": json.dumps({k: _jsonable(r[k]) for k in EVIDENCE_FIELDS if r.get(k) is not None}),
                "observables": _observables(r), "_row": r}

    def _correlation_hits(self, rule: CompiledRule, matched: pa.Table, step: dict) -> list[dict]:
        c = rule.correlation
        if matched.num_rows == 0:
            return []
        con = connect()
        con.register("m", matched)
        gexpr = [f'lower(CAST("{g}" AS VARCHAR)) AS "{g}"' for g in c.group_by]
        g = ", ".join(f'"{x}"' for x in c.group_by)
        part = f"PARTITION BY {g} " if g else ""
        frame = f"RANGE BETWEEN CURRENT ROW AND INTERVAL '{c.timespan_s} seconds' FOLLOWING"
        if c.type == "value_count":
            agg = f'count(DISTINCT v) OVER ({part}ORDER BY ts {frame})'
            vsel = f', lower(CAST("{c.value_field}" AS VARCHAR)) AS v'
            vwhere = f'WHERE "{c.value_field}" IS NOT NULL'
        else:
            agg, vsel, vwhere = f"count(*) OVER ({part}ORDER BY ts {frame})", "", ""
        sym = {"gte": ">=", "gt": ">", "lte": "<=", "lt": "<", "eq": "="}[c.op]
        sel_g = (", ".join(gexpr) + ", ") if gexpr else ""
        out_g = (g + ", ") if g else ""
        sql = (f'WITH x AS (SELECT {sel_g}"@timestamp" AS ts{vsel} FROM m {vwhere}), '
               f"w AS (SELECT {out_g}ts, {agg} AS wc FROM x) "
               f"SELECT {out_g}CAST(CAST(ts AS DATE) AS VARCHAR) AS day, max(wc) AS count, min(ts) AS first_ts, "
               f"max(ts) AS last_ts FROM w WHERE wc {sym} {c.threshold!r} GROUP BY {out_g}day")
        rows = run_sql(con, sql).to_pylist()
        con.close()
        return [self._group_hit(rule, r, step) for r in rows]

    def _group_hit(self, rule: CompiledRule, r: dict, step: dict) -> dict:
        keys = {g: r.get(g) for g in rule.correlation.group_by}
        ent = "|".join(str(v) for v in keys.values()) or "*"
        day = str(r["day"])
        ts = r.get("first_ts")
        if isinstance(ts, datetime) and ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return {"tier": step["tier"], "capability": step["capability"], "exact": step["exact"],
                "hit_key": f"{ent}@{day}", "entity_key": f"{ent}@{day}", "event_id": None, "ts": ts, "day": day,
                "host_name": keys.get("host.name"), "user_name": keys.get("user.name"),
                "source_ip": keys.get("source.ip"), "destination_ip": keys.get("destination.ip"),
                "group_key": json.dumps(keys), "count": int(r["count"]),
                "evidence": json.dumps({"window_count": int(r["count"]), "first": _jsonable(r.get("first_ts")),
                                        "last": _jsonable(r.get("last_ts"))}),
                "observables": sorted({str(v).lower() for k, v in keys.items() if v and k in
                                       ("source.ip", "destination.ip")})}

    def run_dimension(self, rule, step, pinned) -> tuple[list[dict], dict]:
        dt = next(d for d in DIMENSION_TABLES if d.name == step["capability"])
        snap = self._pin(dt.table, pinned)
        data, nbytes = self._read(dt.table, snap, step["days"], step.get("filters") or {})
        hits = []
        if data.num_rows:
            con = connect()
            con.register("t", data)
            rows = run_sql(con, f"SELECT * FROM t WHERE {dt.where_sql(rule)}").to_pylist()
            con.close()
            for r in rows:
                ent = str(r.get(dt.entity_col) or "").lower()
                day = r["day"]
                ts = r.get(dt.time_col) if dt.time_col else datetime.fromisoformat(day).replace(tzinfo=timezone.utc)
                dims = {f: _jsonable(r.get(col)) for f, (col, _) in dt.dims.items()}
                hits.append({"tier": step["tier"], "capability": dt.name, "exact": True,
                             "hit_key": f"{ent}@{day}|" + json.dumps(dims, sort_keys=True), "entity_key": f"{ent}@{day}",
                             "event_id": None, "ts": ts, "day": day,
                             "host_name": dims.get("host.name"), "user_name": dims.get("user.name"),
                             "source_ip": None, "destination_ip": dims.get("destination.ip"), "group_key": None,
                             "count": int(r.get(dt.count_col) or 0), "evidence": json.dumps(dims),
                             "observables": sorted({str(v).lower() for k, v in dims.items()
                                                    if v and k in ("destination.ip",)})})
        return hits, {"scanned_bytes": nbytes, "tier": step["tier"]}

    def run_high_value(self, rule, step, pinned, start, end) -> tuple[list[dict], dict]:
        snap = self._pin(HIGH_VALUE, pinned)
        data, nbytes = self._read(HIGH_VALUE, snap, step["days"], step.get("filters") or {"source": rule.sources})
        return self._event_hits(rule, data, start, end, step), {"scanned_bytes": nbytes, "tier": 2}

    def run_aggregate(self, rule, step, pinned) -> tuple[list[dict], dict]:
        agg = None
        for cap in AGG_CAPABILITIES:
            agg = cap(rule)
            if agg is not None and agg.capability == step["capability"]:
                break
        snap = self._pin(agg.table, pinned)
        data, nbytes = self._read(agg.table, snap, step["days"], {})
        hits = []
        if data.num_rows:
            con = connect()
            con.register("t", data)
            rows = run_sql(con, agg.sql).to_pylist()
            con.close()
            hits = [self._group_hit(rule, r, step) for r in rows]
        return hits, {"scanned_bytes": nbytes, "tier": 2}

    def run_raw(self, rule, step, start, end) -> tuple[list[dict], dict]:
        needed = sorted((set(rule.fields) | set(OUTPUT_FIELDS)) & self.cols)
        tables, read_bytes, restored, objects = [], 0, {}, {}
        for t in step["targets"]:
            if t["row_groups"] is None:
                data = self.store.read_parquet(t["file"], columns=needed)
                nbytes = t["bytes"]
            else:
                data, nbytes = self.store.read_row_groups(t["file"], t["row_groups"], columns=needed)
            tables.append(data)
            read_bytes += nbytes
            restored[t["storage_tier"]] = restored.get(t["storage_tier"], 0) + t["bytes"]
            objects[t["storage_tier"]] = objects.get(t["storage_tier"], 0) + 1
        data = pa.concat_tables(tables, promote_options="default") if tables else pa.table({})
        if rule.correlation:
            con = connect()
            con.register("raw", data)
            matched = run_sql(con, f'SELECT * FROM raw WHERE {rule.sql_where()} AND "@timestamp" >= '
                                   f'{q(start.isoformat())}::TIMESTAMPTZ AND "@timestamp" <= '
                                   f'{q(end.isoformat())}::TIMESTAMPTZ') if data.num_rows else pa.table({})
            con.close()
            hits = self._correlation_hits(rule, matched, step)
        else:
            hits = self._event_hits(rule, data, start, end, step)
        return hits, {"tier": 3, "scanned_bytes": read_bytes, "restored": restored, "restored_objects": objects,
                      "files": len(step["targets"]), "bytes_read": read_bytes}

    # ------------------------------------------------------------------ run
    def execute(self, run, rule_yaml: str) -> dict:
        t0 = time.monotonic()
        plan = run.plan
        rule = compile_sigma(rule_yaml, origin=run.origin)
        start, end = run.range_start, run.range_end
        start = start if start.tzinfo else start.replace(tzinfo=timezone.utc)
        end = end if end.tzinfo else end.replace(tzinfo=timezone.utc)
        pinned: dict = dict((run.context or {}).get("pinned_snapshots") or {})
        hits, metrics = [], []
        for step in plan["steps"]:
            if step["kind"] == "dimension":
                h, m = self.run_dimension(rule, step, pinned)
            elif step["kind"] == "high_value":
                h, m = self.run_high_value(rule, step, pinned, start, end)
            elif step["kind"] == "aggregate":
                h, m = self.run_aggregate(rule, step, pinned)
            else:
                h, m = self.run_raw(rule, step, start, end)
            hits.extend(h)
            metrics.append(m)
        raw_targets = sorted(t["file"] for s in plan["steps"] if s["kind"] == "raw" for t in s["targets"])
        if raw_targets:
            pinned["raw"] = "objects:" + hashlib.sha256("\n".join(raw_targets).encode()).hexdigest()[:16]
        for table, snap in pinned.items():
            if table != "raw" and snap is not None:
                upsert(self.conn, snapshot_leases, {"table_name": table, "snapshot_id": int(snap), "run_id": run.run_id},
                       {"created_at": utcnow(), "expires_at": None, "tagged": False})

        quantities = [est.Quantities(tier=m["tier"], scanned_bytes=m.get("scanned_bytes", 0),
                                     restored=m.get("restored", {}), restored_objects=m.get("restored_objects", {}))
                      for m in metrics]
        actual = est.cost(quantities, apply_calibration=False)
        bytes_scanned = sum(m.get("scanned_bytes", 0) for m in metrics if m["tier"] < 3)
        bytes_restored = sum(sum(m.get("restored", {}).values()) for m in metrics)
        files_restored = sum(m.get("files", 0) for m in metrics)
        keyset = sorted(f"{h['hit_key']}#{h['count']}" for h in hits)
        hits_hash = hashlib.sha256("\n".join(keyset).encode()).hexdigest()[:32]
        duration_ms = int((time.monotonic() - t0) * 1000)
        self._write(run, rule, hits, plan, pinned, actual, bytes_scanned, bytes_restored, files_restored, hits_hash,
                    duration_ms)
        return {"rule": rule, "hits": hits, "pinned": pinned, "actual": actual, "quantities": quantities,
                "bytes_scanned": bytes_scanned, "bytes_restored": bytes_restored, "files_restored": files_restored,
                "hits_hash": hits_hash, "duration_ms": duration_ms,
                "entities": len({h["entity_key"] for h in hits}),
                "bytes_read": sum(m.get("bytes_read", 0) for m in metrics)}

    def _write(self, run, rule, hits, plan, pinned, actual, bytes_scanned, bytes_restored, files_restored,
               hits_hash, duration_ms) -> None:
        rows = [{**{k: v for k, v in h.items() if not k.startswith("_")}, "run_id": run.run_id,
                 "rule_id": rule.rule_id, "rule_version_hash": rule.version_hash} for h in hits]
        for r in rows:
            if r["day"] is None:
                r["day"] = run.range_start.date().isoformat()
        table = ensure_table(self.catalog, HITS_TABLE, HIT_SCHEMA, partition_by=("day",))
        replace_rows(table, pa.Table.from_pylist(rows, schema=HIT_SCHEMA), run_id=run.run_id)
        now = utcnow()
        approved_by = [a["approver"] for a in (run.approvals or [])]
        rr = pa.Table.from_pylist([{
            "run_id": run.run_id, "rule_id": rule.rule_id, "rule_version_hash": rule.version_hash,
            "origin": run.origin, "plan": json.dumps(plan, default=str), "tiers_used": plan["tiers"],
            "coverage_pct": float(plan["coverage_pct"]), "snapshot_ids": json.dumps(pinned, default=str),
            "bytes_scanned": bytes_scanned, "bytes_restored": bytes_restored, "files_restored": files_restored,
            "estimated_cost": float(run.estimated_cost), "actual_cost": float(actual["total"]),
            "cost_currency": actual["currency"], "pricing_version": actual["pricing_version"],
            "approved_by": approved_by, "duration_ms": duration_ms, "status": "succeeded", "hits": len(hits),
            "hits_hash": hits_hash, "range_start": run.range_start, "range_end": run.range_end, "finished_at": now,
            "day": now.date().isoformat()}], schema=RUN_SCHEMA)
        runs_table = ensure_table(self.catalog, RUNS_TABLE, RUN_SCHEMA, partition_by=("day",))
        replace_rows(runs_table, rr, run_id=run.run_id)
