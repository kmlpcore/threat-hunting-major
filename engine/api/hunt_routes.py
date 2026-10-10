"""Query-side endpoints for M2-M4: pipeline status, storage, summaries, artefacts,
search / IOC sweeps, seals and lifecycle. Read models come from Postgres; table
reads are snapshot-pinned Iceberg scans (the snapshot id is returned)."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, HTTPException, Query
from pyiceberg.expressions import And, EqualTo
from sqlalchemy import func, select

from engine.common.catalog import NAMESPACES, get_catalog, read_table, table_stats
from engine.common.db import (as_utc, rm_activity, rm_command_status, rm_feature_days, rm_features,
                              rm_partition_health, rm_seals)
from engine.features.definitions import load_definitions
from engine.indexer.search import Searcher
from engine.summary.policy import load_policy
from engine.summary.tables import HIGH_VALUE, TABLES


def _ts(v):
    return as_utc(v) if isinstance(v, datetime) else v


def _rows(table, limit: int) -> list[dict]:
    out = []
    for r in table.slice(0, limit).to_pylist():
        out.append({k: _ts(v) for k, v in r.items()})
    return out


def _parse_dt(v: str | None) -> datetime | None:
    if not v:
        return None
    d = datetime.fromisoformat(v.replace("Z", "+00:00"))
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def build_router(rt) -> APIRouter:
    r = APIRouter()
    settings = rt.settings
    searcher = Searcher(rt.engine, rt.store, settings, Path("/tmp/engine-index-cache"))
    import threading
    threading.Thread(target=searcher.warm, name="index-warmup", daemon=True).start()

    def feature_sources() -> dict[str, set[str]]:
        return {d.key: set(d.input_sources) for d in load_definitions().values()}

    @r.get("/pipeline")
    def pipeline():
        """Stage completion per source, from the partition_health projection."""
        with rt.engine.connect() as conn:
            rows = conn.execute(select(rm_partition_health.c.source, rm_partition_health.c.stages,
                                       rm_partition_health.c.rows, rm_partition_health.c.projected_at)).all()
            registered = [f"{x.feature}@{x.version}" for x in conn.execute(select(rm_features))]
            cmds = conn.execute(select(rm_command_status.c.command_type, rm_command_status.c.status,
                                       func.count()).group_by(rm_command_status.c.command_type,
                                                              rm_command_status.c.status)).all()
        fs = feature_sources()
        by_source: dict[str, Counter] = defaultdict(Counter)
        for row in rows:
            st = row.stages or {}
            c = by_source[row.source]
            c["partitions"] += 1
            c["rows"] += row.rows
            for k in ("landed", "summary", "index", "sealed", "reseal_pending", "late_data"):
                c[k] += bool(st.get(k))
            needed = [f for f in registered if row.source in fs.get(f, set())]
            c["features"] += all((st.get("features") or {}).get(f) for f in needed)
        total = Counter()
        for c in by_source.values():
            total.update(c)
        commands = defaultdict(dict)
        for t, s, n in cmds:
            commands[t][s] = n
        return {"sources": {k: dict(v) for k, v in sorted(by_source.items())}, "total": dict(total),
                "registered_features": registered, "commands": commands,
                "projected_at": max((_ts(x.projected_at) for x in rows), default=None)}

    @r.get("/storage")
    def storage():
        cat = get_catalog(settings)
        with rt.engine.connect() as conn:
            raw_bytes, raw_rows, raw_parts = conn.execute(select(func.sum(rm_partition_health.c.bytes),
                                                                 func.sum(rm_partition_health.c.rows),
                                                                 func.count())).one()
        summary = [table_stats(cat, t.identifier) for t in TABLES.values()] + [table_stats(cat, HIGH_VALUE)]
        artefacts = []
        try:
            artefacts = [table_stats(cat, ".".join(i)) for i in cat.list_tables("artefacts")]
        except Exception:  # noqa: BLE001
            pass
        idx_objects, idx_bytes = rt.store.total_size(settings.buckets.index)
        in_objects, in_bytes = rt.store.total_size(settings.buckets.incoming)
        raw_bytes = raw_bytes or 0
        sb, ab = sum(t["bytes"] for t in summary), sum(t["bytes"] for t in artefacts)

        def ratio(x):
            return round(x / raw_bytes, 4) if raw_bytes else None
        return {
            "raw": {"bytes": raw_bytes, "rows": raw_rows or 0, "partitions": raw_parts},
            "incoming_native": {"bytes": in_bytes, "objects": in_objects},
            "summary": {"bytes": sb, "rows": sum(t["rows"] for t in summary), "tables": summary},
            "artefacts": {"bytes": ab, "rows": sum(t["rows"] for t in artefacts), "tables": artefacts},
            "index": {"bytes": idx_bytes, "objects": idx_objects},
            "ratios": {"summary_to_raw": ratio(sb), "artefacts_to_raw": ratio(ab), "index_to_raw": ratio(idx_bytes),
                       "derived_to_raw": ratio(sb + ab + idx_bytes)},
            "policy_version": load_policy().version,
        }

    @r.get("/summary/tables")
    def summary_tables():
        cat = get_catalog(settings)
        return {"items": [{**table_stats(cat, t.identifier), "source": t.source, "grain": t.grain}
                          for t in TABLES.values()] + [{**table_stats(cat, HIGH_VALUE), "source": "*",
                                                        "grain": "event (allow-listed by drop policy)"}],
                "policy_version": load_policy().version}

    def _read(identifier: str, day: str | None, limit: int, snapshot_id: int | None, extra: dict | None = None):
        cat = get_catalog(settings)
        filters = [EqualTo("day", day)] if day else []
        filters += [EqualTo(k, v) for k, v in (extra or {}).items() if v]
        filt = None
        if filters:
            filt = filters[0]
            for f in filters[1:]:
                filt = And(filt, f)
        table, snap = read_table(cat, identifier, row_filter=filt, snapshot_id=snapshot_id, limit=limit)
        return {"table": identifier, "snapshot_id": snap, "count": table.num_rows, "items": _rows(table, limit)}

    @r.get("/summary/{name}")
    def summary_rows(name: str, day: str | None = None, limit: int = Query(100, le=5000),
                     snapshot_id: int | None = None, source: str | None = None):
        if name == "high_value_events":
            return _read(HIGH_VALUE, day, limit, snapshot_id, {"source": source})
        if name not in TABLES:
            raise HTTPException(404, f"unknown summary table {name}; known: {sorted(TABLES)}")
        return _read(TABLES[name].identifier, day, limit, snapshot_id)

    @r.get("/features")
    def features_list():
        with rt.engine.connect() as conn:
            reg = {(x.feature, x.version): x for x in conn.execute(select(rm_features))}
        items = []
        for d in load_definitions().values():
            row = reg.get((d.name, d.version))
            items.append({"feature": d.name, "version": d.version, "description": d.description,
                          "inputs": list(d.inputs), "input_sources": list(d.input_sources),
                          "window_days": d.window_days, "output_table": d.output_table,
                          "default_active": d.active, "registered": row is not None,
                          "days_built": row.days_built if row else 0, "rows": row.rows if row else 0,
                          "raw_bytes_read": row.raw_bytes_read if row else 0,
                          "last_built_at": _ts(row.last_built_at) if row else None,
                          "definition_hash": d.definition_hash})
        return {"items": items}

    @r.get("/features/{name}/{version}/days")
    def feature_days(name: str, version: str):
        with rt.engine.connect() as conn:
            rows = conn.execute(select(rm_feature_days).where(rm_feature_days.c.feature == name,
                                                              rm_feature_days.c.version == version)
                                .order_by(rm_feature_days.c.day)).all()
        return {"items": [{k: _ts(v) for k, v in dict(x._mapping).items()} for x in rows]}

    @r.get("/artefacts/{name}")
    def artefact_rows(name: str, day: str | None = None, version: str | None = None,
                      limit: int = Query(100, le=5000), snapshot_id: int | None = None):
        return _read(f"artefacts.{name}", day, limit, snapshot_id, {"feature_version": version})

    @r.get("/search")
    def search(q: str, start: str | None = None, end: str | None = None, source: list[str] | None = Query(None),
               limit: int = Query(20, le=200)):
        return searcher.text_search(q, _parse_dt(start), _parse_dt(end), source, limit)

    @r.get("/ioc")
    def ioc(value: str, type: str | None = None, start: str | None = None, end: str | None = None,
            source: list[str] | None = Query(None), limit: int = Query(200, le=2000)):
        res = searcher.ioc_sweep(value, type, _parse_dt(start), _parse_dt(end), source, limit)
        res.pop("event_ids", None) if len(res.get("event_ids", [])) > 5000 else None
        return res

    @r.get("/activity")
    def activity(limit: int = Query(50, le=500), event_type: str | None = None):
        q = select(rm_activity).order_by(rm_activity.c.id.desc()).limit(limit)
        if event_type:
            q = q.where(rm_activity.c.event_type == event_type)
        with rt.engine.connect() as conn:
            rows = conn.execute(q).all()
        return {"items": [{k: _ts(v) for k, v in dict(x._mapping).items()} for x in rows]}

    @r.get("/seals")
    def seals(limit: int = Query(100, le=2000), source: str | None = None):
        q = select(rm_seals).order_by(rm_seals.c.sealed_at.desc()).limit(limit)
        if source:
            q = q.where(rm_seals.c.source == source)
        with rt.engine.connect() as conn:
            rows = conn.execute(q).all()
            total = conn.execute(select(func.count()).select_from(rm_seals)).scalar()
            versions = conn.execute(select(func.max(rm_seals.c.seal_version))).scalar()
        return {"total": total, "max_seal_version": versions,
                "items": [{k: _ts(v) for k, v in dict(x._mapping).items()} for x in rows]}

    @r.get("/partitions/{partition_id:path}/seal")
    def partition_seal(partition_id: str):
        with rt.engine.connect() as conn:
            row = conn.execute(select(rm_seals).where(rm_seals.c.partition_id == partition_id)).first()
        if row is None:
            raise HTTPException(404, "partition not sealed")
        return {k: _ts(v) for k, v in dict(row._mapping).items()}

    @r.get("/lifecycle")
    def lifecycle(sample: int = Query(40, le=500)):
        """The raw bucket's lifecycle rule plus a spot check of tags and storage classes.
        Invariant: no object without sealed=true may be in a non-STANDARD (archive) class."""
        rule = None
        if rt.store.is_s3:
            try:
                rule = rt.store._client().get_bucket_lifecycle_configuration(Bucket=settings.buckets.raw)["Rules"]
            except Exception as exc:  # noqa: BLE001
                rule = {"error": str(exc)}
        with rt.engine.connect() as conn:
            sealed_rows = conn.execute(select(rm_seals.c.files).limit(sample // 2)).all()
            unsealed = conn.execute(select(rm_partition_health.c.partition_id).where(
                rm_partition_health.c.sealed.is_(False)).limit(sample // 2)).all()
        checks, violations = [], 0
        for row in sealed_rows:
            for f in row.files[:1]:
                tags = rt.store.get_tags(f["file"])
                checks.append({"file": f["file"], "expected": "sealed", "tags": tags,
                               "storage_class": rt.store.storage_class(f["file"])})
        for u in unsealed:
            files = rt.store.list(f"{settings.buckets.raw}/{u.partition_id}", ".parquet")[:1]
            for f in files:
                sc = rt.store.storage_class(f)
                tags = rt.store.get_tags(f)
                bad = sc != "STANDARD"
                violations += bad
                checks.append({"file": f, "expected": "unsealed", "tags": tags, "storage_class": sc,
                               "violation": bad})
        archived = sum(1 for c in checks if c["storage_class"] != "STANDARD")
        return {"bucket": settings.buckets.raw, "lifecycle_rules": rule, "checked": len(checks),
                "archived_in_sample": archived, "unsealed_in_archive_violations": violations, "sample": checks}

    @r.get("/retention")
    def retention():
        """Retention policy per layer, data span, WORM configuration, legal holds, last drill (M8)."""
        from engine.retention.enforcer import status
        with rt.engine.connect() as conn:
            return status(conn, settings, rt.store)

    @r.get("/catalog")
    def catalog():
        cat = get_catalog(settings)
        out = {}
        for ns in NAMESPACES:
            try:
                out[ns] = [".".join(t) for t in cat.list_tables(ns)]
            except Exception:  # noqa: BLE001
                out[ns] = []
        return {"warehouse": settings.warehouse_name, "namespaces": out}

    return r
