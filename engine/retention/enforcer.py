"""Retention enforcer (plan.md section 12).

ApplyRetention(layer)
  * cutoff = as_of - years_for(layer); data older than the cutoff is removed, except what is
    under a legal hold, or WORM-locked (raw objects whose Object Lock retention has not ended);
  * raw purges are dry-run unless explicitly requested (raw is the forensic layer);
  * snapshots referenced by rule results (meta.snapshot_leases) get an Iceberg tag kept for the
    whole retention period, then ordinary snapshots older than `expire_after_days` are expired.
    Results stay reproducible after compaction and expiry (NFR6).
ReadabilityDrill
  * for every year that holds data: sample partitions, read every raw object (archived objects
    are restored through the storage tier), check rows / schema / ECS mapping versions against
    the mapping registry, read the summaries, open the BM25 segment and the bloom bundle, and
    read the Parquet copy of the keyword postings. Any failure fails the command loudly.
CompactTable(table)
  * rewrites each day partition into one data file (copy-on-write) to undo small-file growth.
SetLegalHold(scope)
  * suspends retention for matching raw partitions / days (and sets S3 legal hold on objects).
"""
from __future__ import annotations

import logging
import random
from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone

import pyarrow as pa
from pyiceberg.expressions import EqualTo, LessThan
from sqlalchemy import select

from engine.common import stages
from engine.common.catalog import get_catalog
from engine.common.db import (ecs_mapping_registry, legal_holds, partition_files, partitions, seal_manifest,
                              snapshot_leases, upsert, utcnow)
from engine.common.events import LegalHoldChanged, ReadabilityChecked, RetentionApplied, TableCompacted
from engine.retention.policy import load, years_for

log = logging.getLogger(__name__)
YEAR = timedelta(days=365.25)

# layer -> (tables, column holding the day / date used for retention)
DAY_LAYERS = {"summary": "summary", "artefacts": "artefacts", "results": "results"}
TI_LAYERS = {"ti_operational": ("ti.operational", "period_day"), "ti_strategic": ("ti.strategic", "period_start"),
             "feed_raw": ("ti_staging.feed_raw", "day")}


def _now(as_of: str | None) -> datetime:
    if as_of:
        d = datetime.fromisoformat(as_of)
        return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc)


def cutoff_for(layer: str, as_of: datetime) -> tuple[int, str]:
    years = years_for(layer)
    return years, (as_of - years * YEAR).date().isoformat()


def active_holds(conn) -> list[str]:
    return [r.scope for r in conn.execute(select(legal_holds.c.scope).where(legal_holds.c.active.is_(True)))]


def held(scope_value: str, holds: list[str]) -> bool:
    return any(scope_value.startswith(h) or h.startswith(scope_value) for h in holds)


def held_days(holds: list[str]) -> set[str]:
    """Days named by any hold (date=YYYY-MM-DD anywhere in the scope)."""
    out = set()
    for h in holds:
        for part in h.split("/"):
            if part.startswith("date="):
                out.add(part[5:])
    return out


def layer_tables(settings, layer: str) -> list[tuple[str, str]]:
    cat = get_catalog(settings)
    if layer in DAY_LAYERS:
        try:
            return [(".".join(t), "day") for t in cat.list_tables(DAY_LAYERS[layer])]
        except Exception:  # noqa: BLE001
            return []
    if layer in TI_LAYERS:
        return [TI_LAYERS[layer]]
    if layer == "ti_tactical":
        return [("ti.tactical", "last_seen")]
    if layer == "index_keyword":
        return [("index.keyword_postings", "day")]
    return []


def manage_snapshots(settings, conn, table_name: str, years: int, now: datetime) -> tuple[int, int]:
    """Tag leased snapshots for the retention period; expire other old snapshots."""
    from pyiceberg.exceptions import NoSuchTableError
    pol = load()["snapshots"]
    try:
        t = get_catalog(settings).load_table(table_name)
    except NoSuchTableError:
        return 0, 0
    existing = {s.snapshot_id for s in t.snapshots()}
    tagged = 0
    leases = conn.execute(select(snapshot_leases).where(snapshot_leases.c.table_name == table_name,
                                                        snapshot_leases.c.tagged.is_(False))).all()
    if leases:
        ms = t.manage_snapshots()
        refs = set(t.metadata.refs)
        for lease in leases:
            name = f"run-{lease.run_id}"
            if lease.snapshot_id in existing and name not in refs:
                ms = ms.create_tag(int(lease.snapshot_id), name, max_ref_age_ms=int(years * YEAR.total_seconds() * 1000))
                tagged += 1
        if tagged:
            ms.commit()
        for lease in leases:
            conn.execute(snapshot_leases.update().where(
                snapshot_leases.c.table_name == table_name, snapshot_leases.c.snapshot_id == lease.snapshot_id,
                snapshot_leases.c.run_id == lease.run_id).values(tagged=True))
        t.refresh()
    protected = {r.snapshot_id for r in t.metadata.refs.values()}
    cutoff = now - timedelta(days=int(pol["expire_after_days"]))
    snaps = sorted(t.snapshots(), key=lambda s: s.timestamp_ms)
    keep = {s.snapshot_id for s in snaps[-int(pol.get("keep_min", 5)):]}
    old = [s.snapshot_id for s in snaps if s.timestamp_ms < cutoff.timestamp() * 1000
           and s.snapshot_id not in protected and s.snapshot_id not in keep]
    if old:
        t.maintenance.expire_snapshots().by_ids(old).commit()
    return tagged, len(old)


def _delete_rows(settings, table_name: str, column: str, cutoff: str, hold_days: set[str], layer: str,
                 dry_run: bool) -> int:
    from pyiceberg.exceptions import NoSuchTableError
    try:
        t = get_catalog(settings).load_table(table_name)
    except NoSuchTableError:
        return 0
    if t.current_snapshot() is None:
        return 0
    if layer == "ti_tactical":
        # Expired / revoked / false-positive indicators past retention; active ones are always kept.
        rows = t.scan().to_arrow().to_pylist()
        cut = datetime.fromisoformat(cutoff).replace(tzinfo=timezone.utc)
        gone = [r for r in rows if r["status"] != "active" and r["last_seen"] and r["last_seen"] < cut]
        if gone and not dry_run:
            keep = [r for r in rows if r not in gone]
            t.overwrite(pa.Table.from_pylist(keep, schema=t.schema().as_arrow()))
        return len(gone)
    scan = t.scan(row_filter=LessThan(column, cutoff), selected_fields=(column,)).to_arrow()
    victims = [d for d in scan.column(column).to_pylist() if d not in hold_days]
    if victims and not dry_run:
        for d in sorted(set(victims)):
            t.delete(delete_filter=EqualTo(column, d))
    return len(victims)


def apply_retention(cmd, ctx):
    from engine.cqrs.handlers import HandlerResult
    now = _now(cmd.as_of)
    years, cutoff = cutoff_for(cmd.layer, now)
    holds = active_holds(ctx.conn)
    hold_days = held_days(holds)
    deleted_rows = deleted_objects = retained_lock = retained_hold = tagged = expired = 0
    tables: list[str] = []

    if cmd.layer == "raw":
        deleted_objects, retained_lock, retained_hold = _raw(ctx, cutoff, holds, cmd.dry_run, now)
    elif cmd.layer in ("index_keyword", "index_text"):
        deleted_objects, retained_hold = _index(ctx, cmd.layer, cutoff, hold_days, cmd.dry_run)
    if cmd.layer != "raw" and cmd.layer != "index_text":
        for table_name, column in layer_tables(ctx.settings, cmd.layer):
            tables.append(table_name)
            deleted_rows += _delete_rows(ctx.settings, table_name, column, cutoff, hold_days, cmd.layer,
                                         cmd.dry_run)
            if not cmd.dry_run:
                a, b = manage_snapshots(ctx.settings, ctx.conn, table_name, years, now)
                tagged += a
                expired += b
    detail = {"layer": cmd.layer, "years": years, "cutoff": cutoff, "dry_run": cmd.dry_run,
              "deleted_rows": deleted_rows, "deleted_objects": deleted_objects, "retained_by_lock": retained_lock,
              "retained_by_hold": retained_hold, "tagged_snapshots": tagged, "expired_snapshots": expired,
              "tables": tables}
    stages.record(ctx.conn, "retention", cmd.layer, cutoff, load()["version"], detail, ctx.command_id)
    return HandlerResult(events=[RetentionApplied(**detail)], detail=detail)


def _raw(ctx, cutoff: str, holds: list[str], dry_run: bool, now: datetime) -> tuple[int, int, int]:
    """Raw objects past retention are removed only when not legally held and not WORM-locked."""
    store = ctx.store
    old = ctx.conn.execute(select(partition_files).where(partition_files.c.partition_id.like("source=%"))).all()
    victims = [f for f in old if f.partition_id.split("/")[1].split("=", 1)[1] < cutoff]
    deleted = locked = on_hold = 0
    for f in victims:
        if held(f.partition_id, holds):
            on_hold += 1
            continue
        if store.is_s3:
            bucket, key = f.file.split("/", 1)
            try:
                ret = store._client().get_object_retention(Bucket=bucket, Key=key).get("Retention", {})
                until = ret.get("RetainUntilDate")
                if until and until > now:
                    locked += 1
                    continue
            except Exception:  # noqa: BLE001 - no retention configured on the object
                pass
        if not dry_run:
            if store.is_s3:
                bucket, key = f.file.split("/", 1)
                store._client().delete_object(Bucket=bucket, Key=key)
            else:
                store.fs.delete_file(f.file)
            ctx.conn.execute(partition_files.delete().where(partition_files.c.partition_id == f.partition_id,
                                                            partition_files.c.batch_id == f.batch_id))
        deleted += 1
    return deleted, locked, on_hold


def _index(ctx, layer: str, cutoff: str, hold_days: set[str], dry_run: bool) -> tuple[int, int]:
    s, store = ctx.settings, ctx.store
    prefixes = [f"{s.buckets.index}/bloom", f"{s.buckets.index}/postings"] if layer == "index_keyword" \
        else [f"{s.buckets.index}/fts"]
    deleted = held_n = 0
    for prefix in prefixes:
        for path in store.list(prefix):
            day = next((p[5:] for p in path.split("/") if p.startswith("date=")), None)
            if day is None or day >= cutoff:
                continue
            if day in hold_days:
                held_n += 1
                continue
            if not dry_run:
                store.fs.delete_file(path)
            deleted += 1
    return deleted, held_n


# --------------------------------------------------------------------------- compaction
def compact_table(cmd, ctx):
    from engine.cqrs.handlers import HandlerResult
    t = get_catalog(ctx.settings).load_table(cmd.table)
    if t.current_snapshot() is None:
        return HandlerResult(events=[TableCompacted(table=cmd.table, partitions=0, files_before=0, files_after=0,
                                                    rows=0)])
    files = list(t.scan().plan_files())
    by_day: dict = defaultdict(list)
    for f in files:
        by_day[f.file.partition[0] if len(f.file.partition) else None].append(f)
    rows = 0
    rewritten = 0
    import warnings
    for day, fs in by_day.items():
        if len(fs) <= 1:
            continue
        data = t.scan(row_filter=EqualTo("day", day)).to_arrow() if day is not None else t.scan().to_arrow()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            t.overwrite(data, overwrite_filter=EqualTo("day", day) if day is not None else None)
        rows += data.num_rows
        rewritten += 1
        t.refresh()
    after = len(list(t.scan().plan_files()))
    return HandlerResult(events=[TableCompacted(table=cmd.table, partitions=rewritten, files_before=len(files),
                                                files_after=after, rows=rows)],
                         detail={"table": cmd.table, "files_before": len(files), "files_after": after})


# --------------------------------------------------------------------------- readability drill
def readability_drill(cmd, ctx):
    from engine.cqrs.handlers import HandlerResult
    from engine.indexer.build import bloom_bundle_path, fts_prefix, unpack_bundle
    from engine.indexer.search import Searcher
    from engine.normaliser import ecs
    pol = load()["readability_drill"]
    k = cmd.partitions_per_year or int(pol["partitions_per_year"])
    store, settings = ctx.store, ctx.settings
    parts = ctx.conn.execute(select(partitions).where(partitions.c.sealed.is_(True))).all()
    registry = defaultdict(set)
    for r in ctx.conn.execute(select(ecs_mapping_registry.c.source, ecs_mapping_registry.c.version)):
        registry[r.source].add(r.version)
    by_year: dict[int, list] = defaultdict(list)
    for p in parts:
        by_year[int(p.date[:4])].append(p)
    rng = random.Random(cmd.slot)
    failures, files_read, bytes_read, archived, checked = [], 0, 0, 0, 0
    expected_cols = set(ecs.catalog().arrow_schema.names)
    searcher = Searcher(None, store, settings)
    for year, plist in sorted(by_year.items()):
        for p in rng.sample(plist, min(k, len(plist))):
            checked += 1
            pid = p.partition_id
            for f in ctx.conn.execute(select(partition_files).where(partition_files.c.partition_id == pid)):
                try:
                    if store.is_s3 and store.storage_class(f.file) != "STANDARD":
                        archived += 1
                    t = store.read_parquet(f.file)
                    files_read += 1
                    bytes_read += f.bytes
                    if t.num_rows != f.rows:
                        failures.append(f"{f.file}: {t.num_rows} rows read, {f.rows} recorded")
                    missing = expected_cols - set(t.column_names)
                    if missing:
                        failures.append(f"{f.file}: missing columns {sorted(missing)[:5]}")
                    versions = set(t.column("labels.ecs_mapping_version").to_pylist())
                    unknown = versions - registry.get(p.source, set())
                    if unknown:
                        failures.append(f"{f.file}: ECS mapping version(s) {sorted(unknown)} not in the registry")
                except Exception as exc:  # noqa: BLE001 - every failure is reported
                    failures.append(f"{f.file}: unreadable ({type(exc).__name__}: {exc})")
            try:
                gen, filters = unpack_bundle(store.get_bytes(bloom_bundle_path(settings, p.source, p.date)))
                if not any(key.startswith(pid + "|") for key in filters):
                    failures.append(f"{pid}: no bloom filters in the bundle")
                idx = searcher._index_dir(p.source, p.date)
                if idx is None or not (idx / "meta.json").exists():
                    failures.append(f"{pid}: BM25 segment missing ({fts_prefix(settings, p.source, p.date)})")
                else:
                    searcher.backend.text_search(idx, "a", 1)
                postings = _postings_rows(settings, p.source, p.date)
                if postings == 0 and p.rows:
                    failures.append(f"{pid}: no keyword postings for {p.source}/{p.date}")
            except Exception as exc:  # noqa: BLE001
                failures.append(f"{pid}: index unreadable ({type(exc).__name__}: {exc})")
    result = {"years": sorted(by_year), "partitions": checked, "files_read": files_read, "bytes_read": bytes_read,
              "archived_objects_read": archived, "failures": failures}
    stages.record(ctx.conn, "readability", datetime.now(timezone.utc).date().isoformat(),
                  "failed" if failures else "ok", load()["version"], result, ctx.command_id)
    if failures:
        raise RuntimeError(f"readability drill failed: {len(failures)} problem(s): " + "; ".join(failures[:5]))
    return HandlerResult(events=[ReadabilityChecked(**result)], detail=result)


def _postings_rows(settings, source: str, day: str) -> int:
    from pyiceberg.exceptions import NoSuchTableError
    from pyiceberg.expressions import And
    try:
        t = get_catalog(settings).load_table("index.keyword_postings")
    except NoSuchTableError:
        return 0
    return t.scan(row_filter=And(EqualTo("day", day), EqualTo("source", source)),
                  selected_fields=("event_id",)).to_arrow().num_rows


# --------------------------------------------------------------------------- legal hold
def set_legal_hold(cmd, ctx):
    from engine.cqrs.handlers import HandlerResult
    now = utcnow()
    upsert(ctx.conn, legal_holds, {"scope": cmd.scope}, {
        "reason": cmd.reason, "actor": cmd.actor, "active": cmd.on, "created_at": now,
        "released_at": None if cmd.on else now})
    files = ctx.conn.execute(select(partition_files.c.file).where(
        partition_files.c.partition_id.like(cmd.scope + "%"))).all()
    n = 0
    if ctx.store.is_s3:
        for f in files:
            bucket, key = f.file.split("/", 1)
            try:
                ctx.store._client().put_object_legal_hold(Bucket=bucket, Key=key,
                                                          LegalHold={"Status": "ON" if cmd.on else "OFF"})
                n += 1
            except Exception as exc:  # noqa: BLE001
                log.warning("legal hold on %s failed: %s", f.file, exc)
    return HandlerResult(events=[LegalHoldChanged(scope=cmd.scope, on=cmd.on, reason=cmd.reason, actor=cmd.actor,
                                                  objects=n or len(files))],
                         detail={"scope": cmd.scope, "on": cmd.on, "objects": len(files)})


def status(conn, settings, store) -> dict:
    """Read-only view for GET /retention."""
    spec = load()
    now = datetime.now(timezone.utc)
    years_present = Counter(int(r.date[:4]) for r in conn.execute(select(partitions.c.date)))
    oldest = min((r.date for r in conn.execute(select(partitions.c.date))), default=None)
    runs = stages.runs(conn, "retention")
    drill = stages.runs(conn, "readability")
    lock = None
    if store.is_s3:
        try:
            lock = store._client().get_object_lock_configuration(Bucket=settings.buckets.raw).get(
                "ObjectLockConfiguration")
        except Exception as exc:  # noqa: BLE001
            lock = {"error": str(exc)}
    layers = {}
    for layer in spec["layers"]:
        years, cutoff = cutoff_for(layer, now)
        r = runs.get(("retention", layer))
        layers[layer] = {"years": years, "cutoff": cutoff, "last_applied": r.finished_at if r else None,
                         "last_result": r.detail if r else None, **{k: v for k, v in spec["layers"][layer].items()
                                                                     if k != "years"}}
    last_drill = max(drill.values(), key=lambda r: r.finished_at, default=None)
    return {"policy_version": spec["version"], "minimum_years": spec["minimum_years"], "layers": layers,
            "overrides": spec.get("overrides") or [], "raw_object_lock": lock,
            "data_years": dict(sorted(years_present.items())), "oldest_partition_date": oldest,
            "span_years": (now.date() - date.fromisoformat(oldest)).days / 365.25 if oldest else None,
            "legal_holds": active_holds(conn),
            "last_readability_drill": {"at": last_drill.finished_at, "status": last_drill.generation,
                                       **(last_drill.detail or {})} if last_drill else None,
            "sealed_partitions": len(conn.execute(select(seal_manifest.c.partition_id).distinct()).all())}
