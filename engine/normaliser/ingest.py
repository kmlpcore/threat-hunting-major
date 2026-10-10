"""IngestBatch: native batch → ECS → partitioned zstd Parquet under raw/.

Layout: raw/source=<src>/date=YYYY-MM-DD/hour=HH/part-<batch_id>.parquet
Files are sorted by (@timestamp, host.name) for min/max pruning. File names are
deterministic, so a retried command overwrites (or, with bucket versioning, adds a
version of) the same object rather than duplicating data.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.engine import Connection

from engine.common.config import Settings
from engine.common.db import as_utc, batches, ip_leases, partition_files, partitions, upsert, utcnow
from engine.common.events import BatchNormalised, PartitionWrite
from engine.common.storage import ObjectStore
from engine.normaliser import ecs
from engine.normaliser.entity import EntityResolver
from engine.normaliser.mapping import load_mapping
from engine.normaliser.normalise import normalise_records

log = logging.getLogger(__name__)
_MIN_TS = datetime.min


def _native_time_bounds(mapping, records: list[dict]) -> tuple[datetime | None, datetime | None]:
    stamps = []
    for rec in records:
        native = mapping.parse_record(rec)
        if native is not None:
            try:
                if (ts := mapping.timestamp_of(native)) is not None:
                    stamps.append(ts)
            except Exception:  # noqa: BLE001 - invalid rows are reported later
                continue
    if not stamps:
        return None, None
    return min(stamps) - timedelta(minutes=5), max(stamps) + timedelta(minutes=5)


def record_leases(conn: Connection, rows: list[dict], lease_seconds: int) -> int:
    """DHCP rows → time-bounded IP leases. Assign/renew opens a lease; release, or the
    same IP going to another host, closes the previous one early."""
    n = 0
    for row in sorted(rows, key=lambda r: r["@timestamp"]):
        action, ts = row.get("event.action"), row["@timestamp"]
        ips, host = row.get("host.ip") or [], row.get("host.name")
        if not ips or not host:
            continue
        ip = ips[0]
        open_leases = conn.execute(select(ip_leases.c.id, ip_leases.c.host_name).where(
            ip_leases.c.ip == ip, ip_leases.c.start <= ts, ip_leases.c.end > ts)).all()
        if action in ("dhcp-assign", "dhcp-renew"):
            for lease in open_leases:
                conn.execute(ip_leases.update().where(ip_leases.c.id == lease.id).values(end=ts))
            exists = conn.execute(select(ip_leases.c.id).where(ip_leases.c.source_event_id == row["event.id"])).first()
            if not exists:
                conn.execute(ip_leases.insert().values(ip=ip, host_name=host, mac=(row.get("host.mac") or [None])[0],
                                                       start=ts, end=ts + timedelta(seconds=lease_seconds),
                                                       source_event_id=row["event.id"]))
                n += 1
        elif action == "dhcp-release":
            for lease in open_leases:
                if lease.host_name == host:
                    conn.execute(ip_leases.update().where(ip_leases.c.id == lease.id).values(end=ts))
    return n


def register_mapping(conn: Connection, source: str, version: str) -> None:
    """Keep every ECS mapping version ever used (M8): data written today must be readable with
    the mapping it was written with, 15+ years from now."""
    import hashlib
    from engine.common.db import ecs_mapping_registry
    from engine.normaliser.mapping import MAPPINGS_DIR
    if conn.execute(select(ecs_mapping_registry.c.version).where(
            ecs_mapping_registry.c.source == source, ecs_mapping_registry.c.version == version)).first():
        return
    path = MAPPINGS_DIR / f"{source}.yaml"
    content = path.read_text() if path.exists() else ""
    conn.execute(ecs_mapping_registry.insert().values(source=source, version=version,
                                                      sha256=hashlib.sha256(content.encode()).hexdigest(),
                                                      content=content, registered_at=utcnow()))


def ingest_batch(conn: Connection, store: ObjectStore, settings: Settings, batch_id: str, batch_uri: str,
                 source: str, command_id: str) -> BatchNormalised:
    mapping = load_mapping(source)
    register_mapping(conn, source, mapping.version)
    cat = ecs.catalog()
    records = list(store.iter_jsonl_gz(batch_uri))

    leases = 0
    if mapping.options.get("produces_leases"):
        # Leases must exist before resolution, and DHCP rows carry their own host name.
        resolver = EntityResolver.load(conn, None, None)
        result = normalise_records(mapping, records, resolver, batch_id, cat.ecs_version)
        leases = record_leases(conn, result.rows, int(mapping.options.get("lease_seconds", 8 * 86400)))
    else:
        start, end = _native_time_bounds(mapping, records)
        resolver = EntityResolver.load(conn, start, end)
        result = normalise_records(mapping, records, resolver, batch_id, cat.ecs_version)

    by_partition: dict[str, list[dict]] = defaultdict(list)
    for row in result.rows:
        by_partition[row["labels.ingest_partition"]].append(row)

    writes: list[PartitionWrite] = []
    late: list[str] = []
    now = utcnow()
    sealed = {r.partition_id for r in conn.execute(
        select(partitions.c.partition_id).where(partitions.c.partition_id.in_(list(by_partition)),
                                                partitions.c.sealed.is_(True)))}
    for pid, rows in sorted(by_partition.items()):
        rows.sort(key=lambda r: (r["@timestamp"], r.get("host.name") or ""))
        if pid in sealed:
            # Late data: never rewrite a sealed (WORM) partition. Land it beside it as a delta;
            # the partition's generation changes, stages rebuild and it is re-sealed (v+1).
            path = f"{settings.buckets.raw}/late/{pid}/part-{batch_id}.parquet"
            late.append(pid)
        else:
            path = f"{settings.buckets.raw}/{pid}/part-{batch_id}.parquet"
        size = store.write_parquet(path, ecs.to_table(rows), settings.raw_row_group_rows, metadata={
            "engine.batch_id": batch_id, "engine.source": source, "engine.ecs_mapping_version": mapping.version,
            "engine.ecs_fields_version": cat.ecs_version})
        _, date, hour = (p.split("=", 1)[1] for p in pid.split("/"))
        pw = PartitionWrite(partition_id=pid, source=source, date=date, hour=hour, file=path, rows=len(rows),
                            bytes=size, min_ts=rows[0]["@timestamp"], max_ts=rows[-1]["@timestamp"])
        writes.append(pw)
        upsert(conn, partition_files, {"partition_id": pid, "batch_id": batch_id}, {
            "file": path, "rows": pw.rows, "bytes": size, "min_ts": pw.min_ts, "max_ts": pw.max_ts,
            "ecs_mapping_version": mapping.version, "written_at": now})
        files = conn.execute(select(partition_files).where(partition_files.c.partition_id == pid)).all()
        upsert(conn, partitions, {"partition_id": pid}, {
            "source": source, "date": date, "hour": hour, "rows": sum(f.rows for f in files), "files": len(files),
            "bytes": sum(f.bytes for f in files), "min_ts": min(as_utc(f.min_ts) for f in files),
            "max_ts": max(as_utc(f.max_ts) for f in files),
            "ecs_mapping_versions": sorted({f.ecs_mapping_version for f in files}), "updated_at": now})

    quarantine_uri = None
    if result.invalid:
        quarantine_uri = f"{settings.buckets.quarantine}/source={source}/{batch_id}.jsonl.gz"
        store.put_jsonl_gz(quarantine_uri, result.invalid)
        log.warning("batch %s: %d invalid rows quarantined at %s", batch_id, len(result.invalid), quarantine_uri)

    resolution = dict(resolver.stats)
    upsert(conn, batches, {"batch_id": batch_id}, {
        "source": source, "batch_uri": batch_uri, "ecs_mapping_version": mapping.version, "rows_in": len(records),
        "rows_out": len(result.rows), "rows_invalid": len(result.invalid),
        "partitions": [w.partition_id for w in writes], "quarantine_uri": quarantine_uri, "resolution": resolution,
        "command_id": command_id, "landed_at": now})

    return BatchNormalised(batch_id=batch_id, source=source, batch_uri=batch_uri, ecs_mapping_version=mapping.version,
                           rows_in=len(records), rows_out=len(result.rows), rows_invalid=len(result.invalid),
                           quarantine_uri=quarantine_uri, leases_recorded=leases, resolution=resolution,
                           partitions=writes, late_partitions=late)
