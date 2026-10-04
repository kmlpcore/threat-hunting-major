"""Native records → validated ECS rows."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable

from engine.common.db import utcnow
from engine.common.ids import canonical, stable_event_ids
from engine.normaliser import ecs
from engine.normaliser.entity import EntityResolver
from engine.normaliser.mapping import Mapping


def partition_id(source: str, ts: datetime) -> str:
    return f"source={source}/date={ts:%Y-%m-%d}/hour={ts:%H}"


@dataclass
class NormaliseResult:
    rows: list[dict] = field(default_factory=list)
    invalid: list[dict] = field(default_factory=list)  # {"event_id", "errors", "record"}


def _as_list(value) -> list:
    if value is None:
        return []
    return list(value) if isinstance(value, (list, tuple)) else [value]


def _related(row: dict) -> None:
    ips = [row.get("source.ip"), row.get("destination.ip"), *_as_list(row.get("host.ip")),
           *_as_list(row.get("dns.resolved_ip"))]
    users = [row.get("user.name"), row.get("user.target.name")]
    hosts = [row.get("host.name"), row.get("destination.domain")]
    hashes = [row.get("process.hash.sha256"), row.get("process.hash.md5"), row.get("file.hash.sha256")]
    for key, vals in (("related.ip", ips), ("related.user", users), ("related.hosts", hosts),
                      ("related.hash", hashes)):
        vals = [v for v in dict.fromkeys(vals) if v]
        if vals:
            row[key] = vals


def normalise_records(mapping: Mapping, records: Iterable[dict], resolver: EntityResolver, batch_id: str,
                      ecs_version: str) -> NormaliseResult:
    records = list(records)
    event_ids = stable_event_ids(mapping.source, records)
    ingested = utcnow()
    out = NormaliseResult()
    for rec, event_id in zip(records, event_ids):
        errors: list[str] = []
        native = mapping.parse_record(rec)
        if native is None:
            out.invalid.append({"event_id": event_id, "errors": ["unparseable record"], "record": rec})
            continue
        try:
            ts = mapping.timestamp_of(native)
            row, ents = mapping.apply(native)
        except Exception as exc:  # noqa: BLE001 - a bad record must never fail the batch
            out.invalid.append({"event_id": event_id, "errors": [f"mapping error: {exc}"], "record": rec})
            continue
        if ts is None:
            out.invalid.append({"event_id": event_id, "errors": ["missing timestamp"], "record": rec})
            continue

        row["@timestamp"] = ts
        row["event.id"] = event_id
        row["event.ingested"] = ingested
        row["event.original"] = rec["message"] if mapping.format != "json" else canonical(rec)
        row["ecs.version"] = ecs_version
        row.setdefault("event.dataset", mapping.dataset)

        if "user" in ents:
            u = ents["user"]
            row.update({k: v for k, v in resolver.resolve_user(u.get("name"), u.get("domain"), u.get("sid")).items()
                        if v is not None})
        if "target_user" in ents:
            t = ents["target_user"]
            res = resolver.resolve_user(t.get("name"), t.get("domain"), t.get("sid"))
            if res.get("user.name"):
                row["user.target.name"] = res["user.name"]
            if res.get("user.id"):
                row["user.target.id"] = res["user.id"]
        if "host" in ents:
            h = ents["host"]
            row.update({k: v for k, v in resolver.resolve_host(h.get("name"), row, h.get("ip_fields") or [],
                                                               ts).items() if v is not None})

        mapping.post_process(row)
        _related(row)
        row["labels.ingest_partition"] = partition_id(mapping.source, ts)
        row["labels.ingest_batch"] = batch_id
        row["labels.ecs_mapping_version"] = mapping.version

        coerced, errors = ecs.coerce(row)
        errors += ecs.validate(coerced)
        if errors:
            out.invalid.append({"event_id": event_id, "errors": errors, "record": rec})
        else:
            out.rows.append(coerced)
    return out
