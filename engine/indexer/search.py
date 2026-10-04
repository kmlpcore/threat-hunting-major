"""Tier-3 search on the query side: bloom prune → index lookup → selective restore.

    ioc_sweep(value)   exact IOC match on keyword fields (recall must be 100 %)
    text_search(q)     BM25-ranked free text over command lines, URLs, messages, ...

Both report what they touched: partitions considered vs kept by blooms, indexes
opened, raw files / row groups / bytes restored, and the bytes a full
rehydration of the same time range would have needed.
"""
from __future__ import annotations

import ipaddress
import re
import threading
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.engine import Engine

from engine.common.config import Settings
from engine.common.db import as_utc, rm_partition_health
from engine.common.storage import ObjectStore
from engine.indexer.backend import IOC_FIELDS, DocAddress
from engine.indexer.bloom import BloomFilter, normalise_value
from engine.indexer.build import bloom_bundle_path, bloom_path, fts_prefix, unpack_bundle, unpack_to
from engine.indexer.fts_tantivy import TantivyBackend

RESULT_COLUMNS = ["@timestamp", "event.id", "event.dataset", "event.action", "event.outcome", "host.name",
                  "user.name", "source.ip", "destination.ip", "destination.port", "process.name",
                  "process.command_line", "process.parent.name", "dns.question.name", "url.full",
                  "http.request.method", "http.request.bytes", "labels.ingest_partition"]


def detect_ioc_type(value: str) -> str:
    v = value.strip()
    try:
        ipaddress.ip_address(v)
        return "ip"
    except ValueError:
        pass
    if re.fullmatch(r"[0-9a-fA-F]{32}|[0-9a-fA-F]{40}|[0-9a-fA-F]{64}", v):
        return "hash"
    if "." in v and re.fullmatch(r"[A-Za-z0-9._-]+", v):
        return "domain"
    return "user"


def partition_of(raw_file: str) -> str:
    parts = [p for p in raw_file.split("/") if p.startswith(("source=", "date=", "hour="))]
    return "/".join(parts[:3])


@dataclass
class SearchStats:
    partitions_in_range: int = 0
    partitions_after_bloom: int = 0
    bloom_false_positive_partitions: int = 0
    bloom_filters_read: int = 0
    indexes_opened: int = 0
    hits: int = 0
    files_restored: int = 0
    row_groups_restored: int = 0
    bytes_restored: int = 0
    full_rehydration_bytes: int = 0
    duration_ms: int = 0
    notes: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        d = dict(self.__dict__)
        d["restore_ratio"] = round(self.bytes_restored / self.full_rehydration_bytes, 6) \
            if self.full_rehydration_bytes else None
        d["partition_prune_ratio"] = round(1 - self.partitions_after_bloom / self.partitions_in_range, 4) \
            if self.partitions_in_range else None
        return d


class Searcher:
    def __init__(self, engine: Engine, store: ObjectStore, settings: Settings, cache_dir: Path | None = None):
        self.engine, self.store, self.settings = engine, store, settings
        self.cache_dir = cache_dir or Path("/tmp/engine-index-cache")
        self.backend = TantivyBackend()
        self._blooms: dict[tuple[str, str, str], BloomFilter] = {}
        self._bundles: dict[tuple[str, str, str], dict[str, BloomFilter]] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------ helpers
    def _partitions(self, start: datetime | None, end: datetime | None, sources: list[str] | None) -> list:
        t = rm_partition_health
        q = select(t.c.partition_id, t.c.source, t.c.date, t.c.bytes, t.c.min_ts, t.c.max_ts, t.c.stages)
        if sources:
            q = q.where(t.c.source.in_(sources))
        with self.engine.connect() as conn:
            rows = conn.execute(q).all()
        out = []
        for r in rows:
            lo, hi = as_utc(r.min_ts), as_utc(r.max_ts)
            if (start and hi and hi < start) or (end and lo and lo > end):
                continue
            if not (r.stages or {}).get("index"):
                continue   # not indexed yet: cannot be answered at tier 3 (reported)
            out.append(r)
        return out

    def _manifest_generation(self, source: str, day: str) -> str | None:
        path = f"{fts_prefix(self.settings, source, day)}/manifest.json"
        return self.store.get_json(path)["generation"] if self.store.exists(path) else None

    def _index_dir(self, source: str, day: str) -> Path | None:
        gen = self._manifest_generation(source, day)
        if gen is None:
            return None
        target = self.cache_dir / f"{source}_{day}_{gen}"
        with self._lock:
            if not (target / "meta.json").exists():
                data = self.store.get_bytes(f"{fts_prefix(self.settings, source, day)}/segment.tar.zst")
                unpack_to(data, target)
        return target

    def _bundle(self, source: str, day: str, gen_key: str) -> dict[str, BloomFilter] | None:
        key = (source, day, gen_key)
        if key not in self._bundles:
            path = bloom_bundle_path(self.settings, source, day)
            if not self.store.exists(path):
                return None
            self._bundles[key] = unpack_bundle(self.store.get_bytes(path))[1]
        return self._bundles[key]

    def _bloom(self, pid: str, field: str, gen_key: str) -> BloomFilter | None:
        source, day, _ = (x.split("=", 1)[1] for x in pid.split("/"))
        bundle = self._bundle(source, day, gen_key)
        if bundle is not None:
            return bundle.get(f"{pid}|{field}")
        key = (pid, field, gen_key)          # fall back to the per-partition sidecar
        if key not in self._blooms:
            path = bloom_path(self.settings, pid, field)
            if not self.store.exists(path):
                return None
            self._blooms[key] = BloomFilter.from_bytes(self.store.get_bytes(path))
        return self._blooms[key]

    def _gen_keys(self, parts) -> dict[tuple[str, str], str]:
        """Cache key per source-day: changes when any of its partitions changes (late data)."""
        acc: dict[tuple[str, str], list] = defaultdict(list)
        for p in parts:
            acc[(p.source, p.date)].append(f"{p.partition_id}:{p.bytes}")
        return {k: str(hash(tuple(sorted(v)))) for k, v in acc.items()}

    def warm(self) -> int:
        """Pre-load bloom bundles and index segments so the first hunt is fast."""
        parts = self._partitions(None, None, None)
        keys = self._gen_keys(parts)
        for (source, day), gk in keys.items():
            try:
                self._bundle(source, day, gk)
                self._index_dir(source, day)
            except Exception:  # noqa: BLE001 - warming is best effort
                pass
        return len(keys)

    def restore(self, hits: list[DocAddress], stats: SearchStats, columns: list[str] = RESULT_COLUMNS) -> list[dict]:
        by_file: dict[str, dict[int, set[int]]] = defaultdict(lambda: defaultdict(set))
        for h in hits:
            by_file[h.raw_file][h.row_group].add(h.row_offset)
        rows_by_addr = {}
        for path, groups in by_file.items():
            meta = self.store.parquet_metadata(path)
            cols = [c for c in columns if c in meta.schema.names]
            table, nbytes = self.store.read_row_groups(path, list(groups), cols)
            stats.files_restored += 1
            stats.row_groups_restored += len(groups)
            stats.bytes_restored += nbytes
            data = table.to_pylist()
            base = 0
            for rg in sorted(groups):
                for off in groups[rg]:
                    rows_by_addr[(path, rg, off)] = data[base + off]
                base += meta.row_group(rg).num_rows
        out = []
        for h in hits:
            row = rows_by_addr.get((h.raw_file, h.row_group, h.row_offset))
            if row is not None:
                out.append({**{k: v for k, v in row.items() if v not in (None, [])}, "_score": round(h.score, 4),
                            "_address": {"file": h.raw_file, "row_group": h.row_group, "row_offset": h.row_offset}})
        return out

    # ------------------------------------------------------------------ IOC sweep
    def ioc_sweep(self, value: str, ioc_type: str | None = None, start: datetime | None = None,
                  end: datetime | None = None, sources: list[str] | None = None, limit: int = 200) -> dict:
        t0 = time.monotonic()
        ioc_type = ioc_type or detect_ioc_type(value)
        fields = IOC_FIELDS[ioc_type]
        needle = normalise_value(value)
        stats = SearchStats()
        parts = self._partitions(start, end, sources)
        stats.partitions_in_range = len(parts)
        stats.full_rehydration_bytes = sum(p.bytes for p in parts)

        kept_by_day: dict[tuple[str, str], set[str]] = defaultdict(set)
        gen_keys = self._gen_keys(parts)
        for p in parts:
            gen_key = gen_keys[(p.source, p.date)]
            hit = False
            for f in fields:
                bf = self._bloom(p.partition_id, f, gen_key)
                stats.bloom_filters_read += 1
                if bf is not None and needle in bf:
                    hit = True
                    break
            if hit:
                kept_by_day[(p.source, p.date)].add(p.partition_id)
        stats.partitions_after_bloom = sum(len(v) for v in kept_by_day.values())

        hits: dict[str, DocAddress] = {}
        partitions_with_hits = set()
        for (source, day), pids in sorted(kept_by_day.items()):
            idx = self._index_dir(source, day)
            if idx is None:
                continue
            stats.indexes_opened += 1
            for f in fields:
                for h in self.backend.term_search(idx, f, needle):
                    pid = partition_of(h.raw_file)
                    if pid in pids and (not start or h.timestamp >= start) and (not end or h.timestamp <= end):
                        hits[h.event_id] = h
                        partitions_with_hits.add(pid)
        stats.bloom_false_positive_partitions = stats.partitions_after_bloom - len(partitions_with_hits)
        stats.hits = len(hits)
        ordered = sorted(hits.values(), key=lambda h: h.timestamp)
        events = self.restore(ordered[:limit], stats)
        stats.duration_ms = int((time.monotonic() - t0) * 1000)
        return {"tier": 3, "mode": "ioc", "value": value, "ioc_type": ioc_type, "fields": fields,
                "stats": stats.as_dict(), "event_ids": [h.event_id for h in ordered], "events": events}

    # ------------------------------------------------------------------ BM25 free text
    def text_search(self, query: str, start: datetime | None = None, end: datetime | None = None,
                    sources: list[str] | None = None, limit: int = 20) -> dict:
        t0 = time.monotonic()
        stats = SearchStats()
        parts = self._partitions(start, end, sources)
        stats.partitions_in_range = stats.partitions_after_bloom = len(parts)
        stats.full_rehydration_bytes = sum(p.bytes for p in parts)
        days = sorted({(p.source, p.date) for p in parts})
        hits: list[DocAddress] = []
        for source, day in days:
            idx = self._index_dir(source, day)
            if idx is None:
                continue
            stats.indexes_opened += 1
            hits.extend(self.backend.text_search(idx, query, limit, start, end))
        hits.sort(key=lambda h: h.score, reverse=True)
        top = hits[:limit]
        stats.hits = len(hits)
        stats.notes.append("BM25 scores are per source-day index; merged top-k is approximate across indexes")
        events = self.restore(top, stats)
        stats.duration_ms = int((time.monotonic() - t0) * 1000)
        return {"tier": 3, "mode": "bm25", "query": query, "stats": stats.as_dict(),
                "event_ids": [h.event_id for h in top], "events": events}
