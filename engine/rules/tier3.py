"""Tier 3: index-pruned selective restore of raw Parquet (plan.md sections 3.5 and 3.8).

1. Anchors: from the rule predicate, a set of exact (keyword field, value) terms such that
   every event the rule can match contains at least one of them. Equality literals on an
   indexed keyword field are anchors; OR needs anchors on every branch, AND needs them on
   one. `contains`-style literals are not anchors: substring matches do not line up with
   index tokens, so using the text index for them could miss events.
2. Bloom filters (hot) drop hour partitions that cannot contain any anchor term.
3. The keyword index (hot) returns (raw file, row group) addresses for the remaining ones.
4. Only those objects / row groups are restored; the full SQL predicate is then evaluated on
   them, so results are exact. Without anchors, or for days whose index is not current, the
   step restores every object of the rule's sources in range and says so.

The locator works from write-side metadata (meta.partition_files, index manifests), so the
planner can estimate a restore without touching raw or the archive.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.engine import Connection

from engine.common import stages
from engine.common.db import as_utc, partition_files
from engine.indexer.backend import KEYWORD_FIELDS
from engine.indexer.bloom import BLOOM_FIELDS, normalise_value
from engine.indexer.search import Searcher, partition_of
from engine.rules.capabilities import rewrite
from engine.rules.compiler import Expr, Lit

MAX_ANCHOR_TERMS = 5000


@dataclass(frozen=True)
class RawFile:
    file: str
    partition_id: str
    source: str
    day: str
    bytes: int
    rows: int
    min_ts: datetime
    max_ts: datetime


def raw_files(conn: Connection, sources: list[str], start: datetime, end: datetime) -> list[RawFile]:
    out = []
    for r in conn.execute(select(partition_files).order_by(partition_files.c.partition_id, partition_files.c.batch_id)):
        src, day, _ = (x.split("=", 1)[1] for x in r.partition_id.split("/"))
        if src not in sources:
            continue
        lo, hi = as_utc(r.min_ts), as_utc(r.max_ts)
        if hi < start or lo > end:
            continue
        out.append(RawFile(r.file, r.partition_id, src, day, r.bytes, r.rows, lo, hi))
    return out


def anchors(e: Expr) -> set[tuple[str, str]] | None:
    """Sound anchor terms for `e`, or None when some match could carry no indexed term."""
    if isinstance(e, Lit):
        if e.op == "eq" and e.field in KEYWORD_FIELDS and e.value is not None and not isinstance(e.value, bool):
            v = e.value
            if isinstance(v, float) and v.is_integer():
                v = int(v)
            return {(e.field, normalise_value(v))}
        return None
    if e.kind == "not":
        return None
    parts = [anchors(i) for i in e.items]
    if e.kind == "or":
        if any(p is None for p in parts):
            return None
        return set().union(*parts)
    usable = [p for p in parts if p is not None]
    if not usable:
        return None
    # AND: one child suffices. Prefer terms the bloom filters can prune, then fewer terms.
    return min(usable, key=lambda p: (not all(f in BLOOM_FIELDS for f, _ in p), len(p)))


@dataclass
class Located:
    """Objects (and row groups) a tier-3 step must restore."""
    targets: dict[str, set[int] | None] = field(default_factory=dict)   # file -> row groups (None = whole file)
    anchors: int = 0
    mode: str = "raw_indexed"                 # raw_indexed | raw_scan | mixed
    partitions_in_range: int = 0
    partitions_after_bloom: int = 0
    unindexed_days: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)


class Locator(Searcher):
    """Reuses the query-side bloom/index readers, but enumerates partitions from write-side
    metadata and only trusts an index whose generation matches the landed data."""

    def __init__(self, engine, store, settings, cache_dir: Path | None = None):
        super().__init__(engine, store, settings, cache_dir or Path("/tmp/engine-index-cache"))

    def locate(self, conn: Connection, files: list[RawFile], predicate: Expr) -> Located:
        loc = Located()
        terms = anchors(rewrite(predicate))
        if terms is not None and len(terms) > MAX_ANCHOR_TERMS:
            loc.notes.append(f"{len(terms)} anchor terms exceed {MAX_ANCHOR_TERMS}: scanning instead")
            terms = None
        loc.partitions_in_range = len({f.partition_id for f in files})
        if terms is None:
            loc.mode = "raw_scan"
            loc.notes.append("no exact keyword anchor in every branch of the predicate: every object of the "
                             "rule's sources in range is restored")
            loc.targets = {f.file: None for f in files}
            loc.partitions_after_bloom = loc.partitions_in_range
            return loc
        loc.anchors = len(terms)
        by_term_field: dict[str, set[str]] = defaultdict(set)
        for f_, v in terms:
            by_term_field[f_].add(v)
        day_gens = stages.day_generations(conn)
        by_day: dict[tuple[str, str], list[RawFile]] = defaultdict(list)
        for f in files:
            by_day[(f.source, f.day)].append(f)
        for (source, day), day_files in sorted(by_day.items()):
            manifest_gen = self._manifest_generation(source, day)
            if manifest_gen is None or manifest_gen != day_gens.get((source, day)):
                loc.unindexed_days.append(f"{source}/{day}")
                loc.targets.update({f.file: None for f in day_files})
                loc.partitions_after_bloom += len({f.partition_id for f in day_files})
                continue
            kept_pids = set()
            for pid in sorted({f.partition_id for f in day_files}):
                keep = False
                for f_, values in by_term_field.items():
                    if f_ not in BLOOM_FIELDS:
                        keep = True             # no bloom for this field: the index decides
                        break
                    bf = self._bloom(pid, f_, manifest_gen)
                    if bf is None or any(v in bf for v in values):
                        keep = True
                        break
                if keep:
                    kept_pids.add(pid)
            loc.partitions_after_bloom += len(kept_pids)
            if not kept_pids:
                continue
            wanted = {f.file for f in day_files if f.partition_id in kept_pids}
            idx = self._index_dir(source, day)
            if idx is None:
                loc.unindexed_days.append(f"{source}/{day}")
                loc.targets.update({f: None for f in wanted})
                continue
            for f_, values in by_term_field.items():
                for v in values:
                    for h in self.backend.term_search(idx, f_, v):
                        if h.raw_file in wanted and partition_of(h.raw_file) in kept_pids:
                            rgs = loc.targets.setdefault(h.raw_file, set())
                            if rgs is not None:
                                rgs.add(h.row_group)
        if loc.unindexed_days:
            loc.mode = "mixed"
            loc.notes.append(f"index not current for {len(loc.unindexed_days)} source-days: their objects are "
                             "restored in full")
        return loc
