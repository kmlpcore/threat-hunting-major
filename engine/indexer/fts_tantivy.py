"""Tantivy implementation of IndexBackend: BM25 over text fields, exact terms over
keyword fields, and a stored document address pointing back into raw Parquet."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import tantivy

from engine.indexer.backend import KEYWORD_FIELDS, TEXT_FIELDS, DocAddress

INDEX_VERSION = "2"   # v2: adds per source-day bloom bundles


def _schema() -> tantivy.Schema:
    sb = tantivy.SchemaBuilder()
    for f in TEXT_FIELDS.values():
        sb.add_text_field(f, stored=False, tokenizer_name="default")
    for f in KEYWORD_FIELDS.values():
        sb.add_text_field(f, stored=False, tokenizer_name="raw")
    sb.add_text_field("event_id", stored=True, tokenizer_name="raw")
    sb.add_text_field("raw_file", stored=True, tokenizer_name="raw")
    sb.add_text_field("source", stored=True, tokenizer_name="raw")
    sb.add_integer_field("row_group", stored=True, indexed=False)
    sb.add_integer_field("row_offset", stored=True, indexed=False)
    sb.add_date_field("ts", stored=True, indexed=True, fast=True)
    return sb.build()


SCHEMA = _schema()


def _as_list(v) -> list:
    if v is None:
        return []
    return [x for x in (v if isinstance(v, (list, tuple)) else [v]) if x not in (None, "")]


class TantivyBackend:
    name = "tantivy"
    version = f"tantivy-{getattr(tantivy, '__version__', 'py')}/idx{INDEX_VERSION}"

    def build(self, docs: Iterable[dict], out_dir: Path) -> int:
        """docs: {"row": ECS dict, "raw_file", "row_group", "row_offset", "source"}."""
        out_dir.mkdir(parents=True, exist_ok=True)
        index = tantivy.Index(SCHEMA, path=str(out_dir))
        writer = index.writer(heap_size=50_000_000, num_threads=1)
        n = 0
        for d in docs:
            row = d["row"]
            fields: dict[str, list] = {}
            for ecs, f in TEXT_FIELDS.items():
                vals = [str(x) for x in _as_list(row.get(ecs))]
                if vals:
                    fields[f] = vals
            for ecs, f in KEYWORD_FIELDS.items():
                vals = [str(x).lower() for x in _as_list(row.get(ecs))]
                if vals:
                    fields[f] = vals
            ts = row["@timestamp"].astimezone(timezone.utc).replace(tzinfo=None)
            writer.add_document(tantivy.Document(
                **fields, event_id=[row["event.id"]], raw_file=[d["raw_file"]], source=[d["source"]],
                row_group=[d["row_group"]], row_offset=[d["row_offset"]], ts=[ts]))
            n += 1
        writer.commit()
        writer.wait_merging_threads()
        return n

    @staticmethod
    def _open(index_dir: Path) -> tuple[tantivy.Index, tantivy.Searcher]:
        index = tantivy.Index.open(str(index_dir))
        index.reload()
        return index, index.searcher()

    @staticmethod
    def _addr(searcher, score, addr) -> DocAddress:
        doc = searcher.doc(addr)
        ts = doc["ts"][0]
        ts = ts.replace(tzinfo=timezone.utc) if ts.tzinfo is None else ts
        return DocAddress(raw_file=doc["raw_file"][0], row_group=int(doc["row_group"][0]),
                          row_offset=int(doc["row_offset"][0]), event_id=doc["event_id"][0], timestamp=ts,
                          source=doc["source"][0], score=float(score))

    def text_search(self, index_dir: Path, query: str, limit: int, start: datetime | None = None,
                    end: datetime | None = None) -> list[DocAddress]:
        index, searcher = self._open(index_dir)
        q = index.parse_query_lenient(query, list(TEXT_FIELDS.values()))[0] \
            if hasattr(index, "parse_query_lenient") else index.parse_query(query, list(TEXT_FIELDS.values()))
        hits = [self._addr(searcher, s, a) for s, a in searcher.search(q, limit * 4 if (start or end) else limit).hits]
        if start or end:
            hits = [h for h in hits if (not start or h.timestamp >= start) and (not end or h.timestamp <= end)]
        return hits[:limit]

    def term_search(self, index_dir: Path, ecs_field: str, value: str, limit: int = 100_000) -> list[DocAddress]:
        index, searcher = self._open(index_dir)
        q = tantivy.Query.term_query(SCHEMA, KEYWORD_FIELDS[ecs_field], value.lower())
        result = searcher.search(q, limit)
        return [self._addr(searcher, s, a) for s, a in result.hits]
