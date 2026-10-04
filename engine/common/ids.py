"""Stable identifiers.

event.id is derived from the source name and the native record, so re-ingesting
the same batch always yields the same IDs. Byte-identical records in one batch
(possible for sources without a native record ID, e.g. proxy lines) are told
apart by their occurrence index. The generator uses the same function, which is
how ground-truth labels point at raw events without the engine seeing labels.
"""
from __future__ import annotations

import hashlib
import json
from collections import Counter
from typing import Iterable


def canonical(record: dict) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), default=str)


def stable_event_ids(source: str, records: Iterable[dict]) -> list[str]:
    seen: Counter[str] = Counter()
    ids = []
    for rec in records:
        digest = hashlib.sha256(f"{source}\x1f{canonical(rec)}".encode()).hexdigest()[:32]
        n = seen[digest]
        seen[digest] += 1
        ids.append(digest if n == 0 else hashlib.sha256(f"{digest}\x1f{n}".encode()).hexdigest()[:32])
    return ids


def short_hash(*parts: object, length: int = 16) -> str:
    return hashlib.sha256("\x1f".join(map(str, parts)).encode()).hexdigest()[:length]
