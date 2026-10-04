"""Event bus client: Redis Streams in compose, an in-memory stream for local mode.

Delivery is at-least-once with consumer groups; consumers must be idempotent
(projectors de-duplicate by event_id).
"""
from __future__ import annotations

import json
import threading
from collections import defaultdict
from typing import Protocol

EVENTS_STREAM = "events"


class EventBus(Protocol):
    def publish(self, stream: str, message: dict) -> str: ...
    def read_group(self, stream: str, group: str, consumer: str, count: int = 100,
                   block_ms: int = 1000) -> list[tuple[str, dict]]: ...
    def ack(self, stream: str, group: str, message_id: str) -> None: ...
    def ping(self) -> bool: ...


class RedisStreamsBus:
    def __init__(self, url: str):
        import redis
        self.r = redis.Redis.from_url(url, decode_responses=True)
        self._groups: set[tuple[str, str]] = set()
        self._recovered: set[tuple[str, str, str]] = set()

    def publish(self, stream: str, message: dict) -> str:
        return self.r.xadd(stream, {"data": json.dumps(message, default=str)}, maxlen=1_000_000, approximate=True)

    def _ensure_group(self, stream: str, group: str) -> None:
        if (stream, group) in self._groups:
            return
        import redis
        try:
            self.r.xgroup_create(stream, group, id="0", mkstream=True)
        except redis.ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise
        self._groups.add((stream, group))

    def read_group(self, stream, group, consumer, count=100, block_ms=1000):
        self._ensure_group(stream, group)
        # First drain this consumer's pending (delivered but un-acked) messages after a restart.
        key = (stream, group, consumer)
        start = "0" if key not in self._recovered else ">"
        resp = self.r.xreadgroup(group, consumer, {stream: start}, count=count,
                                 block=None if start == "0" else block_ms)
        messages = [(mid, json.loads(fields["data"])) for _, entries in (resp or []) for mid, fields in entries]
        if start == "0" and not messages:
            self._recovered.add(key)
        return messages

    def ack(self, stream, group, message_id):
        self.r.xack(stream, group, message_id)

    def ping(self) -> bool:
        return bool(self.r.ping())


class InMemoryBus:
    """Single-process stand-in with the same consumer-group semantics."""

    def __init__(self):
        self._lock = threading.Lock()
        self._streams: dict[str, list[tuple[str, dict]]] = defaultdict(list)
        self._offsets: dict[tuple[str, str], int] = defaultdict(int)
        self._pending: dict[tuple[str, str], dict[str, dict]] = defaultdict(dict)

    def publish(self, stream, message):
        with self._lock:
            mid = f"{len(self._streams[stream]) + 1}-0"
            self._streams[stream].append((mid, json.loads(json.dumps(message, default=str))))
            return mid

    def read_group(self, stream, group, consumer, count=100, block_ms=0):
        with self._lock:
            key = (stream, group)
            start = self._offsets[key]
            batch = self._streams[stream][start:start + count]
            self._offsets[key] = start + len(batch)
            for mid, msg in batch:
                self._pending[key][mid] = msg
            return list(batch)

    def ack(self, stream, group, message_id):
        with self._lock:
            self._pending[(stream, group)].pop(message_id, None)

    def ping(self) -> bool:
        return True

    def length(self, stream: str) -> int:
        return len(self._streams[stream])


def make_bus(url: str) -> EventBus:
    if url.startswith("memory://"):
        return InMemoryBus()
    if url.startswith(("redis://", "rediss://")):
        return RedisStreamsBus(url)
    raise ValueError(f"unsupported BUS_URL: {url}")
