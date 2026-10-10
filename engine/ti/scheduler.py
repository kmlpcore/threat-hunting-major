"""Feed scheduler (the `ti-connectors` service): submits PullFeed for every enabled connector
whose schedule is due. One PullFeed per connector per schedule slot (the slot is the
idempotency key), so several scheduler replicas never double-pull."""
from __future__ import annotations

import logging
from datetime import datetime, timezone

from sqlalchemy import select
from sqlalchemy.engine import Engine

from engine.common.db import as_utc, feed_state
from engine.cqrs.commands import PullFeed
from engine.cqrs.writer_queue import submit
from engine.ti.connectors.sdk import feed_config, registry

log = logging.getLogger(__name__)


def due(engine: Engine, now: datetime | None = None) -> list[PullFeed]:
    now = now or datetime.now(timezone.utc)
    with engine.connect() as conn:
        last = {r.connector: as_utc(r.last_pull_at) for r in conn.execute(select(feed_state))}
    out = []
    for name in sorted(registry()):
        cfg = feed_config(name)
        if not cfg.get("enabled"):
            continue
        minutes = max(1, int(cfg.get("schedule_minutes", 60)))
        slot = int(now.timestamp() // (minutes * 60))
        prev = last.get(name)
        if prev is None or int(prev.timestamp() // (minutes * 60)) < slot:
            out.append(PullFeed(connector=name, slot=f"{minutes}m:{slot}"))
    return out


def run_once(engine: Engine, max_attempts: int = 3) -> int:
    n = 0
    for cmd in due(engine):
        if not submit(engine, cmd, submitted_by="ti-scheduler", max_attempts=max_attempts).duplicate:
            n += 1
            log.info("scheduled %s (%s)", cmd.connector, cmd.slot)
    return n
