"""Transactional outbox: events are written in the same Postgres transaction as the
state change that caused them, then relayed to the bus.
"""
from __future__ import annotations

import logging

from sqlalchemy import select
from sqlalchemy.engine import Connection, Engine

from engine.common.bus import EVENTS_STREAM, EventBus
from engine.common.db import is_postgres, outbox, utcnow
from engine.common.events import Envelope

log = logging.getLogger(__name__)


def append(conn: Connection, envelope: Envelope) -> None:
    conn.execute(outbox.insert().values(
        event_id=envelope.event_id,
        event_type=envelope.event_type,
        envelope=envelope.model_dump(mode="json"),
        created_at=utcnow(),
    ))


class OutboxRelay:
    def __init__(self, engine: Engine, bus: EventBus, stream: str = EVENTS_STREAM):
        self.engine = engine
        self.bus = bus
        self.stream = stream

    def run_once(self, limit: int = 500) -> int:
        """Publish unpublished events in order. Publish-then-mark gives at-least-once."""
        with self.engine.begin() as conn:
            query = (select(outbox.c.id, outbox.c.envelope).where(outbox.c.published_at.is_(None))
                     .order_by(outbox.c.id).limit(limit))
            if is_postgres(conn):
                query = query.with_for_update(skip_locked=True)
            rows = conn.execute(query).all()
            for row in rows:
                self.bus.publish(self.stream, row.envelope)
                conn.execute(outbox.update().where(outbox.c.id == row.id).values(published_at=utcnow()))
        if rows:
            log.info("relayed %d events", len(rows))
        return len(rows)
