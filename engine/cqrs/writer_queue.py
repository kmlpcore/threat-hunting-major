"""Single-writer command queues backed by the Postgres `meta.commands` table.

Using the database as the queue avoids a dual write: a command is accepted iff its
row is committed. A writer process owns a queue by holding a Postgres advisory
lock on it, so even with several writer replicas each queue has one writer and
commands run strictly in submission order.
"""
from __future__ import annotations

import hashlib
import logging
import traceback
import uuid
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import select, text
from sqlalchemy.engine import Connection, Engine
from sqlalchemy.exc import IntegrityError

from engine.common import outbox
from engine.common.db import as_utc, commands, is_postgres, utcnow
from engine.common.events import CommandCompleted, CommandFailed, Envelope
from engine.cqrs.commands import COMMAND_TYPES, Command

log = logging.getLogger(__name__)


@dataclass
class Submitted:
    command_id: str
    status: str
    duplicate: bool


def submit(engine: Engine, command: Command, submitted_by: str = "cli", idempotency_key: str | None = None,
           max_attempts: int = 3) -> Submitted:
    key = idempotency_key or command.idempotency_key()
    now = utcnow()
    command_id = str(uuid.uuid4())
    try:
        with engine.begin() as conn:
            conn.execute(commands.insert().values(
                command_id=command_id, command_type=command.command_type, queue=command.queue,
                payload=command.model_dump(mode="json"), idempotency_key=key, status="queued", attempts=0,
                max_attempts=max_attempts, not_before=now, submitted_by=submitted_by, submitted_at=now,
            ))
        return Submitted(command_id, "queued", duplicate=False)
    except IntegrityError:
        with engine.connect() as conn:
            row = conn.execute(select(commands.c.command_id, commands.c.status)
                               .where(commands.c.idempotency_key == key)).one()
        return Submitted(row.command_id, row.status, duplicate=True)


def requeue_failed(engine: Engine, command_types: list[str], older_than: timedelta, max_total_attempts: int) -> int:
    """Give permanently failed commands another round after a cool-down (transient infra errors:
    a restarted database, an unreachable catalog). Capped so a real bug cannot loop forever."""
    cutoff = utcnow() - older_than
    with engine.begin() as conn:
        return conn.execute(commands.update().where(
            commands.c.status == "failed", commands.c.command_type.in_(command_types),
            commands.c.finished_at < cutoff, commands.c.max_attempts < max_total_attempts,
        ).values(status="queued", not_before=utcnow(), max_attempts=commands.c.max_attempts + 3,
                 finished_at=None)).rowcount


def _lock_id(queue: str) -> int:
    return int.from_bytes(hashlib.sha256(f"writer:{queue}".encode()).digest()[:8], "big", signed=True)


class Writer:
    """Executes commands for the queues it owns. Handlers run inside one transaction
    together with the command status update and their outbox events."""

    def __init__(self, engine: Engine, ctx_factory, queues: list[str]):
        self.engine = engine
        self.ctx_factory = ctx_factory
        self.wanted = queues
        self.owned: list[str] = []
        self._lock_conn: Connection | None = None

    def acquire(self) -> list[str]:
        if is_postgres(self.engine):
            if self._lock_conn is None:
                self._lock_conn = self.engine.connect()
            for q in self.wanted:
                if q not in self.owned and self._lock_conn.execute(
                        text("SELECT pg_try_advisory_lock(:k)"), {"k": _lock_id(q)}).scalar():
                    self.owned.append(q)
            self._lock_conn.commit()
        else:
            self.owned = list(self.wanted)
        if self.owned:
            self._recover(self.owned)
        return self.owned

    def _recover(self, queues: list[str]) -> None:
        # We hold the queue lock, so any "running" row is from a crashed writer.
        with self.engine.begin() as conn:
            n = conn.execute(commands.update().where(commands.c.queue.in_(queues), commands.c.status == "running")
                             .values(status="queued")).rowcount
        if n:
            log.warning("requeued %d interrupted commands on %s", n, queues)

    def run_once(self) -> int:
        """Run at most one command per owned queue. Returns how many ran."""
        ran = 0
        for queue in self.owned:
            row = self._claim(queue)
            if row is not None:
                self._execute(row)
                ran += 1
        return ran

    def _claim(self, queue: str):
        with self.engine.begin() as conn:
            row = conn.execute(
                select(commands).where(commands.c.queue == queue, commands.c.status == "queued",
                                       commands.c.not_before <= utcnow())
                .order_by(commands.c.seq).limit(1)).first()
            if row is None:
                return None
            conn.execute(commands.update().where(commands.c.seq == row.seq)
                         .values(status="running", attempts=row.attempts + 1, started_at=utcnow()))
        return row

    def _execute(self, row) -> None:
        from engine.cqrs.handlers import HANDLERS, HandlerContext

        cmd_cls = COMMAND_TYPES[row.command_type]
        attempts = row.attempts + 1
        try:
            command = cmd_cls.model_validate(row.payload)
            with self.engine.begin() as conn:
                ctx: HandlerContext = self.ctx_factory(conn, row.command_id)
                result = HANDLERS[row.command_type](command, ctx)
                for event in result.events:
                    outbox.append(conn, Envelope.wrap(event, row.command_id))
                outbox.append(conn, Envelope.wrap(CommandCompleted(
                    command_id=row.command_id, command_type=row.command_type, attempts=attempts,
                    detail=result.detail), row.command_id))
                conn.execute(commands.update().where(commands.c.seq == row.seq)
                             .values(status="succeeded", finished_at=utcnow(), error=None))
            log.info("command %s %s succeeded", row.command_type, row.command_id)
        except Exception as exc:  # noqa: BLE001 - every failure must be recorded
            err = f"{type(exc).__name__}: {exc}"
            log.error("command %s %s failed (attempt %d): %s\n%s", row.command_type, row.command_id, attempts, err,
                      traceback.format_exc())
            retry = attempts < row.max_attempts
            with self.engine.begin() as conn:
                conn.execute(commands.update().where(commands.c.seq == row.seq).values(
                    status="queued" if retry else "failed", error=err[:4000],
                    finished_at=None if retry else utcnow(),
                    not_before=utcnow() + timedelta(seconds=min(2 ** attempts, 60)) if retry else as_utc(row.not_before)))
                outbox.append(conn, Envelope.wrap(CommandFailed(
                    command_id=row.command_id, command_type=row.command_type, attempts=attempts, error=err[:4000],
                    will_retry=retry), row.command_id))

    def close(self) -> None:
        if self._lock_conn is not None:
            self._lock_conn.close()
            self._lock_conn = None
