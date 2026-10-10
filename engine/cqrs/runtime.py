"""Wires settings → database, bus, object store, and runs the CQRS workers.

Service entrypoints (one per container, all from the same engine image):
    python -m engine.cqrs.runtime writer   [--queues raw,meta,system]
    python -m engine.cqrs.runtime relay
    python -m engine.cqrs.runtime projector
"""
from __future__ import annotations

import argparse
import logging
import signal
import time
from dataclasses import dataclass, field

from sqlalchemy.engine import Engine

from engine.common.bus import EventBus, make_bus
from engine.common.config import Settings
from engine.common.db import create_all, make_engine
from engine.common.outbox import OutboxRelay
from engine.common.storage import ObjectStore
from engine.cqrs.commands import QUEUES, Command
from engine.cqrs.handlers import HandlerContext
from engine.cqrs.projectors import Projector
from engine.cqrs.writer_queue import Submitted, Writer, submit

log = logging.getLogger("engine")


@dataclass
class Runtime:
    settings: Settings
    engine: Engine
    bus: EventBus
    store: ObjectStore
    _writer: Writer | None = field(default=None, repr=False)
    _reconciler: object | None = field(default=None, repr=False)

    @classmethod
    def from_settings(cls, settings: Settings, create_tables: bool = False) -> "Runtime":
        engine = make_engine(settings.database_url)
        if create_tables:
            create_all(engine)
        return cls(settings, engine, make_bus(settings.bus_url), ObjectStore.from_settings(settings))

    def ctx_factory(self, conn, command_id: str) -> HandlerContext:
        return HandlerContext(conn=conn, command_id=command_id, settings=self.settings, store=self.store)

    def writer(self, queues: list[str] | None = None) -> Writer:
        if self._writer is None:
            self._writer = Writer(self.engine, self.ctx_factory, queues or QUEUES)
            self._writer.acquire()
        return self._writer

    def relay(self) -> OutboxRelay:
        return OutboxRelay(self.engine, self.bus)

    def projector(self) -> Projector:
        return Projector(self.engine, self.bus)

    def submit(self, command: Command, submitted_by: str = "cli") -> Submitted:
        return submit(self.engine, command, submitted_by=submitted_by,
                      max_attempts=self.settings.writer_max_attempts)

    def reconciler(self):
        if self._reconciler is None:
            from engine.orchestrator.reconciler import Reconciler
            self._reconciler = Reconciler(self.engine, self.settings.writer_max_attempts, settings=self.settings)
        return self._reconciler

    def drain(self, max_rounds: int = 100_000, pipeline: bool = False) -> int:
        """Local mode: run writer → relay → projector (→ orchestrator) until nothing is left to do."""
        writer, relay, projector = self.writer(), self.relay(), self.projector()
        reconciler = self.reconciler() if pipeline else None
        total = 0
        for _ in range(max_rounds):
            n = writer.run_once() + relay.run_once() + projector.run_once(block_ms=0)
            if n == 0 and reconciler is not None:
                n = reconciler.run_once()
            total += n
            if n == 0:
                return total
        raise RuntimeError("drain did not converge")


class _Stop:
    flag = False


def _loop(step, idle_sleep: float) -> None:
    signal.signal(signal.SIGTERM, lambda *_: setattr(_Stop, "flag", True))
    signal.signal(signal.SIGINT, lambda *_: setattr(_Stop, "flag", True))
    while not _Stop.flag:
        try:
            if step() == 0:
                time.sleep(idle_sleep)
        except Exception:  # noqa: BLE001 - keep the service alive, log and back off
            log.exception("worker step failed")
            time.sleep(5)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="engine.cqrs.runtime")
    parser.add_argument("role", choices=["writer", "relay", "projector", "orchestrator", "ti-scheduler"])
    parser.add_argument("--queues", default=",".join(QUEUES))
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")

    rt = Runtime.from_settings(Settings.from_env())
    if args.role == "writer":
        writer = rt.writer(args.queues.split(","))

        def step() -> int:
            if set(writer.owned) != set(writer.wanted):
                writer.acquire()  # pick up queues released by a stopped replica
            return writer.run_once()

        log.info("writer owns queues %s (wanted %s)", writer.owned, writer.wanted)
        _loop(step, idle_sleep=0.5)
        writer.close()
    elif args.role == "orchestrator":
        reconciler = rt.reconciler()
        _loop(reconciler.run_once, idle_sleep=3)
    elif args.role == "ti-scheduler":
        from engine.ti.scheduler import run_once
        _loop(lambda: run_once(rt.engine, rt.settings.writer_max_attempts), idle_sleep=30)
    elif args.role == "relay":
        relay = rt.relay()
        _loop(relay.run_once, idle_sleep=0.25)
    else:
        projector = rt.projector()
        _loop(lambda: projector.run_once(block_ms=1000), idle_sleep=0)


if __name__ == "__main__":
    main()
