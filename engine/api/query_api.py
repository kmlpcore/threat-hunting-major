"""Query API (read side). Serves projected read models only; every response carries
`projected_at` so clients can see how fresh the (eventually consistent) data is."""
from __future__ import annotations

from datetime import datetime

from fastapi import FastAPI, HTTPException
from sqlalchemy import func, select, text

from engine.common.config import Settings
from engine.common.db import (as_utc, rm_batch_status, rm_command_status, rm_inventory, rm_partition_health,
                              rm_pings)
from engine.cqrs.runtime import Runtime


def _row(r) -> dict:
    d = dict(r._mapping)
    return {k: as_utc(v) if isinstance(v, datetime) else v for k, v in d.items()}


def _page(rows: list[dict], total: int | None = None) -> dict:
    stamps = [r["projected_at"] for r in rows if r.get("projected_at")]
    return {"items": rows, "count": len(rows), "total": total if total is not None else len(rows),
            "projected_at": max(stamps) if stamps else None}


def create_app(runtime: Runtime | None = None) -> FastAPI:
    rt = runtime or Runtime.from_settings(Settings.from_env())
    app = FastAPI(title="Threat Hunting Engine — Query API", version="0.9.0")

    @app.get("/health")
    def health():
        with rt.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "ok", "bus": rt.bus.ping(), "storage": rt.store.description}

    @app.get("/commands/{command_id}")
    def command_status(command_id: str):
        with rt.engine.connect() as conn:
            r = conn.execute(select(rm_command_status).where(rm_command_status.c.command_id == command_id)).first()
        if r is None:
            # Not projected yet (or unknown): eventual consistency, so 404 with a hint rather than a guess.
            raise HTTPException(404, "no projection for this command yet")
        return _row(r)

    @app.get("/pings")
    def pings(limit: int = 50):
        with rt.engine.connect() as conn:
            rows = conn.execute(select(rm_pings).order_by(rm_pings.c.recorded_at.desc()).limit(limit)).all()
        return _page([_row(r) for r in rows])

    @app.get("/inventory")
    def inventory():
        with rt.engine.connect() as conn:
            rows = conn.execute(select(rm_inventory)).all()
        return _page([_row(r) for r in rows])

    @app.get("/batches")
    def batches(source: str | None = None, limit: int = 500):
        q = select(rm_batch_status).order_by(rm_batch_status.c.batch_id).limit(limit)
        if source:
            q = q.where(rm_batch_status.c.source == source)
        with rt.engine.connect() as conn:
            rows = conn.execute(q).all()
        return _page([_row(r) for r in rows])

    @app.get("/partitions")
    def list_partitions(source: str | None = None, date: str | None = None, limit: int = 1000, offset: int = 0):
        q = select(rm_partition_health)
        if source:
            q = q.where(rm_partition_health.c.source == source)
        if date:
            q = q.where(rm_partition_health.c.date == date)
        with rt.engine.connect() as conn:
            total = conn.execute(select(func.count()).select_from(q.subquery())).scalar()
            rows = conn.execute(q.order_by(rm_partition_health.c.partition_id).limit(limit).offset(offset)).all()
        return _page([_row(r) for r in rows], total)

    @app.get("/partitions/summary")
    def partitions_summary():
        t = rm_partition_health
        with rt.engine.connect() as conn:
            rows = conn.execute(select(t.c.source, func.count().label("partitions"), func.sum(t.c.rows).label("rows"),
                                       func.sum(t.c.bytes).label("bytes"), func.min(t.c.min_ts).label("min_ts"),
                                       func.max(t.c.max_ts).label("max_ts"),
                                       func.max(t.c.projected_at).label("projected_at"))
                                .group_by(t.c.source).order_by(t.c.source)).all()
        return _page([_row(r) for r in rows])

    @app.get("/partitions/{partition_id:path}/health")
    def partition_health(partition_id: str):
        with rt.engine.connect() as conn:
            r = conn.execute(select(rm_partition_health)
                             .where(rm_partition_health.c.partition_id == partition_id)).first()
        if r is None:
            raise HTTPException(404, f"partition {partition_id!r} not found")
        return _row(r)

    from engine.api.hunt_routes import build_router
    from engine.api.rule_routes import build_router as rule_router
    from engine.api.ti_routes import build_router as ti_router
    app.include_router(rule_router(rt))
    app.include_router(ti_router(rt))
    app.include_router(build_router(rt))
    return app

