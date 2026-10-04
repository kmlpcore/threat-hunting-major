"""Command API (write side). Accepts commands and queues them; never returns read data.

    POST /commands/{command_type}   body = command payload, optional Idempotency-Key header
    → 202 {command_id, status, duplicate}; poll the query API for the outcome.
"""
from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException
from pydantic import ValidationError
from sqlalchemy import text

from engine.common.config import Settings
from engine.cqrs.commands import COMMAND_TYPES
from engine.cqrs.runtime import Runtime
from engine.cqrs.writer_queue import submit


def create_app(runtime: Runtime | None = None) -> FastAPI:
    rt = runtime or Runtime.from_settings(Settings.from_env())
    app = FastAPI(title="Threat Hunting Engine — Command API", version="0.4.0")

    @app.get("/health")
    def health():
        with rt.engine.connect() as conn:
            conn.execute(text("SELECT 1"))
        return {"status": "ok", "commands": sorted(COMMAND_TYPES)}

    @app.post("/commands/{command_type}", status_code=202)
    def post_command(command_type: str, body: dict | None = None,
                     idempotency_key: str | None = Header(default=None),
                     x_submitted_by: str | None = Header(default=None)):
        cls = COMMAND_TYPES.get(command_type)
        if cls is None:
            raise HTTPException(404, f"unknown command type {command_type!r}; known: {sorted(COMMAND_TYPES)}")
        try:
            command = cls.model_validate(body or {})
        except ValidationError as exc:
            raise HTTPException(422, exc.errors(include_url=False)) from exc
        result = submit(rt.engine, command, submitted_by=x_submitted_by or "api", idempotency_key=idempotency_key,
                        max_attempts=rt.settings.writer_max_attempts)
        return {"command_id": result.command_id, "command_type": command_type, "queue": cls.queue,
                "status": result.status, "duplicate": result.duplicate}

    return app

