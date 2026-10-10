"""Command API (write side). Accepts commands and queues them; never returns read data.

    POST /commands/{command_type}   body = command payload, optional Idempotency-Key header
    → 202 {command_id, status, duplicate}; poll the query API for the outcome.
"""
from __future__ import annotations

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import ValidationError
from sqlalchemy import text

from engine.common.config import Settings
from engine.cqrs.commands import COMMAND_TYPES
from engine.cqrs.runtime import Runtime
from engine.cqrs.writer_queue import submit


def validate(command) -> list[str]:
    """Synchronous checks that must fail at submit time rather than in the writer.
    Sigma rules are compiled here: unknown fields or unsupported modifiers are reported now."""
    if command.command_type == "SubmitRule" and not command.replay_of:
        from engine.rules.compiler import CompileError, compile_sigma
        try:
            compile_sigma(command.rule_yaml, origin=command.origin)
        except CompileError as exc:
            return exc.problems
        if command.end <= command.start:
            return ["end must be after start"]
    return []


def create_app(runtime: Runtime | None = None) -> FastAPI:
    rt = runtime or Runtime.from_settings(Settings.from_env())
    app = FastAPI(title="Threat Hunting Engine — Command API", version="0.9.0")

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
        problems = validate(command)
        if problems:
            raise HTTPException(422, {"problems": problems})
        result = submit(rt.engine, command, submitted_by=x_submitted_by or "api", idempotency_key=idempotency_key,
                        max_attempts=rt.settings.writer_max_attempts)
        return {"command_id": result.command_id, "command_type": command_type, "queue": command.target_queue(),
                "status": result.status, "duplicate": result.duplicate}

    @app.post("/ti/push/{connector}", status_code=202)
    async def push_feed(connector: str, request: Request, x_submitted_by: str | None = Header(default=None)):
        """Push / streaming feeds (v3): store the batch, then queue PullFeed with it as the payload."""
        import uuid
        from engine.cqrs.commands import PullFeed
        from engine.ti.connectors.sdk import registry
        if connector not in registry():
            raise HTTPException(404, f"unknown connector {connector!r}")
        body = await request.body()
        if not body or len(body) > 50_000_000:
            raise HTTPException(413 if body else 422, "empty or oversized payload")
        slot = str(uuid.uuid4())
        uri = f"{rt.settings.buckets.incoming}/feeds/{connector}/{slot}.json"
        rt.store.put_bytes(uri, body)
        result = submit(rt.engine, PullFeed(connector=connector, payload_uri=uri, slot=slot),
                        submitted_by=x_submitted_by or f"push:{connector}", max_attempts=rt.settings.writer_max_attempts)
        return {"command_id": result.command_id, "payload_uri": uri, "status": result.status}

    return app

