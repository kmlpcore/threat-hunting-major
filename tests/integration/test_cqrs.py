"""M0 exit criterion: a no-op command produces an event and a projected read-model row."""
from fastapi.testclient import TestClient
from sqlalchemy import select

from engine.api.command_api import create_app as command_app
from engine.api.query_api import create_app as query_app
from engine.common.bus import EVENTS_STREAM
from engine.common.db import commands, outbox
from engine.cqrs import handlers
from engine.cqrs.commands import Ping


def test_ping_flows_through_command_api_outbox_bus_projection_query_api(runtime):
    cmd_api, q_api = TestClient(command_app(runtime)), TestClient(query_app(runtime))
    resp = cmd_api.post("/commands/Ping", json={"message": "hello"})
    assert resp.status_code == 202
    cid = resp.json()["command_id"]

    assert q_api.get(f"/commands/{cid}").status_code == 404     # not projected yet: eventual consistency
    runtime.drain()

    status = q_api.get(f"/commands/{cid}").json()
    assert status["status"] == "succeeded"
    pings = q_api.get("/pings").json()
    assert pings["items"][0]["message"] == "hello" and pings["projected_at"]
    with runtime.engine.connect() as conn:
        rows = conn.execute(select(outbox.c.event_type, outbox.c.published_at)).all()
    assert {r.event_type for r in rows} == {"PingRecorded", "CommandCompleted"}
    assert all(r.published_at for r in rows)
    assert runtime.bus.length(EVENTS_STREAM) == 2


def test_idempotency_key_deduplicates(runtime):
    a = runtime.submit(Ping(message="x", nonce="same"))
    b = runtime.submit(Ping(message="x", nonce="same"))
    assert b.duplicate and a.command_id == b.command_id


def test_unknown_command_and_bad_payload_rejected(runtime):
    api = TestClient(command_app(runtime))
    assert api.post("/commands/Nope", json={}).status_code == 404
    assert api.post("/commands/IngestBatch", json={"source": "x"}).status_code == 422


def test_projector_is_idempotent_on_redelivery(runtime):
    runtime.submit(Ping(message="once"))
    runtime.drain()
    projector = runtime.projector()
    # Simulate at-least-once redelivery of every event.
    for _, data in list(runtime.bus._streams[EVENTS_STREAM]):
        from engine.common.events import Envelope
        assert projector.apply(Envelope.model_validate(data)) is False


def test_failing_handler_retries_then_fails_and_is_projected(runtime, monkeypatch):
    def boom(cmd, ctx):
        raise RuntimeError("kaboom")
    monkeypatch.setitem(handlers.HANDLERS, "Ping", boom)
    cid = runtime.submit(Ping(message="x")).command_id
    writer = runtime.writer()
    with runtime.engine.begin() as conn:
        conn.execute(commands.update().values(max_attempts=2))
    for _ in range(2):
        with runtime.engine.begin() as conn:   # skip the backoff wait
            conn.execute(commands.update().where(commands.c.status == "queued").values(not_before=commands.c.submitted_at))
        writer.run_once()
    runtime.drain()
    status = TestClient(query_app(runtime)).get(f"/commands/{cid}").json()
    assert status["status"] == "failed" and "kaboom" in status["error"] and status["attempts"] == 2
