"""Engine CLI.

    python -m engine.cli generate --run-id demo --start 2026-09-07 --days 7 --users 40
    python -m engine.cli ingest   --run-id demo           # via the command API (compose)
    python -m engine.cli ping                             # M0 round trip: command → event → read model
    python -m engine.cli ecs-check                        # re-validate every landed raw row
    python -m engine.cli demo --local                     # everything in-process (SQLite + memory bus)

`--local` runs the writer, outbox relay and projector in this process instead of
talking to the services, so the whole pipeline works without Docker.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import uuid
from collections import Counter, defaultdict
from datetime import date

from engine.common.config import Settings
from engine.common.storage import ObjectStore
from engine.cqrs.commands import Command, IngestBatch, LoadInventory, Ping

log = logging.getLogger("engine.cli")


# --------------------------------------------------------------------------- command clients
class LocalClient:
    def __init__(self, settings: Settings):
        from engine.cqrs.runtime import Runtime
        self.rt = Runtime.from_settings(settings, create_tables=True)

    def submit(self, cmd: Command) -> str:
        return self.rt.submit(cmd).command_id

    def wait(self, command_ids: list[str], timeout_s: float = 3600) -> dict[str, dict]:
        self.rt.drain()
        return {cid: self._status(cid) for cid in command_ids}

    def _status(self, cid: str) -> dict:
        from sqlalchemy import select
        from engine.common.db import rm_command_status
        with self.rt.engine.connect() as conn:
            r = conn.execute(select(rm_command_status).where(rm_command_status.c.command_id == cid)).first()
        return dict(r._mapping) if r else {"status": "unknown"}

    def query(self, path: str) -> dict:
        import warnings
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            from fastapi.testclient import TestClient
        from engine.api.query_api import create_app
        return TestClient(create_app(self.rt)).get(path).json()


class HttpClient:
    def __init__(self, command_url: str, query_url: str):
        import httpx
        self.cmd = httpx.Client(base_url=command_url, timeout=30)
        self.q = httpx.Client(base_url=query_url, timeout=30)

    def submit(self, cmd: Command) -> str:
        r = self.cmd.post(f"/commands/{cmd.command_type}", json=cmd.model_dump(mode="json"),
                          headers={"X-Submitted-By": "cli"})
        r.raise_for_status()
        return r.json()["command_id"]

    def wait(self, command_ids: list[str], timeout_s: float = 3600) -> dict[str, dict]:
        pending, done = set(command_ids), {}
        deadline = time.monotonic() + timeout_s
        while pending and time.monotonic() < deadline:
            for cid in list(pending):
                r = self.q.get(f"/commands/{cid}")
                if r.status_code == 200 and r.json()["status"] in ("succeeded", "failed"):
                    done[cid] = r.json()
                    pending.discard(cid)
            if pending:
                time.sleep(1)
        for cid in pending:
            done[cid] = {"status": "timeout"}
        return done

    def query(self, path: str) -> dict:
        return self.q.get(path).json()


def make_client(args, settings: Settings):
    if args.local:
        return LocalClient(settings)
    return HttpClient(os.environ.get("COMMAND_API_URL", "http://localhost:8000"),
                      os.environ.get("QUERY_API_URL", "http://localhost:8001"))


# --------------------------------------------------------------------------- commands
def cmd_generate(args, settings: Settings) -> dict:
    from engine.generator.run import generate
    store = ObjectStore.from_settings(settings)
    return generate(settings, store, run_id=args.run_id, start=date.fromisoformat(args.start), days=args.days,
                    users=args.users, seed=args.seed)


def cmd_ingest(args, settings: Settings, client=None) -> dict:
    store = ObjectStore.from_settings(settings)
    manifest = store.get_json(f"{settings.buckets.incoming}/{args.run_id}/manifest.json")
    client = client or make_client(args, settings)
    inv = client.submit(LoadInventory(uri=manifest["inventory_uri"]))
    inv_status = client.wait([inv])[inv]
    if inv_status["status"] != "succeeded":
        raise SystemExit(f"LoadInventory failed: {inv_status}")
    ids = [client.submit(IngestBatch(batch_id=b["batch_id"], batch_uri=b["uri"], source=b["source"]))
           for b in manifest["batches"]]
    statuses = client.wait(ids)
    outcome = Counter(s["status"] for s in statuses.values())
    failed = {cid: s for cid, s in statuses.items() if s["status"] != "succeeded"}
    return {"run_id": args.run_id, "batches": len(ids), "outcome": dict(outcome),
            "failed": failed, "partitions": client.query("/partitions/summary")}


def cmd_ping(args, settings: Settings, client=None) -> dict:
    client = client or make_client(args, settings)
    cid = client.submit(Ping(message=args.message, nonce=str(uuid.uuid4())))
    status = client.wait([cid], timeout_s=60)[cid]
    pings = client.query("/pings")
    row = next((p for p in pings["items"] if p["command_id"] == cid), None)
    return {"command_id": cid, "command_status": status.get("status"), "read_model_row": row}


def cmd_ecs_check(args, settings: Settings) -> dict:
    """Independent re-validation of everything under raw/ (M1 exit criterion)."""
    from engine.normaliser import ecs
    store = ObjectStore.from_settings(settings)
    totals: dict[str, Counter] = defaultdict(Counter)
    examples: list[dict] = []
    files = store.list(settings.buckets.raw, suffix=".parquet")
    expected = set(ecs.catalog().arrow_schema.names)
    for path in files:
        source = path.split("source=", 1)[1].split("/", 1)[0]
        table = store.read_parquet(path)
        if set(table.schema.names) != expected:
            totals[source]["schema_mismatch_files"] += 1
        for row in table.to_pylist():
            row = {k: v for k, v in row.items() if v is not None and v != []}
            errors = ecs.validate(row)
            totals[source]["rows"] += 1
            totals[source]["valid" if not errors else "invalid"] += 1
            if errors and len(examples) < 5:
                examples.append({"file": path, "event.id": row.get("event.id"), "errors": errors})
    rows = sum(c["rows"] for c in totals.values())
    valid = sum(c["valid"] for c in totals.values())
    return {"files": len(files), "rows": rows, "valid": valid,
            "valid_pct": round(100.0 * valid / rows, 4) if rows else None,
            "by_source": {s: dict(c) for s, c in sorted(totals.items())}, "examples": examples}


def cmd_late_data(args, settings: Settings) -> dict:
    """Demo of the late-data path: land one more record into an already-sealed partition.
    The orchestrator rebuilds that day's summaries/index/features and re-seals it as v2."""
    import random
    from datetime import datetime, timezone
    from engine.cqrs.commands import IngestBatch
    from engine.generator.emitters import Sink
    store = ObjectStore.from_settings(settings)
    ts = datetime.fromisoformat(args.at).replace(tzinfo=timezone.utc)
    sink = Sink(rng=random.Random())
    sink.metric(ts, args.host, 97.5, 64.0, 1_000_000, 5_000_000, 600)
    batch_id = f"late-{ts:%Y%m%d%H%M}-{uuid.uuid4().hex[:6]}"
    uri = f"{settings.buckets.incoming}/late/{batch_id}.jsonl.gz"
    store.put_jsonl_gz(uri, [e.record for e in sink.entries["host_metrics"]])
    client = make_client(args, settings)
    cid = client.submit(IngestBatch(batch_id=batch_id, batch_uri=uri, source="host_metrics"))
    status = client.wait([cid], timeout_s=120)[cid]
    pid = f"source=host_metrics/date={ts:%Y-%m-%d}/hour={ts:%H}"
    return {"batch_id": batch_id, "partition_id": pid, "ingest": status.get("status"),
            "next": "the orchestrator now rebuilds this day and re-seals the partition (seal_version 2); "
                    f"watch GET /partitions/{pid}/seal or the dashboard's Sealing page"}


def cmd_demo(args, settings: Settings) -> dict:
    client = make_client(args, settings)
    out = {"ping": cmd_ping(args, settings, client)}
    out["generate"] = {k: v for k, v in cmd_generate(args, settings).items() if k != "batches"}
    out["ingest"] = cmd_ingest(args, settings, client)
    out["ecs_check"] = cmd_ecs_check(args, settings)
    return out


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(prog="engine.cli")
    p.add_argument("--local", action="store_true", help="run writer/relay/projector in-process (no services)")
    sub = p.add_subparsers(dest="cmd", required=True)

    def gen_args(sp):
        sp.add_argument("--run-id", default="demo")
        sp.add_argument("--start", default="2026-09-07")
        sp.add_argument("--days", type=int, default=7)
        sp.add_argument("--users", type=int, default=40)
        sp.add_argument("--seed", type=int, default=42)

    gen_args(sub.add_parser("generate", help="generate synthetic logs + scenarios"))
    ing = sub.add_parser("ingest", help="submit LoadInventory + IngestBatch for a generated run")
    ing.add_argument("--run-id", default="demo")
    ping = sub.add_parser("ping", help="M0 no-op command round trip")
    ping.add_argument("--message", default="hello from cli")
    sub.add_parser("ecs-check", help="validate every landed raw row against ECS")
    late = sub.add_parser("late-data", help="land a late record into a sealed partition (reseal demo)")
    late.add_argument("--at", default="2026-09-09T10:42:00")
    late.add_argument("--host", default="APP01")
    demo = sub.add_parser("demo", help="ping + generate + ingest + ecs-check")
    gen_args(demo)
    demo.add_argument("--message", default="demo ping")

    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    settings = Settings.from_env()
    handlers = {"generate": cmd_generate, "ingest": cmd_ingest, "ping": cmd_ping, "ecs-check": cmd_ecs_check,
                "late-data": cmd_late_data,
                "demo": cmd_demo}
    result = handlers[args.cmd](args, settings)
    json.dump(result, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
