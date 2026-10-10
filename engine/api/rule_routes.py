"""Query-side endpoints for M5: rules, runs, hits, estimates and costs (plan.md section 4.4).

Run status and costs come from read models (eventually consistent, `projected_at` on every
row). Hits are read from results.rule_hits as a snapshot-pinned Iceberg scan; the snapshot id
read is returned so the response itself is reproducible.
"""
from __future__ import annotations

from datetime import datetime
from statistics import median

from fastapi import APIRouter, HTTPException, Query
from pyiceberg.expressions import EqualTo
from sqlalchemy import select

from engine.common.catalog import get_catalog, read_table
from engine.common.config import REPO_ROOT
from engine.common.db import as_utc, rm_command_status, rm_rule_runs, rm_rules


def _row(r) -> dict:
    return {k: as_utc(v) if isinstance(v, datetime) else v for k, v in dict(r._mapping).items()}


def build_router(rt) -> APIRouter:
    r = APIRouter()

    @r.get("/rules")
    def list_rules(origin: str | None = None, limit: int = Query(200, le=2000)):
        q = select(rm_rules).order_by(rm_rules.c.updated_at.desc()).limit(limit)
        if origin:
            q = q.where(rm_rules.c.origin == origin)
        with rt.engine.connect() as conn:
            rows = [_row(x) for x in conn.execute(q)]
        return {"items": rows, "projected_at": max((x["projected_at"] for x in rows), default=None)}

    @r.get("/rules/corpus")
    def corpus():
        """The benchmark Sigma corpus shipped in rules/sigma/ (handy for the dashboard)."""
        out = []
        for p in sorted((REPO_ROOT / "rules" / "sigma").glob("*.yml")):
            out.append({"file": p.name, "yaml": p.read_text()})
        return {"items": out}

    @r.get("/runs")
    def list_runs(status: str | None = None, origin: str | None = None, limit: int = Query(100, le=2000)):
        q = select(rm_rule_runs).order_by(rm_rule_runs.c.submitted_at.desc()).limit(limit)
        if status:
            q = q.where(rm_rule_runs.c.status == status)
        if origin:
            q = q.where(rm_rule_runs.c.origin == origin)
        with rt.engine.connect() as conn:
            rows = [_row(x) for x in conn.execute(q)]
        return {"items": rows, "projected_at": max((x["projected_at"] for x in rows), default=None)}

    @r.get("/rules/{rule_id}")
    def get_rule(rule_id: str):
        with rt.engine.connect() as conn:
            rule = conn.execute(select(rm_rules).where(rm_rules.c.rule_id == rule_id)).first()
            runs = conn.execute(select(rm_rule_runs).where(rm_rule_runs.c.rule_id == rule_id)
                                .order_by(rm_rule_runs.c.submitted_at.desc())).all()
        if rule is None:
            raise HTTPException(404, "rule not found (or not projected yet)")
        return {**_row(rule), "run_history": [_row(x) for x in runs]}

    def _run(rule_id: str, run_id: str):
        with rt.engine.connect() as conn:
            run = conn.execute(select(rm_rule_runs).where(rm_rule_runs.c.run_id == run_id,
                                                          rm_rule_runs.c.rule_id == rule_id)).first()
            cmd = None
            if run is not None and run.execute_command_id:
                cmd = conn.execute(select(rm_command_status).where(
                    rm_command_status.c.command_id == run.execute_command_id)).first()
        if run is None:
            raise HTTPException(404, "run not found (or not projected yet)")
        out = _row(run)
        if cmd is not None:
            out["execute_command"] = {"status": cmd.status, "attempts": cmd.attempts, "error": cmd.error}
            if cmd.status == "failed" and out["status"] in ("queued", "running"):
                out["status"] = "failed"
        return out

    @r.get("/rules/{rule_id}/runs/{run_id}")
    def get_run(rule_id: str, run_id: str):
        return _run(rule_id, run_id)

    @r.get("/rules/{rule_id}/runs/{run_id}/estimate")
    def get_estimate(rule_id: str, run_id: str):
        run = _run(rule_id, run_id)
        return {k: run.get(k) for k in ("run_id", "status", "tiers", "coverage_pct", "steps", "estimate",
                                        "approval_level", "approvals", "estimated_cost", "cost_currency",
                                        "pricing_version", "projected_at")}

    @r.get("/rules/{rule_id}/runs/{run_id}/hits")
    def get_hits(rule_id: str, run_id: str, limit: int = Query(500, le=20000), snapshot_id: int | None = None):
        table, snap = read_table(get_catalog(rt.settings), "results.rule_hits", row_filter=EqualTo("run_id", run_id),
                                 snapshot_id=snapshot_id)
        rows = table.to_pylist() if table.num_rows else []
        rows.sort(key=lambda x: (x.get("ts") is None, x.get("ts")))
        return {"run_id": run_id, "rule_id": rule_id, "snapshot_id": snap, "count": len(rows),
                "entities": len({x["entity_key"] for x in rows}),
                "items": [{k: as_utc(v) if isinstance(v, datetime) else v for k, v in x.items()} for x in rows[:limit]]}

    @r.get("/costs")
    def costs(start: str | None = None, end: str | None = None):
        """Estimated vs actual cost per run, totals, and estimate accuracy (NFR10)."""
        q = select(rm_rule_runs).where(rm_rule_runs.c.status == "succeeded").order_by(rm_rule_runs.c.finished_at)
        if start:
            q = q.where(rm_rule_runs.c.finished_at >= datetime.fromisoformat(start))
        if end:
            q = q.where(rm_rule_runs.c.finished_at <= datetime.fromisoformat(end))
        with rt.engine.connect() as conn:
            rows = [_row(x) for x in conn.execute(q)]
        errs = [abs(x["estimated_cost"] - x["actual_cost"]) / x["actual_cost"]
                for x in rows if x.get("actual_cost")]
        by_origin: dict[str, dict] = {}
        for x in rows:
            o = by_origin.setdefault(x["origin"] or "?", {"runs": 0, "estimated": 0.0, "actual": 0.0})
            o["runs"] += 1
            o["estimated"] += x["estimated_cost"] or 0
            o["actual"] += x["actual_cost"] or 0
        return {"runs": len(rows), "currency": rows[0]["cost_currency"] if rows else None,
                "estimated_total": round(sum(x["estimated_cost"] or 0 for x in rows), 4),
                "actual_total": round(sum(x["actual_cost"] or 0 for x in rows), 4),
                "by_origin": by_origin,
                "estimate_error": {"median": round(median(errs), 4) if errs else None,
                                   "within_25pct": round(sum(e <= 0.25 for e in errs) / len(errs), 4) if errs else None},
                "items": [{k: x.get(k) for k in ("run_id", "rule_id", "title", "origin", "tiers", "estimated_cost",
                                                 "actual_cost", "bytes_restored", "files_restored", "finished_at")}
                          for x in rows]}

    return r
