"""Rule service command handlers: SubmitRule → plan + estimate → (approval) → ExecuteRule.

    SubmitRule   compile, plan, estimate; record the run. Auto-approved runs are queued for
                 execution in the same transaction; others wait for ApproveRun. A replay reuses
                 the original plan and its pinned snapshots.
    ApproveRun   record an approval; once the approval policy is satisfied the run is queued.
    ExecuteRule  execute at pinned snapshots, write results.*, record actual cost and
                 re-calibrate the estimator.
"""
from __future__ import annotations

import copy
from datetime import datetime, timezone

from sqlalchemy import func, select

from engine.common.db import rule_runs, rules, upsert, utcnow
from engine.common.events import RestoreRequested, RuleEvaluated, RulePlanned, RuleSubmitted, RunApproved, RunQueued
from engine.cost import estimator as est
from engine.rules.compiler import compile_sigma
from engine.rules.planner import Planner, step_summary


def _utc(d: datetime) -> datetime:
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def spent_today(conn) -> float:
    start = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
    done = conn.execute(select(func.coalesce(func.sum(rule_runs.c.actual_cost), 0.0))
                        .where(rule_runs.c.finished_at >= start)).scalar() or 0.0
    pending = conn.execute(select(func.coalesce(func.sum(rule_runs.c.estimated_cost), 0.0))
                           .where(rule_runs.c.status.in_(("queued", "running")))).scalar() or 0.0
    return float(done) + float(pending)


def _queue_execute(ctx, run_id: str, reason: str):
    from engine.cqrs.commands import ExecuteRule
    from engine.cqrs.writer_queue import enqueue
    cid = enqueue(ctx.conn, ExecuteRule(run_id=run_id), submitted_by="rule-service")
    ctx.conn.execute(rule_runs.update().where(rule_runs.c.run_id == run_id)
                     .values(status="queued", execute_command_id=cid))
    return RunQueued(run_id=run_id, command_id=cid, reason=reason)


def release_deferred(cmd, ctx):
    """Queue budget-deferred feed sweeps (oldest first) while they fit today's budget."""
    from engine.cqrs.handlers import HandlerResult
    budget = est.thresholds()["daily_budget"]
    spent = spent_today(ctx.conn)
    events = []
    for run in ctx.conn.execute(select(rule_runs).where(rule_runs.c.status == "deferred_budget")
                                .order_by(rule_runs.c.created_at)).all():
        if spent + run.estimated_cost > budget:
            break
        spent += run.estimated_cost
        events.append(_queue_execute(ctx, run.run_id, f"released from budget deferral on {cmd.day}"))
    return HandlerResult(events=events, detail={"released": len(events), "spent_today": round(spent, 4)})


def submit_rule(cmd, ctx):
    from engine.cqrs.handlers import HandlerResult
    rule = compile_sigma(cmd.rule_yaml, origin=cmd.origin)
    start, end = _utc(cmd.start), _utc(cmd.end)
    context = dict(cmd.context or {})
    if cmd.replay_of:
        old = ctx.conn.execute(select(rule_runs).where(rule_runs.c.run_id == cmd.replay_of)).first()
        if old is None or old.status != "succeeded":
            raise ValueError(f"cannot replay {cmd.replay_of}: no succeeded run with that id")
        plan = copy.deepcopy(old.plan)
        start, end = _utc(old.range_start), _utc(old.range_end)
        context["pinned_snapshots"] = {k: v for k, v in (old.snapshot_ids or {}).items() if k != "raw"}
        plan["replay_of"] = cmd.replay_of
    else:
        plan = Planner(ctx.conn, ctx.store, ctx.settings).plan(rule, start, end)
    level, reasons = plan["approval"]["level"], list(plan["approval"]["reasons"])
    estimate = plan["estimate"]

    now = utcnow()
    upsert(ctx.conn, rules, {"rule_id": rule.rule_id}, {
        "version_hash": rule.version_hash, "title": rule.title, "level": rule.level, "origin": rule.origin,
        "tags": rule.tags, "compiled": rule.to_dict(), "yaml": cmd.rule_yaml, "submitted_at": now, "updated_at": now})

    status = "planned" if cmd.dry_run else {"blocked": "blocked", "auto": "approved"}.get(level, "awaiting_approval")
    if status == "approved" and cmd.origin == "feed_sweep":
        budget = est.thresholds()["daily_budget"]
        if spent_today(ctx.conn) + estimate["total"] > budget:
            status = "deferred_budget"
            reasons.append(f"daily budget {budget} {estimate['currency']} reached: deferred to the next day")
    ctx.conn.execute(rule_runs.insert().values(
        run_id=cmd.run_id, rule_id=rule.rule_id, rule_version_hash=rule.version_hash, origin=cmd.origin,
        status=status, range_start=start, range_end=end, plan=plan, approval_level=level, approvals=[],
        context=context, estimated_cost=estimate["total"], cost_currency=estimate["currency"],
        pricing_version=estimate["pricing_version"], replay_of=cmd.replay_of, submitted_by=cmd.submitted_by,
        created_at=now))
    events = [
        RuleSubmitted(run_id=cmd.run_id, rule_id=rule.rule_id, rule_version_hash=rule.version_hash, title=rule.title,
                      level=rule.level, origin=cmd.origin, kind=rule.kind, tags=rule.tags,
                      techniques=rule.techniques, sources=rule.sources, range_start=start, range_end=end,
                      dry_run=cmd.dry_run, replay_of=cmd.replay_of, submitted_by=cmd.submitted_by),
        RulePlanned(run_id=cmd.run_id, rule_id=rule.rule_id, status=status, tiers=plan["tiers"],
                    coverage_pct=plan["coverage_pct"], steps=[step_summary(s) for s in plan["steps"]],
                    estimate=estimate, approval_level=level, approval_reasons=reasons),
    ]
    if status == "approved":
        events.append(_queue_execute(ctx, cmd.run_id, "auto-approved"))
    return HandlerResult(events=events, detail={"run_id": cmd.run_id, "rule_id": rule.rule_id, "status": status,
                                                "tiers": plan["tiers"], "estimated_cost": estimate["total"],
                                                "approval_level": level})


def approve_run(cmd, ctx):
    from engine.cqrs.handlers import HandlerResult
    run = ctx.conn.execute(select(rule_runs).where(rule_runs.c.run_id == cmd.run_id)).first()
    if run is None:
        raise ValueError(f"unknown run {cmd.run_id}")
    if run.approval_level == "blocked":
        raise ValueError("run is blocked by the max_restore_bytes safety cap; approval cannot override it")
    if cmd.role not in ("hunter", "manager"):
        raise ValueError("role must be hunter or manager")
    approvals = [a for a in (run.approvals or []) if a["approver"] != cmd.approver]
    approvals.append({"approver": cmd.approver, "role": cmd.role, "at": utcnow().isoformat()})
    ctx.conn.execute(rule_runs.update().where(rule_runs.c.run_id == cmd.run_id).values(approvals=approvals))
    satisfied = est.approvals_satisfied(run.approval_level, approvals)
    events = [RunApproved(run_id=cmd.run_id, approver=cmd.approver, role=cmd.role, approvals=approvals,
                          satisfied=satisfied)]
    if satisfied and run.status == "awaiting_approval":
        events.append(_queue_execute(ctx, cmd.run_id, f"approved by {', '.join(a['approver'] for a in approvals)}"))
    return HandlerResult(events=events, detail={"run_id": cmd.run_id, "satisfied": satisfied})


def execute_rule(cmd, ctx):
    from engine.cost.calibrate import recalibrate
    from engine.cqrs.handlers import HandlerResult
    from engine.rules.executor import Executor
    run = ctx.conn.execute(select(rule_runs).where(rule_runs.c.run_id == cmd.run_id)).first()
    if run is None:
        raise ValueError(f"unknown run {cmd.run_id}")
    if run.status == "succeeded":
        return HandlerResult(detail={"run_id": run.run_id, "status": "succeeded", "note": "already executed"})
    if run.approval_level == "blocked":
        raise ValueError("run is blocked by the max_restore_bytes safety cap")
    if not est.approvals_satisfied(run.approval_level, run.approvals or []):
        raise ValueError(f"run needs {run.approval_level} approval before it can execute")
    rule_yaml = ctx.conn.execute(select(rules.c.yaml).where(rules.c.rule_id == run.rule_id)).scalar()
    started = utcnow()
    res = Executor(ctx.conn, ctx.store, ctx.settings).execute(run, rule_yaml)
    actual = res["actual"]
    ctx.conn.execute(rule_runs.update().where(rule_runs.c.run_id == run.run_id).values(
        status="succeeded", tiers_used=run.plan["tiers"], coverage_pct=run.plan["coverage_pct"],
        snapshot_ids=res["pinned"], bytes_scanned=res["bytes_scanned"], bytes_restored=res["bytes_restored"],
        files_restored=res["files_restored"], actual_cost=actual["total"], hits=len(res["hits"]),
        hits_hash=res["hits_hash"], duration_ms=res["duration_ms"], started_at=started, finished_at=utcnow(),
        actual={"quantities": [q.__dict__ for q in res["quantities"]], "cost": actual,
                "bytes_read": res["bytes_read"]}, error=None))
    recalibrate(ctx.conn)
    events = []
    if res["files_restored"]:
        tiers: dict[str, int] = {}
        for q in res["quantities"]:
            for t, b in q.restored.items():
                tiers[t] = tiers.get(t, 0) + b
        events.append(RestoreRequested(run_id=run.run_id, files=res["files_restored"], bytes=res["bytes_restored"],
                                       modelled_bytes=int(res["bytes_restored"] * est.scale()), storage_tiers=tiers))
    rule = res["rule"]
    events.append(RuleEvaluated(
        run_id=run.run_id, rule_id=run.rule_id, origin=run.origin, status="succeeded", tiers_used=run.plan["tiers"],
        coverage_pct=run.plan["coverage_pct"], hits=len(res["hits"]), entities=res["entities"],
        bytes_scanned=res["bytes_scanned"], bytes_restored=res["bytes_restored"],
        files_restored=res["files_restored"], full_rehydration_bytes=run.plan["full_rehydration_bytes"],
        estimated_cost=run.estimated_cost, actual_cost=actual["total"], currency=actual["currency"],
        pricing_version=actual["pricing_version"], snapshot_ids=res["pinned"], duration_ms=res["duration_ms"],
        hits_hash=res["hits_hash"], techniques=rule.techniques, replay_of=run.replay_of))
    from engine.ti.service import after_rule_run
    events.extend(after_rule_run(ctx, run, res))
    return HandlerResult(events=events, detail={"run_id": run.run_id, "hits": len(res["hits"]),
                                                "actual_cost": actual["total"], "hits_hash": res["hits_hash"]})


