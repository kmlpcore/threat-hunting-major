"""Estimator calibration (plan.md section 13.1, NFR10).

After every run the estimate is compared with what the run actually touched. Per tier the
calibrator keeps the median ratio actual/estimated for restored and scanned bytes over the
most recent runs, and the estimator multiplies future quantities by it. It also records the
observed prototype throughput for reporting.

In the prototype, `actual_cost` prices the *measured* quantities with the same price table
(there is no cloud bill to read). In production the same comparison runs against billing
exports, which is what `pricing_version` on every run is for.
"""
from __future__ import annotations

from statistics import median

from sqlalchemy import select
from sqlalchemy.engine import Connection

from engine.common.db import cost_calibration, rule_runs, utcnow

WINDOW = 50


def _ratios(runs) -> dict[int, dict[str, list[float]]]:
    out: dict[int, dict[str, list[float]]] = {}
    for r in runs:
        est_q = (r.plan or {}).get("quantities") or []
        act_q = ((r.actual or {}).get("quantities")) or []
        for e, a in zip(est_q, act_q):
            tier = int(e["tier"])
            d = out.setdefault(tier, {"restore": [], "scan": [], "tput": [], "err": []})
            er, ar = sum(e.get("restored", {}).values()), sum(a.get("restored", {}).values())
            if er and ar:
                d["restore"].append(ar / er)
            if e.get("scanned_bytes") and a.get("scanned_bytes"):
                d["scan"].append(a["scanned_bytes"] / e["scanned_bytes"])
            if r.duration_ms and (a.get("scanned_bytes") or ar):
                d["tput"].append((a.get("scanned_bytes", 0) + ar) / max(r.duration_ms / 1000, 1e-3))
        if r.actual_cost:
            for e in est_q[:1]:
                out.setdefault(int(e["tier"]), {"restore": [], "scan": [], "tput": [], "err": []})["err"].append(
                    abs(r.estimated_cost - r.actual_cost) / r.actual_cost)
    return out


def recalibrate(conn: Connection) -> list[dict]:
    runs = conn.execute(select(rule_runs).where(rule_runs.c.status == "succeeded", rule_runs.c.replay_of.is_(None))
                        .order_by(rule_runs.c.finished_at.desc()).limit(WINDOW)).all()
    rows = []
    for tier, d in sorted(_ratios(runs).items()):
        if not (d["restore"] or d["scan"]):
            continue
        row = {"tier": tier, "restore_ratio": median(d["restore"]) if d["restore"] else 1.0,
               "scan_ratio": median(d["scan"]) if d["scan"] else 1.0,
               "throughput_bytes_per_s": median(d["tput"]) if d["tput"] else None,
               "samples": max(len(d["restore"]), len(d["scan"])),
               "mean_abs_error_before": (sum(d["err"]) / len(d["err"])) if d["err"] else None,
               "computed_at": utcnow()}
        conn.execute(cost_calibration.insert().values(**row))
        rows.append(row)
    return rows


def accuracy(conn: Connection) -> dict:
    """|estimated - actual| / actual per run, split into runs estimated before / after calibration."""
    runs = conn.execute(select(rule_runs).where(rule_runs.c.status == "succeeded",
                                                rule_runs.c.actual_cost.is_not(None))).all()
    before, after = [], []
    for r in runs:
        if not r.actual_cost:
            continue
        err = abs(r.estimated_cost - r.actual_cost) / r.actual_cost
        (after if (r.plan or {}).get("estimate", {}).get("calibrated") else before).append(err)

    def stats(xs):
        if not xs:
            return None
        xs = sorted(xs)
        return {"runs": len(xs), "mean": round(sum(xs) / len(xs), 4), "median": round(median(xs), 4),
                "within_25pct": round(sum(1 for x in xs if x <= 0.25) / len(xs), 4)}
    return {"uncalibrated": stats(before), "calibrated": stats(after)}
