"""Cost benchmark (plan.md sections 11 and 13, milestone M9).

    Baseline = N x C_full                     every hunt rehydrates its whole time range
    Ours     = C_extract + sum(C_tier x n_tier) + n_T3 x C_restore

* C_full     full rehydration of a rule's range: every raw object of its sources restored from
             its storage tier, then scanned (priced with policies/pricing.yaml).
* C_extract  one-time cost of building the derived layers (summaries + index read every raw
             byte once, while it is still hot) plus their storage for the retention period.
* C_tier     the measured actual cost of each benchmark run.

Also: storage cost of the estate at modelled scale (derived layers vs raw on standard storage),
estimate accuracy before / after calibration (NFR10), restore ratio of IOC sweeps, retro-sweep
cost per indicator and feed-to-sighting latency.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import date, timezone
from statistics import median

from sqlalchemy import select

from engine.common.db import commands, partition_files, rule_runs, rules, stage_runs
from engine.cost import estimator as est
from engine.cost.calibrate import accuracy
from engine.rules.compiler import compile_sigma
from engine.rules.tier3 import raw_files

GB = 1024 ** 3


def full_rehydration_cost(conn, store, run) -> dict:
    """Price restoring + scanning every raw object of the run's sources in its range."""
    rule = compile_sigma(conn.execute(select(rules.c.yaml).where(rules.c.rule_id == run.rule_id)).scalar())
    files = raw_files(conn, rule.sources, run.range_start, run.range_end)
    restored, objects = defaultdict(int), defaultdict(int)
    today = est.utc_today()
    for f in files:
        tier = est.tier_for_class(store.storage_class(f.file)) if store.is_s3 else est.tier_for_age(f.day, today)
        restored[tier] += f.bytes
        objects[tier] += 1
    q = est.Quantities(tier=3, scanned_bytes=sum(f.bytes for f in files), restored=dict(restored),
                       restored_objects=dict(objects))
    c = est.cost([q], apply_calibration=False)
    return {"bytes": sum(f.bytes for f in files), "cost": c["total"], "restore_time_s": c["estimated_restore_time_s"]}


def extract_cost(conn, derived_bytes: int, months: int) -> dict:
    """Build cost of the derived layers (one compute pass over raw per stage) + storage over `months`."""
    raw_bytes = sum(r.bytes for r in conn.execute(select(partition_files.c.bytes)))
    builds = conn.execute(select(stage_runs.c.stage)).all()
    passes = max(1, len({b.stage for b in builds} & {"summary", "index"}))
    build = est.cost([est.Quantities(tier=1, scanned_bytes=raw_bytes * passes)], apply_calibration=False)["total"]
    p = est.pricing()
    gb = derived_bytes * est.scale() / GB
    storage = gb * p["storage_tiers"]["infrequent_access"]["storage"] * months
    return {"build": round(build, 4), "storage_per_month": round(gb * p["storage_tiers"]["infrequent_access"]["storage"], 4),
            "storage_period": round(storage, 4), "total": round(build + storage, 4), "months": months}


def storage_model(raw_bytes: int, derived_bytes: int) -> dict:
    """Monthly storage at modelled scale: this design vs keeping raw on standard storage."""
    p, s = est.pricing(), est.scale()
    t = p["storage_tiers"]
    raw_gb, derived_gb = raw_bytes * s / GB, derived_bytes * s / GB
    ours = raw_gb * t["deep_archive"]["storage"] + derived_gb * t["infrequent_access"]["storage"]
    baseline = raw_gb * t["hot"]["storage"]
    return {"modelled_raw_tb": round(raw_gb / 1024, 3), "modelled_derived_tb": round(derived_gb / 1024, 3),
            "ours_per_month": round(ours, 2), "raw_on_standard_per_month": round(baseline, 2),
            "saving_pct": round(100 * (1 - ours / baseline), 1) if baseline else None}


def feed_metrics(conn) -> dict:
    sweeps = conn.execute(select(rule_runs).where(rule_runs.c.origin == "feed_sweep",
                                                  rule_runs.c.status == "succeeded")).all()
    per_indicator = []
    for r in sweeps:
        n = len((r.context or {}).get("indicator_ids") or [])
        if n:
            per_indicator.append((r.actual_cost or 0) / n)
    cmds = {(c.command_type, (c.payload or {}).get("run_id")): c for c in conn.execute(
        select(commands).where(commands.c.command_type.in_(("RecordFeedSightings",)))).all()}
    latencies = []
    for r in sweeps:
        sight = cmds.get(("RecordFeedSightings", r.run_id))
        if sight and sight.finished_at and r.created_at:
            latencies.append((est_utc(sight.finished_at) - est_utc(r.created_at)).total_seconds())
    ratios = [r.bytes_restored / r.plan["full_rehydration_bytes"] for r in sweeps
              if r.plan.get("full_rehydration_bytes")]
    return {"sweeps": len(sweeps),
            "retro_sweep_cost_per_indicator": round(median(per_indicator), 6) if per_indicator else None,
            "feed_to_sighting_latency_s": {"median": round(median(latencies), 1), "max": round(max(latencies), 1)}
            if latencies else None,
            "sweep_restore_ratio_max": round(max(ratios), 6) if ratios else None}


def est_utc(d):
    return d if d.tzinfo else d.replace(tzinfo=timezone.utc)


def run(conn, store, run_ids: list[str], derived_bytes: int, retention_years: int = 15) -> dict:
    runs = conn.execute(select(rule_runs).where(rule_runs.c.run_id.in_(run_ids),
                                                rule_runs.c.status == "succeeded")).all()
    per_run, c_full, c_ours, by_tier = [], [], [], defaultdict(list)
    for r in runs:
        full = full_rehydration_cost(conn, store, r)
        tier = max(r.plan["tiers"])
        by_tier[tier].append(r.actual_cost or 0)
        c_full.append(full["cost"])
        c_ours.append(r.actual_cost or 0)
        per_run.append({"run_id": r.run_id, "rule_id": r.rule_id, "tier": tier, "actual_cost": r.actual_cost,
                        "estimated_cost": r.estimated_cost, "full_rehydration_cost": full["cost"],
                        "full_rehydration_bytes": full["bytes"], "bytes_restored": r.bytes_restored,
                        "restore_ratio": round((r.bytes_restored or 0) / full["bytes"], 6) if full["bytes"] else None,
                        "full_restore_wait_h": round(full["restore_time_s"] / 3600, 1)})
    raw_bytes = sum(x.bytes for x in conn.execute(select(partition_files.c.bytes)))
    extract = extract_cost(conn, derived_bytes, months=12 * retention_years)
    mean_full = sum(c_full) / len(c_full) if c_full else 0.0
    mean_ours = sum(c_ours) / len(c_ours) if c_ours else 0.0
    break_even = extract["total"] / (mean_full - mean_ours) if mean_full > mean_ours else None
    # Derived storage is a yearly cost; restores scale with the hunted range (plan.md 13.3 uses 5 years).
    yearly = extract["storage_per_month"] * 12
    per_year = yearly / (mean_full - mean_ours) if mean_full > mean_ours else None
    days = max(1, median([(r.range_end - r.range_start).days for r in runs])) if runs else 1
    k = 5 * 365.25 / days
    full5, ours5 = mean_full * k, mean_ours * k
    five = {"range_days": round(5 * 365.25), "baseline_per_hunt": round(full5, 2), "ours_per_hunt": round(ours5, 2),
            "break_even_hunts_per_year": round(yearly / (full5 - ours5), 2) if full5 > ours5 else None,
            "for_n_hunts": {str(n): {"baseline": round(n * full5, 2), "ours": round(yearly + n * ours5, 2)}
                            for n in (1, 10, 50, 100)}}
    ioc = [x["restore_ratio"] for x in per_run if x["tier"] == 3 and x["restore_ratio"] is not None
           and x["restore_ratio"] < 0.5]
    return {
        "currency": est.pricing()["currency"], "pricing_version": est.pricing()["version"],
        "scale_factor": est.scale(), "runs": len(runs),
        "mean_cost_per_hunt": {"baseline_full_rehydration": round(mean_full, 4), "ours": round(mean_ours, 4)},
        "mean_actual_cost_by_tier": {str(t): round(sum(v) / len(v), 6) for t, v in sorted(by_tier.items())},
        "extract": extract,
        "break_even_hunts": round(break_even, 2) if break_even is not None else None,
        "break_even_hunts_per_year": round(per_year, 2) if per_year is not None else None,
        "five_year": five,
        "for_n_hunts": {str(n): {"baseline": round(n * mean_full, 2), "ours": round(extract["total"] + n * mean_ours, 2)}
                        for n in (1, 10, 50, 100)},
        "ioc_sweep_restore_ratio_max": round(max(ioc), 6) if ioc else None,
        "storage": storage_model(raw_bytes, derived_bytes),
        "estimate_accuracy": accuracy(conn),
        "feeds": feed_metrics(conn),
        "per_run": per_run,
        "as_of": date.today().isoformat(),
    }
