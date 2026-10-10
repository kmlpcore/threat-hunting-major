"""Cost estimator (plan.md section 13.1).

    estimated_cost =   Σ restored_GB(tier) × retrieval_price(tier) + Σ restore_requests × request_price(tier)
                     + Σ scanned_GB × query_price(engine)            # 0 for self-hosted DuckDB
                     + compute_hours × compute_price
                     + temp_storage_GB × days × hot_storage_price    # restored copies
                     + llm_tokens × llm_price                        # enrichment only

All prices come from policies/pricing.yaml. Quantities are expressed at *modelled* scale
(prototype bytes × simulation.scale_factor) so that thresholds behave like a real estate.

Archive retrieval is priced per object: deep-archive tiers restore whole objects, so the
restore volume of a tier-3 step is the size of every object it touches, not the row groups
it finally reads. The planner gets those objects from the (hot) bloom filters and keyword
index, so estimating never touches the archive.
"""
from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from functools import lru_cache

import yaml
from sqlalchemy import select
from sqlalchemy.engine import Connection

from engine.common.config import REPO_ROOT
from engine.common.db import cost_calibration

GB = 1024 ** 3
OBJECT_SIZE = 128 * 1024 ** 2     # objects are compacted to >= 128 MB before archiving (plan.md 12.2)


@lru_cache
def pricing() -> dict:
    return yaml.safe_load((REPO_ROOT / "policies" / "pricing.yaml").read_text())


@lru_cache
def thresholds() -> dict:
    t = yaml.safe_load((REPO_ROOT / "policies" / "coverage_thresholds.yaml").read_text())
    t["max_restore_bytes"] = parse_bytes(t["max_restore_bytes"])
    return t


def parse_bytes(v) -> int:
    if isinstance(v, (int, float)):
        return int(v)
    m = re.fullmatch(r"\s*([\d.]+)\s*([KMGTP]?B?)\s*", str(v).upper())
    if not m:
        raise ValueError(f"bad byte size {v!r}")
    mult = {"": 1, "B": 1, "K": 1024, "KB": 1024, "M": 1024 ** 2, "MB": 1024 ** 2, "G": GB, "GB": GB,
            "T": 1024 ** 4, "TB": 1024 ** 4, "P": 1024 ** 5, "PB": 1024 ** 5}[m.group(2)]
    return int(float(m.group(1)) * mult)


def scale() -> float:
    return float(pricing().get("simulation", {}).get("scale_factor", 1))


def tier_for_age(day: str, today: date) -> str:
    age = (today - date.fromisoformat(day)).days
    for rule in pricing()["age_tiering"]:
        if age >= rule["min_days"]:
            return rule["tier"]
    return "hot"


def tier_for_class(storage_class: str | None) -> str:
    return pricing()["storage_class_map"].get(storage_class or "STANDARD", "hot")


@dataclass
class Calibration:
    restore_ratio: dict[int, float] = field(default_factory=dict)
    scan_ratio: dict[int, float] = field(default_factory=dict)

    @classmethod
    def load(cls, conn: Connection | None) -> "Calibration":
        cal = cls()
        if conn is None:
            return cal
        rows = conn.execute(select(cost_calibration).order_by(cost_calibration.c.id)).all()
        for r in rows:                       # latest row per tier wins
            cal.restore_ratio[r.tier] = r.restore_ratio
            cal.scan_ratio[r.tier] = r.scan_ratio
        return cal


@dataclass
class Quantities:
    """What a plan step will touch, in prototype bytes."""
    tier: int
    scanned_bytes: int = 0
    restored: dict[str, int] = field(default_factory=dict)      # storage tier -> object bytes
    restored_objects: dict[str, int] = field(default_factory=dict)
    llm_tokens: int = 0


def cost(quantities: list[Quantities], calibration: Calibration | None = None, apply_calibration: bool = True) -> dict:
    """Price a list of step quantities. Returns lines, total and the modelled volumes."""
    p, s = pricing(), scale()
    cal = calibration or Calibration()
    tiers = p["storage_tiers"]
    lines: list[dict] = []
    restored_gb_total, scanned_gb_total, compute_h, latency = 0.0, 0.0, 0.0, 0
    for qn in quantities:
        rr = cal.restore_ratio.get(qn.tier, 1.0) if apply_calibration else 1.0
        sr = cal.scan_ratio.get(qn.tier, 1.0) if apply_calibration else 1.0
        scanned_gb = qn.scanned_bytes * s * sr / GB
        scanned_gb_total += scanned_gb
        if scanned_gb:
            price = p["query_engines"]["duckdb"]["price_per_gb_scanned"]
            lines.append({"item": f"tier {qn.tier} scan", "quantity": round(scanned_gb, 3), "unit": "GB",
                          "unit_price": price, "cost": scanned_gb * price})
        step_gb = scanned_gb
        for tier_name, nbytes in qn.restored.items():
            gb = nbytes * s * rr / GB
            if not gb:
                continue
            t = tiers[tier_name]
            requests = max(qn.restored_objects.get(tier_name, 0), math.ceil(nbytes * s * rr / OBJECT_SIZE))
            lines.append({"item": f"restore from {tier_name}", "quantity": round(gb, 3), "unit": "GB",
                          "unit_price": t["retrieval"], "cost": gb * t["retrieval"]})
            lines.append({"item": f"restore requests ({tier_name})", "quantity": requests, "unit": "requests",
                          "unit_price": t["requests_per_1000"] / 1000,
                          "cost": requests * t["requests_per_1000"] / 1000})
            hot = tiers[p["temp_storage"]["tier"]]["storage"]
            days = p["temp_storage"]["days"]
            lines.append({"item": f"temporary hot copy ({tier_name})", "quantity": round(gb, 3), "unit": "GB",
                          "unit_price": hot * days / 30, "cost": gb * hot * days / 30})
            restored_gb_total += gb
            step_gb += gb
            latency = max(latency, int(t["latency_s"]))
        thr = float(p["compute"]["throughput_gb_per_hour"].get(qn.tier, p["compute"]["throughput_gb_per_hour"][3]))
        hours = step_gb / thr if thr else 0.0
        compute_h += hours
        if qn.llm_tokens:
            price = p["llm"]["price_per_1k_tokens"]
            lines.append({"item": "llm tokens", "quantity": qn.llm_tokens, "unit": "tokens",
                          "unit_price": price / 1000, "cost": qn.llm_tokens * price / 1000})
    if compute_h:
        price = p["compute"]["price_per_hour"]
        lines.append({"item": f"compute ({p['compute']['instance']})", "quantity": round(compute_h, 4),
                      "unit": "hours", "unit_price": price, "cost": compute_h * price})
    total = sum(x["cost"] for x in lines)
    for x in lines:
        x["cost"] = round(x["cost"], 6)
    return {"currency": p["currency"], "pricing_version": p["version"], "scale_factor": s,
            "total": round(total, 6), "lines": lines, "modelled_restored_gb": round(restored_gb_total, 3),
            "modelled_scanned_gb": round(scanned_gb_total, 3), "compute_hours": round(compute_h, 4),
            "estimated_restore_time_s": int(latency + compute_h * 3600), "calibrated": bool(
                apply_calibration and (cal.restore_ratio or cal.scan_ratio))}


def approval_level(estimate: dict, modelled_restore_bytes: int) -> tuple[str, list[str]]:
    t = thresholds()
    total = estimate["total"]
    if modelled_restore_bytes > t["max_restore_bytes"]:
        return "blocked", [f"modelled restore {modelled_restore_bytes / 1024 ** 4:.2f} TB exceeds the "
                           f"max_restore_bytes safety cap ({t['max_restore_bytes'] / 1024 ** 4:.0f} TB)"]
    if total <= t["auto_approve_cost"]:
        return "auto", [f"estimated {total:.2f} {t['currency']} <= auto_approve_cost {t['auto_approve_cost']}"]
    if total <= t["manager_approve_cost"]:
        return "hunter", [f"estimated {total:.2f} {t['currency']} > auto_approve_cost {t['auto_approve_cost']}: "
                          "hunter approval required"]
    return "manager", [f"estimated {total:.2f} {t['currency']} > manager_approve_cost "
                       f"{t['manager_approve_cost']}: hunter + manager approval required"]


def approvals_satisfied(level: str, approvals: list[dict]) -> bool:
    approvers = {a["approver"] for a in approvals}
    roles = {a["role"] for a in approvals}
    if level == "auto":
        return True
    if level == "hunter":
        return bool(approvers)
    if level == "manager":
        return len(approvers) >= 2 and "manager" in roles
    return False


def utc_today() -> date:
    return datetime.now(timezone.utc).date()
