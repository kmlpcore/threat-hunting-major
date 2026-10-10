"""Retention policy loader (policies/retention.yaml, plan.md section 12.1)."""
from __future__ import annotations

from functools import lru_cache

import yaml

from engine.common.config import REPO_ROOT

POLICY_FILE = REPO_ROOT / "policies" / "retention.yaml"
FLOOR_YEARS = 15                       # decision D15: nothing below this without a decision-log change


class RetentionPolicyError(ValueError):
    pass


@lru_cache
def load() -> dict:
    spec = yaml.safe_load(POLICY_FILE.read_text())
    validate(spec)
    return spec


def validate(spec: dict) -> None:
    minimum = int(spec.get("minimum_years", 0))
    if minimum < FLOOR_YEARS:
        raise RetentionPolicyError(f"minimum_years {minimum} is below the {FLOOR_YEARS}-year floor (decision D15)")
    for layer, cfg in (spec.get("layers") or {}).items():
        if int(cfg.get("years", 0)) < minimum:
            raise RetentionPolicyError(f"layer {layer}: {cfg.get('years')} years is below minimum_years {minimum}")
    for o in spec.get("overrides") or []:
        if int(o.get("years", 0)) < minimum:
            raise RetentionPolicyError(f"override {o}: overrides may only raise retention")


def minimum_years() -> int:
    return int(load()["minimum_years"])


def years_for(layer: str, tenant: str | None = None, source: str | None = None) -> int:
    spec = load()
    years = int((spec["layers"].get(layer) or {}).get("years", spec["minimum_years"]))
    for o in spec.get("overrides") or []:
        if o.get("layer") in (None, layer) and o.get("tenant") in (None, tenant) and o.get("source") in (None, source):
            years = max(years, int(o["years"]))
    return max(years, int(spec["minimum_years"]))
