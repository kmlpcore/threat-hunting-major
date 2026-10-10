"""Coverage planner (plan.md section 3.8).

For a compiled rule and a time range it lists every way the rule could be answered, prices
each with the cost estimator and picks the cheapest one that fully covers the range:

    tier 1  artefact dimension tables              (exact at entity x day)
    tier 2  summary.high_value_events              (exact, event level)
            summary dimension tables               (exact at entity x day / hour)
            summary aggregate capabilities         (correlations; sound over-approximation)
    tier 3  index-pruned selective restore of raw  (exact; bounded by bloom + keyword index)

Coverage is per day: a derived table only answers the days whose stage is current (same
input generation and policy / feature version). For single-event rules the uncovered days
become a tier-3 step and the plan reports the coverage %. Correlation windows can cross day
boundaries, so a correlation is answered from a summary only when every day is covered.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import date, datetime

from pyiceberg.expressions import And, EqualTo, In
from sqlalchemy.engine import Connection

from engine.common import stages
from engine.common.catalog import get_catalog
from engine.common.config import Settings
from engine.common.storage import ObjectStore
from engine.cost import estimator as est
from engine.features.definitions import load_definitions
from engine.rules.capabilities import (AGG_TABLE_SOURCE, DIMENSION_TABLES, Coverage, aggregate_plan,
                                       high_value_coverage)
from engine.rules.compiler import CompiledRule
from engine.rules.tier3 import Located, Locator, RawFile, raw_files
from engine.summary.policy import load_policy

PLANNER_VERSION = "1"
COST_TIE = 0.01


def summary_current_days(conn: Connection, source: str, day_gens: dict, runs: dict) -> set[str]:
    version = load_policy().version
    return {d for (s, d), g in day_gens.items()
            if s == source and stages.is_current(runs.get(("summary", f"{s}/{d}")), g, version)}


def feature_current_days(conn: Connection, feature_key: str, day_gens: dict, runs: dict) -> set[str]:
    d = load_definitions().get(feature_key)
    if d is None:
        return set()
    out = set()
    for (stage, scope), r in runs.items():
        if stage != "features" or not scope.startswith(feature_key + "/"):
            continue
        day = scope.split("/", 1)[1]
        if r.status != "succeeded" or r.version != d.definition_hash:
            continue
        gens = (r.detail or {}).get("source_generations") or {}
        if all(g is None or day_gens.get((s, day)) == g for s, g in gens.items()):
            out.add(day)
    return out


def table_scan(settings: Settings, table: str, days: list[str], filters: dict | None = None) -> tuple[int, int | None]:
    """(data-file bytes, current snapshot id) for the given days, from Iceberg metadata only."""
    from pyiceberg.exceptions import NoSuchTableError
    cat = get_catalog(settings)
    try:
        t = cat.load_table(table)
    except NoSuchTableError:
        return 0, None
    snap = t.current_snapshot()
    if snap is None or not days:
        return 0, snap.snapshot_id if snap else None
    filt = In("day", days)
    for k, v in (filters or {}).items():
        filt = And(filt, In(k, v) if isinstance(v, list) else EqualTo(k, v))
    files = t.scan(row_filter=filt, snapshot_id=snap.snapshot_id).plan_files()
    return sum(f.file.file_size_in_bytes for f in files), snap.snapshot_id


@dataclass
class Candidate:
    capability: str
    tier: int
    exact: bool
    steps: list[dict]
    quantities: list[est.Quantities]
    estimate: dict
    coverage_pct: float


class Planner:
    def __init__(self, conn: Connection, store: ObjectStore, settings: Settings, today: date | None = None):
        self.conn, self.store, self.settings = conn, store, settings
        self.today = today or est.utc_today()
        self.locator = Locator(None, store, settings)
        self.calibration = est.Calibration.load(conn)
        self._tiers: dict[str, str] = {}
        self.day_gens = stages.day_generations(conn)
        self.runs = stages.runs(conn)

    # ------------------------------------------------------------------ raw helpers
    def storage_tier(self, f: RawFile) -> str:
        if f.file not in self._tiers:
            if self.store.is_s3:
                try:
                    self._tiers[f.file] = est.tier_for_class(self.store.storage_class(f.file))
                except Exception:  # noqa: BLE001 - fall back to the age model
                    self._tiers[f.file] = est.tier_for_age(f.day, self.today)
            else:
                self._tiers[f.file] = est.tier_for_age(f.day, self.today)
        return self._tiers[f.file]

    def raw_step(self, rule: CompiledRule, files: list[RawFile]) -> tuple[dict, est.Quantities]:
        loc: Located = self.locator.locate(self.conn, files, rule.predicate)
        by_file = {f.file: f for f in files}
        targets, restored, objects = [], {}, {}
        for path, rgs in sorted(loc.targets.items()):
            f = by_file[path]
            tier = self.storage_tier(f)
            targets.append({"file": path, "partition_id": f.partition_id, "bytes": f.bytes, "storage_tier": tier,
                            "row_groups": sorted(rgs) if rgs is not None else None})
            restored[tier] = restored.get(tier, 0) + f.bytes
            objects[tier] = objects.get(tier, 0) + 1
        step = {"tier": 3, "kind": "raw", "capability": loc.mode, "exact": True, "granularity": "event",
                "sources": rule.sources, "days": sorted({f.day for f in files}),
                "targets": targets, "restore_bytes": sum(t["bytes"] for t in targets),
                "range_bytes": sum(f.bytes for f in files), "anchors": loc.anchors,
                "partitions_in_range": loc.partitions_in_range, "partitions_after_bloom": loc.partitions_after_bloom,
                "unindexed_days": loc.unindexed_days, "notes": loc.notes}
        return step, est.Quantities(tier=3, scanned_bytes=step["restore_bytes"], restored=restored,
                                    restored_objects=objects)

    # ------------------------------------------------------------------ candidates
    def _derived(self, rule, cov: Coverage, covered: set[str], days: list[str], files: list[RawFile],
                 filters: dict | None, extra: dict) -> Candidate | None:
        use = [d for d in days if d in covered]
        if not use:
            return None
        rest = [f for f in files if f.day not in covered]
        if rest and rule.correlation:
            return None
        scanned, snap = table_scan(self.settings, cov.table, use, filters)
        if snap is None:
            return None
        step = {"tier": cov.tier, "kind": extra.pop("kind"), "capability": cov.capability, "table": cov.table,
                "exact": cov.exact, "granularity": cov.granularity, "sources": rule.sources, "days": use,
                "scanned_bytes": scanned, "snapshot_id_at_plan": snap, "filters": filters or {},
                "notes": cov.reasons + extra.pop("notes", []), **extra}
        steps, qs = [step], [est.Quantities(tier=cov.tier, scanned_bytes=scanned)]
        if rest:
            rs, rq = self.raw_step(rule, rest)
            rs["notes"] = [f"{len({f.day for f in rest})} day(s) not covered by {cov.table}"] + rs["notes"]
            steps.append(rs)
            qs.append(rq)
        total = sum(f.bytes for f in files) or 1
        covered_bytes = sum(f.bytes for f in files if f.day in covered)
        return Candidate(cov.capability, cov.tier, cov.exact, steps, qs, est.cost(qs, self.calibration),
                         round(100.0 * covered_bytes / total, 2))

    def candidates(self, rule: CompiledRule, files: list[RawFile]) -> list[Candidate]:
        days = sorted({f.day for f in files})
        out: list[Candidate] = []
        for dt in DIMENSION_TABLES:
            cov = dt.covers(rule)
            if cov is None:
                continue
            if dt.feature:
                covered = feature_current_days(self.conn, dt.feature, self.day_gens, self.runs)
            else:
                covered = summary_current_days(self.conn, dt.summary_source, self.day_gens, self.runs)
            c = self._derived(rule, cov, covered, days, files, dict(dt.filters),
                              {"kind": "dimension", "entity_col": dt.entity_col, "count_col": dt.count_col,
                               "time_col": dt.time_col})
            if c:
                out.append(c)
        hv = high_value_coverage(rule)
        if hv:
            covered = set(days)
            for s in rule.sources:
                covered &= summary_current_days(self.conn, s, self.day_gens, self.runs)
            c = self._derived(rule, hv, covered, days, files, {"source": list(rule.sources)}, {"kind": "high_value"})
            if c:
                out.append(c)
        agg = aggregate_plan(rule)
        if agg:
            covered = summary_current_days(self.conn, AGG_TABLE_SOURCE[agg.table], self.day_gens, self.runs)
            cov = Coverage(agg.capability, 2, agg.table, agg.exact, "group-day",
                           ["correlation answered on summary buckets (upper-bound counts)"])
            c = self._derived(rule, cov, covered, days, files, None, {"kind": "aggregate", "notes": agg.notes})
            if c:
                out.append(c)
        step, qn = self.raw_step(rule, files)
        out.append(Candidate("raw", 3, True, [step], [qn], est.cost([qn], self.calibration), 0.0))
        return out

    def plan(self, rule: CompiledRule, start: datetime, end: datetime) -> dict:
        files = raw_files(self.conn, rule.sources, start, end)
        cands = self.candidates(rule, files)
        # Differences below one cent (at modelled scale) are noise: prefer the lower tier then.
        cheapest = min(c.estimate["total"] for c in cands)
        near = [c for c in cands if c.estimate["total"] - cheapest <= COST_TIE]
        best = min(near, key=lambda c: (c.tier, not c.exact, c.estimate["total"]))
        modelled_restore = int(sum(s.get("restore_bytes", 0) for s in best.steps) * est.scale())
        level, reasons = est.approval_level(best.estimate, modelled_restore)
        tiers = sorted({s["tier"] for s in best.steps})
        return {
            "planner_version": PLANNER_VERSION,
            "rule": rule.to_dict(),
            "range": {"start": start.isoformat(), "end": end.isoformat()},
            "candidates": [{"capability": c.capability, "tier": c.tier, "exact": c.exact,
                            "coverage_pct": c.coverage_pct if c.tier < 3 else 100.0,
                            "estimated_cost": c.estimate["total"]} for c in cands],
            "chosen": best.capability,
            "steps": best.steps,
            "tiers": tiers,
            "coverage_pct": best.coverage_pct if best.tier < 3 else 0.0,
            "exact": all(s["exact"] for s in best.steps),
            "full_rehydration_bytes": sum(f.bytes for f in files),
            "raw_files_in_range": len(files),
            "estimate": best.estimate,
            "quantities": [q.__dict__ for q in best.quantities],
            "modelled_restore_bytes": modelled_restore,
            "approval": {"level": level, "reasons": reasons},
        }


def step_summary(step: dict) -> dict:
    """Compact form of a plan step for events and read models."""
    keys = ("tier", "kind", "capability", "table", "exact", "granularity", "scanned_bytes", "restore_bytes",
            "anchors", "partitions_in_range", "partitions_after_bloom", "notes")
    out = {k: step[k] for k in keys if k in step}
    out["days"] = len(step.get("days", []))
    if "targets" in step:
        out["objects"] = len(step["targets"])
    return out
