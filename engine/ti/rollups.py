"""ti.strategic rollups (plan.md section 3.10a): which attack types the organisation faces.

Built from ti.operational (validated and auto_validated rows only) joined with ti.tactical
for threat families/types and feed provenance. One row per
    period x tactic x technique x threat family x threat type x asset class x business unit
with trend columns against the previous period and the same period one year earlier
(the 15-year retention is what makes multi-year comparison possible).
"""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import date, datetime, timedelta, timezone

from engine.ti.attack import attack
from engine.ti.tables import now

ROLLUP_VERSION = "1"
PERIODS = ("week", "month", "quarter", "year")
INCLUDED = ("validated", "auto_validated")


def period_start(d: date, period: str) -> date:
    if period == "week":
        return d - timedelta(days=d.weekday())
    if period == "month":
        return d.replace(day=1)
    if period == "quarter":
        return d.replace(month=3 * ((d.month - 1) // 3) + 1, day=1)
    if period == "year":
        return d.replace(month=1, day=1)
    raise ValueError(f"unknown period {period}")


def previous(start: date, period: str) -> date:
    if period == "week":
        return start - timedelta(days=7)
    if period == "month":
        return (start - timedelta(days=1)).replace(day=1)
    if period == "quarter":
        m = start.month - 3
        return start.replace(year=start.year - (m < 1), month=m + 12 if m < 1 else m)
    return start.replace(year=start.year - 1)


def same_last_year(start: date, period: str) -> date:
    if period == "week":
        return period_start(start - timedelta(days=364), "week")
    return start.replace(year=start.year - 1)


def build(operational: list[dict], tactical: list[dict], period: str) -> list[dict]:
    att = attack()
    ind = {}
    for t in tactical:
        ind.setdefault(t["indicator_id"], []).append(t)
    groups: dict[tuple, dict] = defaultdict(lambda: {"obs": 0, "entities": set(), "patterns": Counter(),
                                                     "families": Counter(), "feed_hits": 0})
    for o in operational:
        if o["status"] not in INCLUDED or o.get("observed_at") is None:
            continue
        observed = o["observed_at"]
        observed = observed if observed.tzinfo else observed.replace(tzinfo=timezone.utc)
        start = period_start(observed.date(), period).isoformat()
        matched = [r for i in (o.get("matched_indicator_ids") or []) for r in ind.get(i, [])]
        feed = [r for r in matched if r["source"] != "internal"]
        family = o.get("threat_family") or next((r["malware_family"] for r in matched if r.get("malware_family")),
                                                None) or "unattributed"
        ttype = next((r["threat_type"] for r in matched if r.get("threat_type")), None) or "unknown"
        techniques = o.get("attack_techniques") or []
        for tech in techniques:
            t = att.technique(tech)
            tactics = [x for x in (o.get("attack_tactics") or []) if t and x in t.tactics] or \
                (list(t.tactics) if t else ["unknown"])
            for tactic in tactics:
                key = (start, tactic, tech, family, ttype, o.get("asset_class") or "unknown",
                       o.get("business_unit") or "unknown")
                g = groups[key]
                g["obs"] += 1
                g["entities"].add(o.get("entity_pseudonym"))
                g["patterns"][o.get("title") or o.get("pattern_id")] += 1
                g["families"][family] += 1
                g["feed_hits"] += len({r["indicator_id"] for r in feed})
    counts = {k: g["obs"] for k, g in groups.items()}
    built = now()
    rows = []
    for key, g in sorted(groups.items()):
        start = date.fromisoformat(key[0])
        prev_key = (previous(start, period).isoformat(),) + key[1:]
        yoy_key = (same_last_year(start, period).isoformat(),) + key[1:]
        rows.append({
            "period_type": period, "period_start": key[0], "tactic": key[1], "technique_id": key[2],
            "threat_family": key[3], "threat_type": key[4], "asset_class": key[5], "business_unit": key[6],
            "observations": g["obs"], "distinct_entities": len(g["entities"] - {None}),
            "distinct_patterns": len(g["patterns"]), "feed_indicator_hits": g["feed_hits"],
            "delta_vs_prev_period": g["obs"] - counts.get(prev_key, 0),
            "delta_vs_same_period_last_year": g["obs"] - counts.get(yoy_key, 0),
            "top_patterns": [p for p, _ in g["patterns"].most_common(3)],
            "top_families": [f for f, _ in g["families"].most_common(3)],
            "rollup_version": ROLLUP_VERSION, "built_at": built})
    return rows


def compare(rows: list[dict], period: str, by: str = "tactic") -> list[dict]:
    """Per period and dimension: observations, previous period and same period last year."""
    agg: dict[tuple[str, str], int] = defaultdict(int)
    for r in rows:
        agg[(r["period_start"], r[by])] += r["observations"]
    out = []
    for (start, dim), n in sorted(agg.items()):
        s = date.fromisoformat(start)
        prev = agg.get((previous(s, period).isoformat(), dim), 0)
        yoy = agg.get((same_last_year(s, period).isoformat(), dim), 0)
        out.append({"period_start": start, by: dim, "observations": n, "previous_period": prev,
                    "same_period_last_year": yoy, "delta_vs_prev_period": n - prev,
                    "delta_vs_same_period_last_year": n - yoy,
                    "yoy_change_pct": round(100.0 * (n - yoy) / yoy, 1) if yoy else None})
    return out


def utc(d: datetime | None) -> datetime | None:
    return d if d is None or d.tzinfo else d.replace(tzinfo=timezone.utc)
