"""Detection fidelity benchmark (plan.md sections 10 / 11, milestone M9).

For every rule in rules/sigma/ it submits the rule through the normal command path
(SubmitRule → plan → approval → ExecuteRule), then evaluates the same compiled rule on
*all* raw data (a full rehydration: the ground truth of what the rule means) and compares:

  * recall    = |tier hits ∩ raw hits| / |raw hits|      at entity x day (every tier) and
                at event level (when the answering tier returns events)
  * precision against the scenario labels, for the tier answer and for the raw answer
    (the plan's "no regression vs raw")
  * tier-hit rate, restore ratio (objects restored / full rehydration), latency per tier

Labels are read only here; the engine never sees them.

    python -m benchmarks.fidelity --run-id demo [--local]
"""
from __future__ import annotations

import argparse
import json
import math
import sys
import time
import uuid
from collections import defaultdict
from datetime import datetime, timezone
from statistics import median

from engine.common.config import REPO_ROOT, Settings

CORPUS_DIR = REPO_ROOT / "rules" / "sigma"
TERMINAL = {"succeeded", "failed", "blocked", "planned", "deferred_budget"}


def corpus() -> list[tuple[str, str]]:
    return [(p.stem, p.read_text()) for p in sorted(CORPUS_DIR.glob("*.yml"))]


# --------------------------------------------------------------------------- ground truth helpers
def raw_baseline(conn, store, settings: Settings, rule_yaml: str, start: datetime, end: datetime) -> list[dict]:
    """The rule evaluated on every raw object of its sources in range (full rehydration)."""
    from engine.rules.compiler import compile_sigma
    from engine.rules.executor import Executor
    from engine.rules.tier3 import raw_files
    rule = compile_sigma(rule_yaml)
    files = raw_files(conn, rule.sources, start, end)
    step = {"tier": 3, "capability": "raw_baseline", "exact": True,
            "targets": [{"file": f.file, "bytes": f.bytes, "storage_tier": "hot", "row_groups": None} for f in files]}
    hits, _ = Executor(conn, store, settings).run_raw(rule, step, start, end)
    return hits


def label_tokens(store, settings: Settings, labels: list[dict]) -> tuple[set[str], dict[str, list[set[str]]]]:
    """Labelled event ids, and per day the identifying values of each labelled event."""
    ids = {e for lab in labels for v in lab["event_ids"].values() for e in v}
    by_day: dict[str, list[set[str]]] = defaultdict(list)
    cols = ["event.id", "@timestamp", "host.name", "user.name", "source.ip", "destination.ip",
            "dns.question.registered_domain", "url.domain", "user.target.name"]
    for path in store.list(settings.buckets.raw, ".parquet"):
        t = store.read_parquet(path, columns=cols)
        for row in t.to_pylist():
            if row["event.id"] in ids:
                day = row["@timestamp"].astimezone(timezone.utc).date().isoformat()
                by_day[day].append({str(row[c]).lower() for c in cols[2:] if row.get(c)})
    return ids, by_day


def is_true_positive(hit: dict, ids: set[str], by_day: dict[str, list[set[str]]]) -> bool:
    if hit.get("event_id"):
        return hit["event_id"] in ids
    if hit.get("group_key"):
        values = {str(v).lower() for v in json.loads(hit["group_key"]).values() if v is not None}
    else:
        values = {hit["entity_key"].rsplit("@", 1)[0]}
    return any(values <= tokens for tokens in by_day.get(hit["day"], []))


def compare(tier_hits: list[dict], raw_hits: list[dict]) -> dict:
    te, re_ = {h["entity_key"] for h in tier_hits}, {h["entity_key"] for h in raw_hits}
    out = {"raw_hits": len(raw_hits), "tier_hits": len(tier_hits), "raw_entities": len(re_),
           "tier_entities": len(te),
           "entity_recall": round(len(te & re_) / len(re_), 4) if re_ else None,
           "entity_precision_vs_raw": round(len(te & re_) / len(te), 4) if te else None}
    tev = {h["event_id"] for h in tier_hits if h.get("event_id")}
    rev = {h["event_id"] for h in raw_hits if h.get("event_id")}
    if tev or (rev and all(h.get("event_id") for h in tier_hits) and tier_hits):
        out["event_recall"] = round(len(tev & rev) / len(rev), 4) if rev else None
    return out


# --------------------------------------------------------------------------- driving the engine
def submit_corpus(client, start: datetime, end: datetime, rules: list[tuple[str, str]], approve: bool = True,
                  timeout_s: float = 3600) -> dict[str, dict]:
    """Submit every rule, approve what needs approval, wait for terminal states. Returns {name: run}."""
    from engine.cqrs.commands import ApproveRun, SubmitRule
    runs = {}
    cmd_ids = []
    for name, text in rules:
        run_id = str(uuid.uuid4())
        cmd_ids.append(client.submit(SubmitRule(rule_yaml=text, start=start, end=end, run_id=run_id,
                                                origin="benchmark", submitted_by="benchmark")))
        runs[name] = run_id
    client.wait(cmd_ids)
    deadline = time.monotonic() + timeout_s
    approved: set[str] = set()
    out: dict[str, dict] = {}
    while time.monotonic() < deadline:
        pending = False
        listing = client.query("/runs?limit=2000")
        for name, run_id in runs.items():
            if name in out:
                continue
            row = next((x for x in listing["items"] if x["run_id"] == run_id), None)
            if row is None:
                pending = True
                continue
            if row["status"] == "awaiting_approval" and approve and run_id not in approved:
                ids = [client.submit(ApproveRun(run_id=run_id, approver="benchmark-hunter", role="hunter"))]
                if row["approval_level"] == "manager":
                    ids.append(client.submit(ApproveRun(run_id=run_id, approver="benchmark-manager", role="manager")))
                client.wait(ids)
                approved.add(run_id)
                pending = True
                continue
            if row["status"] == "queued" and row.get("execute_command_id"):
                client.wait([row["execute_command_id"]])
            detail = client.query(f"/rules/{row['rule_id']}/runs/{run_id}")
            if detail.get("status") in TERMINAL:
                out[name] = detail
            else:
                pending = True
        if not pending or len(out) == len(runs):
            break
        time.sleep(1)
    return out


def evaluate(client, conn, store, settings: Settings, labels: list[dict] | None, start: datetime,
             end: datetime, rules: list[tuple[str, str]] | None = None) -> dict:
    rules = rules or corpus()
    runs = submit_corpus(client, start, end, rules)
    ids, by_day = label_tokens(store, settings, labels) if labels else (set(), {})
    per_rule, latencies = [], defaultdict(list)
    for name, text in rules:
        run = runs.get(name)
        if run is None or run.get("status") != "succeeded":
            per_rule.append({"rule": name, "status": run.get("status") if run else "missing"})
            continue
        hits = client.query(f"/rules/{run['rule_id']}/runs/{run['run_id']}/hits?limit=20000")["items"]
        raw = raw_baseline(conn, store, settings, text, start, end)
        row = {"rule": name, "run_id": run["run_id"], "title": run.get("title"), "status": "succeeded",
               "tiers": run["tiers"],
               "exact": all(s.get("exact", True) for s in (run.get("steps") or [])),
               "coverage_pct": run["coverage_pct"], **compare(hits, raw),
               "bytes_scanned": run.get("bytes_scanned"), "bytes_restored": run.get("bytes_restored"),
               "files_restored": run.get("files_restored"),
               "full_rehydration_bytes": None, "duration_ms": run.get("duration_ms"),
               "estimated_cost": run.get("estimated_cost"), "actual_cost": run.get("actual_cost"),
               "approval_level": run.get("approval_level")}
        if labels:
            row["label_precision"] = round(sum(is_true_positive(h, ids, by_day) for h in hits) / len(hits), 4) \
                if hits else None
            row["raw_label_precision"] = round(sum(is_true_positive(h, ids, by_day) for h in raw) / len(raw), 4) \
                if raw else None
        latencies[max(run["tiers"])].append(run.get("duration_ms") or 0)
        per_rule.append(row)
    ok = [r for r in per_rule if r["status"] == "succeeded"]
    t12 = [r for r in ok if max(r["tiers"]) <= 2]
    recalls = [r["entity_recall"] for r in t12 if r.get("entity_recall") is not None]
    return {
        "rules": len(rules), "succeeded": len(ok),
        "tier_hit_rate": round(len(t12) / len(ok), 4) if ok else None,
        "tier_distribution": {str(t): sum(1 for r in ok if max(r["tiers"]) == t) for t in (1, 2, 3)},
        "recall_tier12_min": min(recalls) if recalls else None,
        "recall_tier12_mean": round(sum(recalls) / len(recalls), 4) if recalls else None,
        "latency_ms": {str(t): {"p50": int(median(v)), "p95": int(sorted(v)[max(0, math.ceil(len(v) * 0.95) - 1)])}
                       for t, v in sorted(latencies.items())},
        "per_rule": per_rule,
    }


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--run-id", default="demo")
    p.add_argument("--start", default=None)
    p.add_argument("--end", default=None)
    p.add_argument("--local", action="store_true")
    args = p.parse_args()
    from engine.cli import make_client
    from engine.common.db import make_engine
    from engine.common.storage import ObjectStore
    settings = Settings.from_env()
    run_meta = json.loads((settings.ground_truth_dir / args.run_id / "run.json").read_text())
    labels = json.loads((settings.ground_truth_dir / args.run_id / "labels.json").read_text())
    from datetime import date, timedelta
    d0 = date.fromisoformat(run_meta["start"])
    start = datetime.fromisoformat(args.start) if args.start else datetime(d0.year, d0.month, d0.day, tzinfo=timezone.utc)
    end = datetime.fromisoformat(args.end) if args.end else start + timedelta(days=run_meta["days"])
    client = make_client(args, settings)
    store = ObjectStore.from_settings(settings)
    engine = make_engine(settings.database_url)
    with engine.connect() as conn:
        result = evaluate(client, conn, store, settings, labels, start, end)
    json.dump(result, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
