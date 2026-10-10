"""M9 evaluation report (plan.md sections 10 and 11).

Runs the benchmark corpus twice through the normal command path (the second pass uses the
calibrated estimator), optionally pulls the TI feeds, waits for TI processing, then measures:

  tier-hit rate, recall / precision per rule vs a full rehydration and vs labels, restore ratio,
  storage ratio, latency per tier, LLM mapping accuracy, estimate accuracy before/after
  calibration, feed-to-sighting latency, retro-sweep cost per indicator, and the cost model
  (break-even number of hunts vs full rehydration).

Writes docs/evaluation.md and benchmarks/results/evaluation.json.

    python -m benchmarks.report --run-id demo [--local] [--feeds]
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from datetime import date, datetime, timedelta, timezone

from engine.common.config import REPO_ROOT, Settings

TARGETS = {"tier_hit_rate": 0.70, "recall": 0.95, "ioc_restore_ratio": 0.05, "llm_accuracy": 0.80,
           "estimate_error": 0.25}


def llm_accuracy(settings: Settings, labels: list[dict], operational: list[dict]) -> dict:
    from engine.common.pseudonymise import pseudonym
    llm = [o for o in operational if o["origin"] == "llm"]
    if not llm:
        return {"measured": False, "reason": "no LLM-enriched observations (LLM_PROVIDER not set?)"}
    correct, detail = 0, []
    for lab in labels:
        # Correlation hits are keyed by their group (e.g. the spraying source IP) and by bucket start.
        ents = {pseudonym(settings, "user", u) for u in lab["users"]} | \
               {pseudonym(settings, "host", h) for h in lab["hosts"]} | \
               {pseudonym(settings, "ip", i) for i in lab["indicators"]["ips"]}
        start = datetime.fromisoformat(lab["start"]).replace(hour=0, minute=0, second=0, microsecond=0)
        end = datetime.fromisoformat(lab["end"]) + timedelta(hours=7)
        cands = [o for o in llm if o["entity_pseudonym"] in ents and o["observed_at"]
                 and start <= o["observed_at"] <= end]
        got = {t for o in cands for t in o["attack_techniques"]}
        want = set(lab["techniques"])
        ok = bool(got & want) or any(t.split(".")[0] in {w.split(".")[0] for w in want} for t in got)
        correct += ok
        detail.append({"scenario": lab["scenario_id"], "expected": sorted(want), "mapped": sorted(got)[:8],
                       "correct": ok})
    providers = sorted({f"{o['llm_provider']}/{o['llm_model']}" for o in llm})
    return {"measured": True, "providers": providers, "accuracy": round(correct / len(labels), 4),
            "correct": correct, "scenarios": len(labels), "detail": detail}


def wait_quiet(client, timeout_s: float = 900) -> None:
    """Wait until TI processing settles (observation / enrichment / rollup commands drain)."""
    last, stable, deadline = None, 0, time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        s = client.query("/ti/summary")
        key = json.dumps(s, sort_keys=True)
        stable = stable + 1 if key == last else 0
        last = key
        if stable >= 3:
            return
        time.sleep(5)


def fmt(v, pct=False):
    if v is None:
        return "–"
    if pct:
        return f"{100 * v:.1f} %"
    return f"{v:,.4f}" if isinstance(v, float) else str(v)


def render(r: dict) -> str:
    f, c, ti = r["fidelity"], r["cost"], r["ti"]
    ok = lambda b: "✅" if b else "❌"  # noqa: E731
    est_err = (c["estimate_accuracy"].get("calibrated") or {}).get("median")
    llm = ti["llm_mapping"]
    lines = [
        "# Evaluation report (M9)", "",
        f"Generated {r['generated_at']} from run `{r['run_id']}` "
        f"({r['dataset']['records']:,} records, {r['dataset']['days']} days, {r['dataset']['users']} users"
        f"{', plus multi-year history' if r['dataset'].get('history_years') else ''}). "
        f"Mode: {r['mode']}. Pricing `{c['pricing_version']}`, modelled scale x{c['scale_factor']:,.0f}.", "",
        "Produced by `python -m benchmarks.report`; every number below is measured on this deployment.", "",
        "## Targets (plan.md section 11)", "",
        "| Metric | Target | Result | |", "|---|---|---|---|",
        f"| Tier-hit rate (rules answered fully at tier 1/2) | ≥ 70 % | {fmt(f['tier_hit_rate'], True)} | "
        f"{ok((f['tier_hit_rate'] or 0) >= TARGETS['tier_hit_rate'])} |",
        f"| Detection recall at tier 1/2 vs full rehydration (min over rules) | ≥ 0.95 | "
        f"{fmt(f['recall_tier12_min'])} | {ok((f['recall_tier12_min'] or 0) >= TARGETS['recall'])} |",
        f"| Restore ratio, IOC sweeps (max) | ≤ 5 % | {fmt(c['ioc_sweep_restore_ratio_max'], True)} | "
        f"{ok(c['ioc_sweep_restore_ratio_max'] is not None and c['ioc_sweep_restore_ratio_max'] <= 0.05)} |",
        f"| LLM ATT&CK mapping accuracy | ≥ 0.8 | "
        f"{fmt(llm.get('accuracy')) if llm.get('measured') else 'not measured'} | "
        f"{ok((llm.get('accuracy') or 0) >= TARGETS['llm_accuracy']) if llm.get('measured') else '–'} |",
        f"| Cost estimate error after calibration (median) | ≤ 25 % | {fmt(est_err, True)} | "
        f"{ok(est_err is not None and est_err <= TARGETS['estimate_error'])} |",
        f"| Storage ratio (summary + artefacts + index) / raw | report | {fmt(r['storage']['derived_to_raw'])} | |",
        f"| Break-even (hunts per year, 7-day / 5-year hunts) | report | {fmt(c['break_even_hunts_per_year'])} / "
        f"{fmt(c['five_year']['break_even_hunts_per_year'])} | |", "",
        "## Tier distribution and latency", "",
        "| Tier | Rules | p50 latency | p95 latency |", "|---|---|---|---|"]
    for t in ("1", "2", "3"):
        lat = f["latency_ms"].get(t, {})
        lines.append(f"| {t} | {f['tier_distribution'].get(t, 0)} | {lat.get('p50', '–')} ms | {lat.get('p95', '–')} ms |")
    lines += ["", "## Per-rule fidelity", "",
              "| Rule | Tier | Exact | Coverage | Raw hits | Recall (entity) | Recall (event) | Label precision "
              "(tier / raw) | Restored | Est. / actual cost |",
              "|---|---|---|---|---|---|---|---|---|---|"]
    for x in f["per_rule"]:
        if x.get("status") != "succeeded":
            lines.append(f"| {x['rule']} | – | – | – | – | – | – | – | – | {x.get('status')} |")
            continue
        lines.append(
            f"| {x['rule']} | {max(x['tiers'])} | {'yes' if x['exact'] else 'upper bound'} | {x['coverage_pct']} % | "
            f"{x['raw_hits']} | {fmt(x.get('entity_recall'))} | {fmt(x.get('event_recall'))} | "
            f"{fmt(x.get('label_precision'))} / {fmt(x.get('raw_label_precision'))} | "
            f"{x['bytes_restored'] or 0:,} B | {x['estimated_cost']:.4f} / {x['actual_cost']:.4f} |")
    lines += ["", "## Cost model", "",
              f"Mean cost per hunt: full rehydration **{c['mean_cost_per_hunt']['baseline_full_rehydration']:.2f} "
              f"{c['currency']}**, this design **{c['mean_cost_per_hunt']['ours']:.4f} {c['currency']}** "
              f"(by tier: {', '.join(f'T{k} {v:.4f}' for k, v in c['mean_actual_cost_by_tier'].items())}).", "",
              f"Extraction: one-time build {c['extract']['build']:.2f} {c['currency']}, plus derived-layer storage "
              f"{c['extract']['storage_per_month'] * 12:,.2f} {c['currency']}/year. Hunts per year needed to pay for "
              f"it: **{fmt(c['break_even_hunts_per_year'])}** with this 7-day range, "
              f"**{fmt(c['five_year']['break_even_hunts_per_year'])}** for the plan's 5-year hunts "
              f"(full rehydration {c['five_year']['baseline_per_hunt']:,.2f} vs {c['five_year']['ours_per_hunt']:,.2f} per hunt).", "",
              "| Hunts per year (5-year range) | Full rehydration | This design |", "|---|---|---|"]
    for n, v in c["five_year"]["for_n_hunts"].items():
        lines.append(f"| {n} | {v['baseline']:,.2f} | {v['ours']:,.2f} |")
    s = c["storage"]
    lines += ["", f"Storage at modelled scale ({s['modelled_raw_tb']} TB raw, {s['modelled_derived_tb']} TB derived): "
              f"**{s['ours_per_month']:,.2f}/month** (raw in deep archive + derived infrequent-access) vs "
              f"{s['raw_on_standard_per_month']:,.2f}/month for raw on standard storage ({s['saving_pct']} % less).", "",
              "Estimate accuracy (|est − actual| / actual):", "",
              f"* uncalibrated: {json.dumps(c['estimate_accuracy']['uncalibrated'])}",
              f"* calibrated: {json.dumps(c['estimate_accuracy']['calibrated'])}", "",
              "## Threat intelligence", "",
              f"* ti.tactical: {ti['summary']['tactical']['indicators']} indicators "
              f"({json.dumps(ti['summary']['tactical']['by_source'])}), {ti['summary']['tactical']['sighted']} sighted in the org",
              f"* ti.operational: {ti['summary']['operational']['rows']} observations "
              f"({json.dumps(ti['summary']['operational']['by_origin'])})",
              f"* ti.strategic tactics: {', '.join(ti['summary']['strategic']['tactics'])}",
              f"* Feed retro-sweeps: {c['feeds']['sweeps']}, cost per indicator "
              f"{fmt(c['feeds']['retro_sweep_cost_per_indicator'])} {c['currency']}, feed-to-sighting latency "
              f"{json.dumps(c['feeds']['feed_to_sighting_latency_s'])} s, max sweep restore ratio "
              f"{fmt(c['feeds']['sweep_restore_ratio_max'], True)}"]
    if llm.get("measured"):
        lines += ["", f"LLM mapping ({', '.join(llm['providers'])}): {llm['correct']}/{llm['scenarios']} planted "
                  "scenarios mapped to at least one expected technique (or its parent).", "",
                  "| Scenario | Expected | Mapped | |", "|---|---|---|---|"]
        lines += [f"| {d['scenario']} | {', '.join(d['expected'])} | {', '.join(d['mapped']) or '–'} | "
                  f"{ok(d['correct'])} |" for d in llm["detail"]]
    lines += ["", "## Notes", "",
              "* Recall is measured against the rule evaluated on *all* raw data (what a full rehydration answers), "
              "at entity × day for every tier and at event level where the tier returns events.",
              "* Tier-2 correlation answers are sound over-approximations (upper-bound counts on hourly/daily "
              "buckets): they cannot miss an alert, but can add candidates; see label precision.",
              "* Costs are modelled at `scale_factor` with the list prices in policies/pricing.yaml (verify them). "
              "In the prototype `actual_cost` prices the measured bytes; production would read billing exports.",
              "* The offline LLM provider is a deterministic heuristic, so its mapping accuracy is a baseline; set "
              "LLM_PROVIDER=groq with GROQ_API_KEY and LLM_MODEL to measure a real model.", ""]
    return "\n".join(lines)


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--run-id", default="demo")
    p.add_argument("--local", action="store_true")
    p.add_argument("--feeds", action="store_true", help="pull every enabled feed first (exercises M7 metrics)")
    p.add_argument("--out", default=str(REPO_ROOT / "docs" / "evaluation.md"))
    args = p.parse_args()
    from benchmarks import cost as cost_mod
    from benchmarks.fidelity import evaluate
    from engine.cli import make_client
    from engine.common.db import make_engine
    from engine.common.storage import ObjectStore
    from engine.cqrs.commands import PullFeed
    from engine.ti import tables as T
    from engine.ti.connectors.sdk import feed_config, registry

    settings = Settings.from_env()
    gt = settings.ground_truth_dir / args.run_id
    run_meta = json.loads((gt / "run.json").read_text())
    labels = json.loads((gt / "labels.json").read_text())
    d0 = date.fromisoformat(run_meta["start"])
    start = datetime(d0.year, d0.month, d0.day, tzinfo=timezone.utc)
    end = start + timedelta(days=run_meta["days"])
    client = make_client(args, settings)
    store = ObjectStore.from_settings(settings)
    engine = make_engine(settings.database_url)

    if args.feeds:
        ids = [client.submit(PullFeed(connector=n)) for n in sorted(registry()) if feed_config(n).get("enabled")]
        client.wait(ids)
    with engine.connect() as conn:
        first = evaluate(client, conn, store, settings, labels, start, end)      # uncalibrated estimates
    with engine.connect() as conn:
        second = evaluate(client, conn, store, settings, labels, start, end)     # calibrated estimates
    wait_quiet(client)
    with engine.connect() as conn:
        storage = client.query("/storage")
        derived = storage["summary"]["bytes"] + storage["artefacts"]["bytes"] + storage["index"]["bytes"]
        cost = cost_mod.run(conn, store, [x["run_id"] for x in second["per_rule"] if x.get("run_id")], derived)
    operational, _ = T.read_all(settings, T.OPERATIONAL)
    history = [y for y in client.query("/retention")["data_years"] if int(y) != d0.year]
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"), "run_id": args.run_id,
        "mode": "local" if args.local else "compose",
        "dataset": {"records": run_meta["records"], "days": run_meta["days"], "users": run_meta["users"],
                    "history_years": len(history)},
        "fidelity": second, "fidelity_first_pass": {k: v for k, v in first.items() if k != "per_rule"},
        "storage": storage["ratios"], "cost": cost,
        "ti": {"summary": client.query("/ti/summary"), "llm_mapping": llm_accuracy(settings, labels, operational)},
    }
    out_json = REPO_ROOT / "benchmarks" / "results" / "evaluation.json"
    out_json.parent.mkdir(parents=True, exist_ok=True)
    out_json.write_text(json.dumps(report, indent=2, default=str) + "\n")
    md = render(report)
    from pathlib import Path
    Path(args.out).write_text(md, encoding="utf-8")
    print(md)


if __name__ == "__main__":
    sys.exit(main())
