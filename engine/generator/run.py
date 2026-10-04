"""Generate a run: baseline + scenarios → native batches in the `incoming` bucket.

    incoming/<run_id>/manifest.json
    incoming/<run_id>/inventory/{identities,assets}.json
    incoming/<run_id>/source=<src>/date=<YYYY-MM-DD>/batch.jsonl.gz

Ground truth goes to GROUND_TRUTH_DIR/<run_id>/ on the local filesystem, never to
object storage, so the engine cannot see it.
"""
from __future__ import annotations

import json
import logging
import random
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

import yaml

from engine.common.config import REPO_ROOT, Settings
from engine.common.ids import stable_event_ids
from engine.common.storage import ObjectStore
from engine.generator.benign import Baseline
from engine.generator.emitters import SOURCES, Sink
from engine.generator.scenarios import ScenarioContext, run_scenarios
from engine.generator.world import build_world

log = logging.getLogger(__name__)


def load_scenarios(path: Path | None) -> list[dict]:
    path = path or REPO_ROOT / "scenarios" / "default.yaml"
    return yaml.safe_load(path.read_text())["scenarios"]


def generate(settings: Settings, store: ObjectStore, *, run_id: str, start: date, days: int, users: int, seed: int,
             scenarios_file: Path | None = None) -> dict:
    rng = random.Random(seed)
    world = build_world(seed, users)
    sink = Sink(rng=random.Random(seed + 1))
    baseline = Baseline(world, sink, rng)
    baseline.run(start, days)
    ctx = ScenarioContext(world, sink, baseline, random.Random(seed + 2), start)
    labels = run_scenarios(ctx, load_scenarios(scenarios_file), days)
    by_id = {lab.scenario_id: lab for lab in labels}

    prefix = f"{settings.buckets.incoming}/{run_id}"
    identities, assets = world.inventory()
    store.put_json(f"{prefix}/inventory/identities.json", identities)
    store.put_json(f"{prefix}/inventory/assets.json", assets)

    label_events: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    batches = []
    for source in SOURCES:
        per_day: dict[date, list] = defaultdict(list)
        for entry in sink.entries.get(source, []):
            per_day[entry.ts.date()].append(entry)
        for day in sorted(per_day):
            entries = sorted(per_day[day], key=lambda e: (e.ts, e.seq))
            records = [e.record for e in entries]
            for entry, event_id in zip(entries, stable_event_ids(source, records)):
                if entry.scenario:
                    label_events[entry.scenario][source].append(event_id)
            batch_id = f"{run_id}-{source}-{day:%Y%m%d}"
            uri = f"{prefix}/source={source}/date={day:%Y-%m-%d}/batch.jsonl.gz"
            store.put_jsonl_gz(uri, records)
            batches.append({"batch_id": batch_id, "source": source, "date": f"{day:%Y-%m-%d}", "uri": uri,
                            "records": len(records)})

    manifest = {
        "run_id": run_id, "seed": seed, "start": start.isoformat(), "days": days, "users": users,
        "inventory_uri": f"{prefix}/inventory", "sources": list(SOURCES),
        "batches": batches,  # dhcp first: leases must exist before network sources are resolved
        "records": sum(b["records"] for b in batches),
    }
    store.put_json(f"{prefix}/manifest.json", manifest)

    gt_dir = settings.ground_truth_dir / run_id
    gt_dir.mkdir(parents=True, exist_ok=True)
    gt = []
    for sid, lab in by_id.items():
        d = lab.to_dict()
        d["event_ids"] = {src: ids for src, ids in label_events[sid].items()}
        d["event_count"] = sum(len(v) for v in d["event_ids"].values())
        gt.append(d)
    (gt_dir / "labels.json").write_text(json.dumps(gt, indent=2) + "\n")
    (gt_dir / "run.json").write_text(json.dumps({k: v for k, v in manifest.items() if k != "batches"}, indent=2)
                                     + "\n")
    counts = Counter({b["source"]: 0 for b in batches})
    for b in batches:
        counts[b["source"]] += b["records"]
    log.info("generated run %s: %d records, %d batches, %d scenarios", run_id, manifest["records"], len(batches),
             len(gt))
    return {**manifest, "records_by_source": dict(counts), "scenarios": [g["scenario_id"] for g in gt],
            "ground_truth": str(gt_dir)}
