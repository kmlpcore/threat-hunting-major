"""Check that every labelled attack event landed in raw/ (M1 exit criterion).

Benchmark tooling is the only code allowed to read ground truth; the engine never does.

    python -m benchmarks.ground_truth_check --run-id demo
"""
from __future__ import annotations

import argparse
import json
import sys

from engine.common.config import Settings
from engine.common.storage import ObjectStore


def check(settings: Settings, run_id: str) -> dict:
    store = ObjectStore.from_settings(settings)
    labels = json.loads((settings.ground_truth_dir / run_id / "labels.json").read_text())
    landed: dict[str, set[str]] = {}
    for path in store.list(settings.buckets.raw, suffix=".parquet"):
        if f"part-{run_id}-" not in path:
            continue
        source = path.split("source=", 1)[1].split("/", 1)[0]
        landed.setdefault(source, set()).update(store.read_parquet(path, columns=["event.id"]).column(0).to_pylist())
    report, all_ok = [], True
    for lab in labels:
        missing = {src: [i for i in ids if i not in landed.get(src, set())] for src, ids in lab["event_ids"].items()}
        missing = {k: v for k, v in missing.items() if v}
        all_ok &= not missing
        report.append({"scenario_id": lab["scenario_id"], "techniques": lab["techniques"],
                       "events": lab["event_count"], "by_source": {k: len(v) for k, v in lab["event_ids"].items()},
                       "missing": {k: len(v) for k, v in missing.items()}})
    return {"run_id": run_id, "scenarios": len(labels), "all_events_landed": all_ok, "detail": report}


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--run-id", default="demo")
    result = check(Settings.from_env(), p.parse_args().run_id)
    json.dump(result, sys.stdout, indent=2)
    sys.stdout.write("\n")
    sys.exit(0 if result["all_events_landed"] else 1)


if __name__ == "__main__":
    main()
