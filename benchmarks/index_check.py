"""M3 exit criteria: planted IOCs found with 100 % recall; BM25 top-10 contains planted
free-text attacks. Also reports restore ratio vs a full rehydration.

Ground truth for an IOC is a brute-force scan of every raw row (what a full
rehydration would answer), so recall is measured against the raw data itself,
not only against the scenario labels. Benchmark tooling may read labels; the
engine never does.

    python -m benchmarks.index_check --run-id demo
"""
from __future__ import annotations

import argparse
import json
import sys

from engine.common.config import Settings
from engine.common.db import make_engine
from engine.common.storage import ObjectStore
from engine.indexer.backend import IOC_FIELDS
from engine.indexer.bloom import normalise_value
from engine.indexer.search import Searcher, detect_ioc_type

# (query, scenario whose labelled events must appear in the top 10)
TEXT_QUERIES = [
    ("powershell enc hidden bypass", "s03-encoded-powershell"),
    ("certutil urlcache split", "s04-lolbins"),
    ("mshta hta", "s04-lolbins"),
    ("psexesvc", "s05-lateral-movement"),
    ("xmrig stratum donate", "s09-cryptomining"),
]


def brute_force(store: ObjectStore, settings: Settings, value: str, ioc_type: str) -> set[str]:
    """Every raw row whose IOC fields contain the value: the full-rehydration answer."""
    needle, fields, hits = normalise_value(value), IOC_FIELDS[ioc_type], set()
    for path in store.list(settings.buckets.raw, ".parquet"):
        t = store.read_parquet(path, columns=["event.id", *fields])
        cols = {f: t.column(f).to_pylist() for f in fields}
        for i, eid in enumerate(t.column("event.id").to_pylist()):
            for f in fields:
                v = cols[f][i]
                vals = v if isinstance(v, list) else [v]
                if any(x is not None and normalise_value(x) == needle for x in vals):
                    hits.add(eid)
                    break
    return hits


def run(settings: Settings, run_id: str) -> dict:
    store = ObjectStore.from_settings(settings)
    engine = make_engine(settings.database_url)
    searcher = Searcher(engine, store, settings)
    labels = json.loads((settings.ground_truth_dir / run_id / "labels.json").read_text())

    iocs = sorted({(v, k) for lab in labels for k in ("ips", "domains", "hashes") for v in lab["indicators"][k]})
    ioc_results, all_full = [], True
    for value, kind in iocs:
        ioc_type = detect_ioc_type(value)
        res = searcher.ioc_sweep(value, ioc_type, limit=1)
        found = set(res["event_ids"])
        truth = brute_force(store, settings, value, ioc_type)
        recall = len(found & truth) / len(truth) if truth else None
        all_full &= recall in (None, 1.0)
        s = res["stats"]
        ioc_results.append({"ioc": value, "type": ioc_type, "truth": len(truth), "found": len(found),
                            "recall": recall, "extra": len(found - truth),
                            "partitions": f"{s['partitions_after_bloom']}/{s['partitions_in_range']}",
                            "restore_ratio": s["restore_ratio"], "bytes_restored": s["bytes_restored"]})

    text_results, all_top10 = [], True
    by_id = {lab["scenario_id"]: {e for ids in lab["event_ids"].values() for e in ids} for lab in labels}
    for query, scenario in TEXT_QUERIES:
        if scenario not in by_id:
            continue
        res = searcher.text_search(query, limit=10)
        hit = bool(set(res["event_ids"]) & by_id[scenario])
        all_top10 &= hit
        rank = next((i + 1 for i, e in enumerate(res["event_ids"]) if e in by_id[scenario]), None)
        text_results.append({"query": query, "scenario": scenario, "in_top10": hit, "first_rank": rank})

    ratios = [r["restore_ratio"] for r in ioc_results if r["restore_ratio"] is not None]
    return {"run_id": run_id, "ioc_recall_100pct": all_full, "bm25_top10_ok": all_top10,
            "iocs": ioc_results, "text": text_results,
            "restore_ratio_max": max(ratios) if ratios else None,
            "restore_ratio_mean": round(sum(ratios) / len(ratios), 6) if ratios else None}


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("--run-id", default="demo")
    result = run(Settings.from_env(), p.parse_args().run_id)
    json.dump(result, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    sys.exit(0 if result["ioc_recall_100pct"] and result["bm25_top10_ok"] else 1)


if __name__ == "__main__":
    main()
