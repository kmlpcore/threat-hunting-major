"""One report for the M2 and M4 exit criteria on a running stack.

M2: summary-to-raw size ratio; policy version on every summary row.
M4: no raw partition reaches the archive unsealed (lifecycle rule is tag-filtered and a
    sample of unsealed objects is checked); feature builds/backfills read zero raw bytes.

    python -m benchmarks.milestone_report
"""
from __future__ import annotations

import json
import sys

from sqlalchemy import func, select

from engine.common.catalog import get_catalog, read_table, table_stats
from engine.common.config import Settings
from engine.common.db import make_engine, partitions, seal_manifest, stage_runs
from engine.common.storage import ObjectStore
from engine.summary.policy import load_policy
from engine.summary.tables import HIGH_VALUE, TABLES


def run(settings: Settings) -> dict:
    engine = make_engine(settings.database_url)
    store = ObjectStore.from_settings(settings)
    cat = get_catalog(settings)

    # ---- M2
    stats = [table_stats(cat, t.identifier) for t in TABLES.values()] + [table_stats(cat, HIGH_VALUE)]
    versions = set()
    for t in [*TABLES.values()]:
        tbl, _ = read_table(cat, t.identifier)
        if tbl.num_rows:
            versions |= set(tbl.column("policy_version").to_pylist())
    with engine.connect() as conn:
        raw_bytes, raw_rows, n_parts = conn.execute(
            select(func.sum(partitions.c.bytes), func.sum(partitions.c.rows), func.count())).one()
        sealed = conn.execute(select(func.count()).select_from(partitions).where(partitions.c.sealed.is_(True))).scalar()
        resealed = conn.execute(select(func.count()).select_from(seal_manifest)
                                .where(seal_manifest.c.seal_version > 1)).scalar()
        feature_runs = conn.execute(select(stage_runs).where(stage_runs.c.stage == "features")).all()
        unsealed = [r.partition_id for r in conn.execute(select(partitions.c.partition_id)
                                                         .where(partitions.c.sealed.is_(False)).limit(25))]
    summary_bytes = sum(s["bytes"] for s in stats)
    idx_objects, idx_bytes = store.total_size(settings.buckets.index)

    # ---- M4: lifecycle invariant
    rules = []
    if store.is_s3:
        rules = store._client().get_bucket_lifecycle_configuration(Bucket=settings.buckets.raw)["Rules"]
    tag_filtered = bool(rules) and all(
        r.get("Filter", {}).get("Tag", {}).get("Key") == "sealed" or
        any(t.get("Key") == "sealed" for t in r.get("Filter", {}).get("And", {}).get("Tags", []))
        for r in rules if r.get("Transitions"))
    violations = []
    for pid in unsealed:
        for f in store.list(f"{settings.buckets.raw}/{pid}", ".parquet"):
            if store.storage_class(f) != "STANDARD":
                violations.append(f)

    return {
        "M2": {
            "policy_version": load_policy().version,
            "policy_versions_on_rows": sorted(versions),
            "raw": {"rows": raw_rows, "bytes": raw_bytes, "partitions": n_parts},
            "summary": {"rows": sum(s["rows"] for s in stats), "bytes": summary_bytes,
                        "tables": {s["table"]: {"rows": s["rows"], "bytes": s["bytes"]} for s in stats}},
            "summary_to_raw_ratio": round(summary_bytes / raw_bytes, 4) if raw_bytes else None,
            "index_to_raw_ratio": round(idx_bytes / raw_bytes, 4) if raw_bytes else None,
        },
        "M4": {
            "partitions_sealed": f"{sealed}/{n_parts}",
            "partitions_resealed_after_late_data": resealed,
            "feature_builds": len(feature_runs),
            "feature_builds_raw_bytes_read": sum((r.detail or {}).get("raw_bytes_read", 0) for r in feature_runs),
            "lifecycle_rules": rules,
            "lifecycle_transitions_are_tag_filtered": tag_filtered,
            "unsealed_objects_checked": len(unsealed),
            "unsealed_objects_in_archive": violations,
        },
    }


def main() -> None:
    result = run(Settings.from_env())
    json.dump(result, sys.stdout, indent=2, default=str)
    sys.stdout.write("\n")
    m4 = result["M4"]
    ok = (result["M2"]["policy_versions_on_rows"] == [result["M2"]["policy_version"]]
          and m4["feature_builds_raw_bytes_read"] == 0 and not m4["unsealed_objects_in_archive"]
          and (m4["lifecycle_transitions_are_tag_filtered"] or not m4["lifecycle_rules"]))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
