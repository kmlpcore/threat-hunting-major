# Demo script: Artefact-based Retrospective Threat Hunting Engine (M0–M9)

A 12–15 minute walkthrough of the working prototype. Everything runs locally with
`docker compose`; the main screen is the dashboard at **http://localhost:8080**.

---

## 0. Before the audience arrives (5 min)

```powershell
.\scripts\dev.ps1 up            # 17 services (14 long-running + 3 init jobs), waits until healthy
.\scripts\dev.ps1 seed          # 7 days x 40 users, 8 log sources, 9 planted attacks
```

Then wait about 5 minutes. The **orchestrator** does the rest by itself: it summarises,
indexes, builds artefacts and seals every partition. It's done when the Overview shows
**Sealed 100%**.

Open these tabs in this order:

1. Dashboard, at http://localhost:8080
2. MinIO console, at http://localhost:9001. The user is `engine-minio`; the password is
   `MINIO_ROOT_PASSWORD` in `.env`. Click the licence acknowledgement once.
3. Lakekeeper (Iceberg catalog), at http://localhost:8181/ui/
4. Query API docs, at http://localhost:8001/docs

If something looks stuck: `.\scripts\dev.ps1 logs`, or the **Activity** page.

---

## 1. The problem (1 min, no screen needed)

- Security teams must keep years of logs. Once logs are archived, they're cheap to store
  but expensive to search.
- A new detection rule, or a new threat-intel indicator, means **rehydrating** the
  archive: restoring terabytes, paying retrieval fees and waiting hours.
- Our idea: do the expensive work **once**, before the data goes cold. That means
  summaries, an index and versioned "artefacts". Later hunts then touch raw data as
  little as possible, and the system **knows** when it has to.

## 2. Overview page: the whole pipeline (2 min)

Point at the KPI row:

| Tile | What to say |
|---|---|
| Raw events: 91,106 | 7 days, 40 users, 47 hosts, 8 native log formats (Windows, Sysmon, Zeek, Squid, CloudTrail, DHCP, metrics) |
| Summary / raw: ~6.5% | All the summary tables together are about 1/15 of the raw size |
| Sealed: 100% | Every hour partition has passed the seal checks and may move to the archive |

Then walk the **Architecture** strip left to right (M0 to M4), and the **Pipeline by source**
bars. Mention the **Live activity** feed: every box in the strip emits domain events, and
the dashboard reads only projections of them (that's CQRS).

## 3. Hunt page: the headline result (4 min)

1. Click the chip **`198.51.100.77`** (the cryptomining pool). Read the funnel aloud:

   > "766 hour partitions are in range. The bloom filters (which live in the hot tier)
   > rule out about 92% of them without touching raw. We open 19 index segments, find
   > 31 events, and restore only the row groups that hold them: about **0.5 MB instead of
   > 25 MB**, roughly 2% of a full rehydration."

2. Click a result row. That's the full ECS event, restored from the raw Parquet row
   group listed under `_address`.
3. Click **`203.0.113.66`** (the brute-force source): 301 events.
4. Switch to free text. Click **`powershell enc hidden bypass`**. The planted encoded
   PowerShell download cradle is result **#1**, ranked by BM25. Then try
   **`xmrig stratum donate`** and **`certutil urlcache split`**.

**Proof point:** `benchmarks.index_check` compares every planted indicator against a
brute-force scan of *all* raw data. Recall is **100%** for all 12 indicators, every BM25
query ranks the attack first, and the worst-case restore ratio is **0.55%** (the target
was ≤ 5%).

## 4. Partitions page (1 min)

- The heatmap shows one cell per source per hour (7 days × 24 hours). Green means sealed.
- Click any cell. You get the partition's stages plus its **seal manifest**: files, row
  counts, the job versions it was built with, and the Iceberg snapshot IDs. These make
  any later result reproducible.

## 5. Storage and Summaries pages (1 min)

- Storage compares bytes per layer: native gzip, raw Parquet, summaries, artefacts and
  index.
- Summaries lists 9 Iceberg tables, each built by the versioned **drop/aggregate policy**
  (`policies/drop_policy.yaml`). Open `metrics_hourly`: metrics are *aggregated, never
  dropped*, which is how cryptomining becomes visible.
- Every row carries `policy_version`, and every read shows the snapshot ID it was pinned to.

## 6. Artefacts page: versioned features, no raw access (2 min)

1. Seven feature versions are registered. Each card shows **`raw bytes read: 0`**.
2. The **candidates** table at the bottom (v2) is the prefilter. It surfaces most of the
   planted attacks: the password-spray source, the brute-forced user, the DNS tunnel host
   (entropy 4.6), the 2 GB upload, certutil/mshta/xmrig as rare processes, and sustained
   CPU on APP01.
   - Say clearly: *candidates are a prefilter, never the source of truth.*
3. Versioning story: v1 of candidates was noisy (52 rows). Versions are immutable, so we
   added v2 (17 rows), and the orchestrator backfilled it from summaries in about 20 seconds.
4. **Live moment:** on `dns_beaconing@1`, click **Activate & backfill**. Within about
   30 seconds its progress bar fills, day by day, with `raw bytes read: 0`. Click
   **Browse**: `app01 → 198.51.100.77:3333`, the mining pool, found by a feature that
   didn't exist when the data was archived.

## 7. Sealing & archive page (2 min)

1. Click **Run spot check**. It shows the raw bucket's real lifecycle rule:
   `Filter: Tag sealed=true → transition to ARCHIVE`. The archive is a second MinIO
   standing in for deep archive.
   - Say: *the rule matches only tagged objects, and only the seal manager sets the tag.
     So an unsealed partition structurally cannot reach the archive.*
     `unsealed objects in archive: 0`.
2. **Late data, live.** In a terminal:

   ```powershell
   docker compose run --rm --no-deps cli late-data
   ```

   This lands one record in an hour that is already sealed (and WORM-locked). Within about
   40 seconds, the partition `source=host_metrics/date=2026-09-09/hour=10` shows **seal v2**
   with 2 files, one of them marked late. The sealed file was never modified.
3. In the MinIO console, open `raw/` and show **Object Lock** (retention) on a file. Then
   show that `incoming/` holds the native logs and `index/` holds the bloom bundles and
   BM25 segments.

## 8. Under the hood: CQRS (optional, 1 min)

- On the Activity page, send a **Ping**. It goes command API → single-writer queue
  (Postgres) → transactional outbox → Redis Streams → projector → query API, and appears
  in the feed.
- Lakekeeper UI: the `threathunt` warehouse with `summary.*` and `artefacts.*` tables.
- Query API docs: every read endpoint, including `/ioc`, `/search` and `/storage`.

## 9. Close (30 s)

| Milestone | Exit criterion | Result |
|---|---|---|
| M0 | Stack healthy; no-op command → event → read model | ✅ 17 services (14 long-running + 3 init jobs); ping round trip in under 100 ms |
| M1 | 7 days × 5 sources; 100% ECS-valid; ground truth | ✅ 8 sources, 91,106 / 91,106 valid, 1,032 labelled events all landed |
| M2 | Summary-to-raw ratio reported; policy version on every row | ✅ 6.5%; `policy_version` 1.0.0 on every row |
| M3 | Planted IOCs at 100% recall; BM25 top 10 contains attacks | ✅ 12/12 at 100%; 5/5 ranked #1; restore ≤ 0.55% |
| M4 | Nothing archived unsealed; backfill touches no raw | ✅ tag-gated rule, 0 violations; 7 feature versions × 7 days, 0 raw bytes |

M5–M9 continue in section 10 below.

---

## Commands to verify the numbers yourself

```powershell
docker compose run --rm --no-deps --entrypoint python cli -m benchmarks.milestone_report   # M2 + M4
docker compose run --rm --no-deps --entrypoint python cli -m benchmarks.index_check        # M3
docker compose run --rm --no-deps --entrypoint python cli -m benchmarks.ground_truth_check # M1
.\scripts\dev.ps1 test                                                                     # 64 tests (+1 E2E, skipped unless E2E=1)
```

---

## 10. M5–M9 walkthrough (8–10 min)

Before the audience arrives, also run `.\scripts\dev.ps1 history` (15-year layout) and
`.\scripts\dev.ps1 report`. Each takes a while.

1. **Rules (M5).** Open the **Rules** page and pick `win_encoded_powershell.yml`, then click **Dry run**. The plan
   reads *tier 2, high-value events, coverage 100%, auto-approved*: the planner proved that every event the rule
   can match is retained in `summary.high_value_events`. Then pick `ecs_documentation_range_traffic.yml`
   (a CIDR over every source) and run it. It has no exact index anchor, so the estimate is a full restore,
   about 60 USD at modelled scale for the 7-day range, and the run waits for **hunter approval**. Approve it in the drawer.
2. **Costs.** Estimated vs actual per run, with the median error after calibration (about 0%).
3. **Threat intel (M6).** `ti.strategic` per tactic and year: 2012–2026, with the YoY delta in each cell's tooltip.
   Open a pattern: LLM output is advisory; validate or reject it.
4. **Feeds (M7).** Every connector with its last pull. The ThreatFox row shows that new indicators queued a
   retro-sweep. In `ti.tactical`, `203.0.113.80:80` (Cobalt Strike) has `org_sightings` > 0, while the decoys
   have 0 and `1.1.1.1` is `false_positive` (warninglist). Record an analyst indicator, e.g. `203.0.113.66`,
   and watch its sightings appear.
5. **Retention (M8).** 15 years minimum per layer, partitions per year 2012–2026, and the last readability drill
   (it read archived objects back through the archive tier). Run the drill live.
6. **Evaluation (M9).** Open `docs/evaluation.md`. Every target in plan.md section 11 is met: tier-hit 73.7%,
   recall 1.0, IOC restore ratio ≤ 1.7%, estimate error 0% median. For 5-year hunts, full rehydration costs
   2,788 USD per hunt and this design 1,055 USD.

| Milestone | Exit criterion | Result |
|---|---|---|
| M5 | Corpus runs with tiers, coverage, bytes, est./actual cost; pinned reruns identical | ✅ 19/19, replays identical |
| M6 | No identifiers in egress; invalid ATT&CK IDs rejected; strategic shows planted tactics | ✅ test-enforced |
| M7 | Planted ThreatFox IOC → sweep → org_sightings / feed_match / strategic | ✅ 7 s feed-to-sighting |
| M8 | 15-year layout queryable; YoY comparison | ✅ 2012–2026, 2,237 partitions |
| M9 | Evaluation report | ✅ docs/evaluation.md |

```powershell
.\scripts\dev.ps1 test      # 64 tests (+1 E2E, skipped unless E2E=1)
.\scripts\dev.ps1 report    # regenerates docs/evaluation.md
```
