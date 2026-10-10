# Artefact-based Retrospective Threat Hunting Engine

Cost-efficient retrospective threat hunting over archived security logs. The full design is in
[plan.md](plan.md) (v2.1).

**Status:** milestones **M0–M9** are implemented, plus the **v3** modern-feed connectors. Measured
results are in [docs/evaluation.md](docs/evaluation.md). The test suite has 64 tests passing, plus 1 E2E test
that is skipped unless `E2E=1`.

## What exists

| Milestone | Built |
|-----------|-------|
| M0 | Compose stack (MinIO with Object Lock, Postgres, Lakekeeper Iceberg REST catalog, Redis Streams); Postgres `meta` (write side) and `readmodel` (query side) schemas; versioned event contracts (`schemas/events/`); CQRS skeleton: command API → single-writer queues → transactional outbox → relay → event bus → projector → query API |
| M1 | Synthetic enterprise generator (8 native log formats) + 9 labelled attack scenarios; YAML-driven ECS normaliser; entity resolution (user aliases → SID, DHCP lease-based IP→host, static IPs, per-sensor clock-skew correction); raw landing as partitioned zstd Parquet; quarantine for invalid rows; ground truth stored outside the engine |
| M2–M4 | Drop/aggregate policy and Iceberg summary tables; bloom sidecars + Tantivy BM25/keyword index with `/ioc` and `/search`; versioned feature registry and artefacts built from summaries only; seal manager with a tag-gated archive lifecycle and a late-data reseal path; orchestrator (reconciler); dashboard |
| M5 | `engine/rules/`: pySigma compiler (ECS pipeline `rules/pipelines/ecs_custom.yaml`) → predicate IR → DuckDB SQL; capability catalog and **coverage planner** (tier 1 artefact dimensions, tier 2 high-value events / summary dimensions / summary correlation buckets, tier 3 index-pruned restore); cost estimator (`policies/pricing.yaml`) with dry run, **cost-based approval** (`policies/coverage_thresholds.yaml`) and a bytes safety cap; tiered executor with snapshot-pinned reads, snapshot leases, `results.rule_hits` / `results.rule_runs`, replays at pinned snapshots; calibration; a 19-rule Sigma corpus in `rules/sigma/` |
| M6 | `engine/ti/`: behaviour bundler with HMAC pseudonymisation and an egress audit log (`meta.llm_egress`); OpenAI-compatible LLM provider (Groq by default, model from config) plus an offline heuristic provider; validator (local ATT&CK STIX bundle, evidence references, confidence → status); `ti.tactical`, `ti.operational`, `ti.strategic` Iceberg tables; rule observations; analyst review; strategic rollups by week, month, quarter and year with YoY deltas |
| M7 | Connector SDK (`engine/ti/connectors/sdk.py`) and the legacy connectors: ThreatFox (API and export), URLhaus, MalwareBazaar, Feodo, SSLBL, CSV blocklists, MISP, STIX 1.x/TAXII 1.1, and the ATT&CK and CISA KEV reference feeds; warninglists; TLP on export and LLM egress; decay; a batched **IOC retro-sweep** for every new indicator (planned, estimated, approved like any rule); sightings → `org_sightings` + `feed_match` observations; a daily budget with deferral; the `ti-connectors` scheduler; analyst indicators |
| M8 | `policies/retention.yaml` (15-year floor enforced in code); retention enforcer per layer (legal holds, WORM-aware raw purge, which is a dry run by default); Iceberg tags for result snapshots + snapshot expiry; compaction; ECS mapping registry; keyword postings copied to `index.keyword_postings`; an **annual readability drill** that fails loudly; multi-year history generator (`cli history`) |
| M9 | `benchmarks/fidelity.py` (recall/precision against a full rehydration and against the labels), `benchmarks/cost.py` (cost model, break-even, storage, estimate accuracy, feed metrics), `benchmarks/report.py` → `docs/evaluation.md` |
| v3 | TAXII 2.1/STIX 2.1, AlienVault OTX, AbuseIPDB and push/webhook connectors (`POST /ti/push/{connector}` on the command API); connectors are discovered automatically, and a drop-in connector needs no changes outside `connectors/` (test-enforced) |

## M5–M9 results (compose stack, 2026-10-10)

From `make report` (full numbers in [docs/evaluation.md](docs/evaluation.md)). Costs are *modelled*: every prototype
byte stands for 100,000 bytes (≈ 0.4 TB/day of raw Parquet), priced with the AWS list prices in `policies/pricing.yaml`.

| Exit criterion / metric (plan.md 10–11) | Result |
|---|---|
| **M5** corpus runs; tiers, coverage %, bytes, estimated and actual cost per run; replays identical | ✅ 19/19 rules; replay `hits_hash` identical (test-enforced, and still identical after snapshot expiry) |
| Tier-hit rate ≥ 70 % | ✅ 73.7 % (2 tier-1, 12 tier-2, 5 tier-3) |
| Recall ≥ 0.95 at tier 1/2 vs full rehydration | ✅ 1.00 for every rule (entity × day; event level where the tier returns events) |
| Restore ratio ≤ 5 % for IOC sweeps | ✅ max 1.7 % (feed retro-sweeps: max 0.9 %) |
| Estimate error ≤ ±25 % after calibration | ✅ median 0 %, 95.6 % of runs within ±25 % |
| Approval | broad CIDR scan over 15 years estimated at 95.67 USD → waited for hunter approval; actual 77.84 USD |
| **M6** no identifiers in egress; invalid ATT&CK IDs rejected; `ti.strategic` shows planted tactics | ✅ test-enforced; every planted tactic present; offline provider maps 9/9 scenarios (a heuristic baseline that partly uses rule tags, not a real model) |
| **M7** planted ThreatFox IOC ingested → swept → `org_sightings`, `feed_match`, `ti.strategic` | ✅ 203.0.113.80:80 (Cobalt Strike) sighted; feed-to-sighting median 7.1 s; 0.10 USD per swept indicator |
| **M8** 15-year layout queryable; YoY strategic comparison | ✅ 2012–2026 sealed (2,237 partitions, 14.1-year span); YoY per tactic follows the history scenarios; readability drill OK, including restores from the archive tier |
| **M9** report | ✅ `docs/evaluation.md`; 5-year hunts: full rehydration 2,788 vs 1,055 USD per hunt, so derived-layer storage pays for itself at < 1 hunt per year |
| **v3** new connector without changes outside `connectors/` | ✅ test-enforced (`tests/integration/test_feeds_v3.py`) |

## Quick start

### With Docker (the target environment)

```bash
make up          # builds the engine image, starts everything, waits for health
make ping        # M0 exit check
make seed        # generate 7 days × 40 users and ingest (RUN_ID/DAYS/USERS overridable)
make check       # M1 exit checks: ECS validity + all ground-truth events landed
make hunt        # M5: plan, estimate and run the 19-rule Sigma corpus (rules/sigma/)
make feeds       # M7: pull every enabled TI feed (synthetic samples unless TI_FEEDS_OFFLINE=0)
make history     # M8: add one generated day per past year (15-year layout; takes a while)
make drill       # M8: readability drill over every retained year
make report      # M9: docs/evaluation.md + benchmarks/results/evaluation.json
```

Single commands: `docker compose run --rm cli hunt <rule.yml> --start 2026-09-07 --end 2026-09-14 [--dry-run]`,
`... cli approve <run_id> --role hunter|manager`, `... cli retention apply [--layer summary] [--as-of 2030-01-01]`.
The dashboard (http://localhost:8080) has pages for rules, costs, threat intel, feeds and retention.

LLM enrichment defaults to the **offline** heuristic provider, so nothing leaves the host. For Groq, set
`LLM_PROVIDER=groq`, `GROQ_API_KEY` and `LLM_MODEL` in `.env`; the model name is configuration and is never
hardcoded. Set `PSEUDONYMISATION_HMAC_KEY` outside dev.

On Windows without `make`, use the PowerShell equivalent with the same targets:
`.\scripts\dev.ps1 up`, `ping`, `seed`, `check`, `e2e`, `hunt`, `feeds`, `history`, `drill`, `report`. Docker Desktop on Windows 11 Home needs
**WSL 2** (`wsl --install` from an administrator terminal, then reboot).

APIs: command API `http://localhost:8000/docs`, query API `http://localhost:8001/docs`, MinIO console
`http://localhost:9001`, Lakekeeper `http://localhost:8181`.

### Without Docker (local mode)

The same code runs in-process with SQLite, an in-memory bus and the local filesystem (`./.local/`):

```bash
pip install -e ./engine[dev]
python -m engine.cli --local demo --days 7 --users 40
python -m benchmarks.ground_truth_check --run-id demo
python -m pytest
```

On Windows with a deep checkout path, set `ENGINE_TEST_TMP` to a short directory before running the
tests. The Hive-style partition paths can go past the 260-character `MAX_PATH`.

## Exit criteria

| Criterion (plan.md section 10) | Result |
|---|---|
| **M0** `make up` healthy | ✅ all 13 services healthy or completed; MinIO buckets with Object Lock on `raw`; Lakekeeper warehouse `threathunt` + 6 Iceberg namespaces; Postgres `meta`/`readmodel` schemas |
| **M0** no-op command → event → projected read-model row | ✅ on the compose stack (Postgres → Redis Streams), and in local mode: `Ping` → `PingRecorded` + `CommandCompleted` in the outbox → bus → `readmodel.pings` / `readmodel.command_status` → `GET /pings`, `GET /commands/{id}` (`tests/integration/test_cqrs.py`, and `ping` in the local demo) |
| **M1** 7 days × 5 sources generated | ✅ 7 days × **8** sources, 91,106 records for 40 users (seed 42), 56 batches → 766 partitions in MinIO |
| **M1** 100 % of rows ECS-valid | ✅ 91,106 / 91,106 rows pass an independent re-validation of every landed Parquet file in MinIO (`engine.cli ecs-check`); 0 quarantined |
| **M1** ground truth stored | ✅ `benchmarks/ground_truth/<run>/labels.json`: 9 scenarios, 1,032 labelled events, **all** found in `raw/` by `event.id` |

Also verified on the compose stack: raw files carry Object Lock retention and a delete is refused as
WORM-protected; re-submitting a whole ingest creates no new commands (idempotency keys); a second writer
replica acquires no queues (advisory locks); the test suite passes inside the engine container.

Entity resolution on that run: every network event got a host. Proxy and Zeek were resolved through DHCP
leases or static server IPs, with 0 unresolved. All Sysmon, proxy and CloudTrail users were resolved to
their SID.

## How it fits together

```
generator ─► incoming/<run>/source=…/date=…/batch.jsonl.gz   (native formats, sensor clock skew)
                         │
  CLI / anyone ─POST /commands/IngestBatch─► command-api ─► meta.commands (queue "raw")
                                                               │  writer (advisory lock = single writer)
                                         normalise → ECS → raw/source=…/date=…/hour=…/part-<batch>.parquet
                                         meta.batches / partitions / ip_leases  + outbox event   (one transaction)
                                                               │
                              outbox-relay ─► Redis Stream "events" ─► projector ─► readmodel.*  ─► query-api
```

* **Commands** (`engine/cqrs/commands.py`): `Ping`, `LoadInventory`, `IngestBatch`. Each names a writer
  queue and has an idempotency key. `IngestBatch` uses `ingest:<batch>:ecs=<mapping version>`, so a new
  mapping version can re-ingest the same batch, while a resubmission with the same version is deduplicated.
* **Events** (`engine/common/events.py`, JSON Schemas in `schemas/events/`): `CommandCompleted`,
  `CommandFailed`, `PingRecorded`, `InventoryLoaded`, `BatchNormalised`.
* **Read models** (`readmodel.*`): `command_status`, `pings`, `inventory`, `batch_status`,
  `partition_batches`, `partition_health`. Projections are built only from events and are idempotent per
  `event_id`. Every response carries `projected_at`.
* **Query API**: `/health`, `/commands/{id}`, `/pings`, `/inventory`, `/batches`, `/partitions`,
  `/partitions/summary`, `/partitions/{partition_id}/health`.

### ECS mappings

Each source has one versioned YAML file in `schemas/ecs/mappings/`. The field catalogue
`schemas/ecs/fields.yaml` defines the Parquet schema, the types, the required fields and the allowed
categorisation values, including the ECS `event.category` × `event.type` pairs. Adding a source means adding
a mapping file; no code changes are needed unless it needs a new transform.

| Source | Native format | Notable handling |
|---|---|---|
| `windows_security` | Windows event JSON | 4624/4625/4634/4672/4728/4732; overrides for Subject vs Target vs Member |
| `sysmon` | Sysmon EID 1 JSON | hashes parsed from `Hashes`; `DOMAIN\user` resolved |
| `zeek_conn`, `zeek_dns` | Zeek JSON | +2.5 s sensor skew corrected; host from DHCP lease; direction; DNS registered domain/subdomain |
| `proxy` | Squid text lines (regex) | −7 s skew corrected; URL parts; user `CORP\user` or bare |
| `cloudtrail` | CloudTrail JSON | IAM user or assumed-role session name → identity |
| `host_metrics` | agent JSON | `host.cpu.usage`, memory, network bytes (aggregated in M2, never dropped) |
| `dhcp` | Windows DHCP audit CSV | builds the time-bounded `meta.ip_leases` table |

### Scenarios (`scenarios/default.yaml`)

| ID | Type | ATT&CK |
|---|---|---|
| s01 | password spray | T1110.003 |
| s02 | brute force on WEB01 | T1110.001 |
| s03 | macro → encoded PowerShell cradle | T1059.001, T1027, T1566.001 |
| s04 | LOLBins (certutil, rundll32, mshta, bitsadmin), same victim as s03 | T1105, T1218.011, T1218.005, T1197 |
| s05 | PsExec-style lateral movement | T1021.002, T1569.002 |
| s06 | s03's victim added to Domain Admins by s05's actor | T1098, T1078.002 |
| s07 | DNS tunnelling over TXT | T1071.004, T1048.003 |
| s08 | night-time 2 GB exfiltration (s03's victim) | T1048, T1567.002 |
| s09 | cryptominer on APP01 (CPU metric + pool traffic) | T1496 |

Attacker infrastructure uses only RFC 5737 addresses and `.example` domains.

## Decisions made while building (not spelled out in plan.md)

1. **The write queue is the Postgres `meta.commands` table, not Redis.** A command is accepted if and only
   if its row commits, so there is no dual write between the database and a queue. A Postgres advisory lock
   per queue guarantees a single writer even with several writer replicas. Redis Streams carries events
   only.
2. **`event.id` is a hash of (source, native record)**, plus an occurrence index for byte-identical records.
   The generator uses the same function, which lets ground truth point at raw events without the engine
   ever reading labels.
3. **Flat dotted ECS column names in Parquet** (`"source.ip"`), not nested structs. This keeps DuckDB SQL and
   pySigma field mapping simple in M5.
4. **`event.original` is kept in raw.** Raw is the forensic layer, and the field is about half of raw's
   size. Derived layers will not carry it.
5. **Object Lock is GOVERNANCE / 1 day in the dev stack** so `make clean` works. COMPLIANCE for 15 years is
   M8.
6. **Dagster is not in the stack.** A reconciler loop (the `orchestrator` service) submits pipeline,
   rollup, retention and drill commands idempotently. Dagster could drive the same commands later.
7. **Sigma semantics drive the drop policy (M5).** High-value selection became case-insensitive (policy
   1.1.0). Sigma compares strings case-insensitively, so this is what lets the planner *prove* that every
   event a rule can match was retained. Coverage is proven per rule, never assumed.
8. **Tier-2 correlations are sound over-approximations.** Any sliding window of length T lies within
   ceil(T/bucket)+1 hourly or daily buckets, so bucket counts are upper bounds. They cannot miss an alert but
   can add candidates, and results say `exact: false`.
9. **`contains` is never an index anchor.** Substrings do not line up with index tokens, so only exact
   keyword equality prunes tier-3 restores. Rules without an exact anchor restore every object of their
   sources in range, and their cost (and approval) shows it.
10. **Archive retrieval is priced per object.** Deep-archive tiers restore whole objects, so a tier-3
    estimate is the size of every object the bloom filters + keyword index point at. It is computed from hot
    metadata only, never by touching the archive.
11. **Modelled costs.** Prototype bytes × `simulation.scale_factor`. `actual_cost` prices the measured
    quantities with the same table, and the calibrator learns actual/estimated byte ratios per tier.
12. **Maintenance stays single-writer.** `ApplyRetention` / `CompactTable` route to the queue that owns the
    tables they touch (`Command.target_queue()`). All `ti.*` writes go through the `ti` queue, owned by the
    `ti-enricher` service.

## Known gaps

* **MinIO images.** MinIO no longer publishes images on Docker Hub or Quay. The stack uses Chainguard's
  source-built `cgr.dev/chainguard/minio` and `minio-client`. Their free tier only tags `latest`, so the
  defaults are pinned by digest; override them with `MINIO_IMAGE` / `MC_IMAGE` in `.env`. Both images are
  shell-less, so `infra/minio/Dockerfile` wraps `mc` on Wolfi base for the init job, and the init job (not a
  healthcheck) waits for MinIO.
* **Lakekeeper is on `latest-main`.** Pin it with `LAKEKEEPER_IMAGE` in `.env` for reproducible builds.
* **Small-file overhead.** Hourly partitions per source at prototype volume give 766 files of a few hundred
  rows. Each file carries about 20 KB of footer for the 120-column schema, so raw (34 MB) is currently larger
  than the gzipped native input (3.6 MB). The same rows in a single file are about 3× smaller. This goes away
  at production volumes, and plan.md §12.2 already compacts before archiving.
* No GeoIP enrichment yet, so there is no `source.geo.*`.
* **Raw is not compacted before archiving.** plan.md §12.2 compacts to ≥ 128 MB objects. The cost model
  assumes that (requests are priced per 128 MB), but the prototype archives its small hourly files as they are.
* **Index size.** The index is about 58 % of raw at prototype volume (footer-dominated small files). It is
  the main reason for the derived-to-raw ratio of 0.66.
* **Object Lock is GOVERNANCE / 1 day in dev.** Production uses `RAW_LOCK_MODE=COMPLIANCE RAW_LOCK_PERIOD=15y`.
  The enforcer never deletes a raw object whose lock has not expired, and raw purges are dry runs by default.
* **LLM accuracy is measured with the offline heuristic**, which partly reuses the techniques of the rules
  that fired. A real model (Groq) has to be measured by setting `LLM_PROVIDER=groq`.
* **Correlation types.** `event_count` and `value_count` are supported. `temporal` /
  `temporal_ordered` are rejected at submit, and so is an IPv6 CIDR.
* **Live feeds are untested against the real services.** Connectors are verified against format-faithful
  synthetic samples and mocked HTTP. Real abuse.ch / MISP / TAXII endpoints need credentials and a
  licence check per deployment.
* A readability drill that runs while indexes are being rebuilt reports missing postings, which is
  correct at that moment. It passes once the rebuild finishes.

## Layout

```
docker-compose.yml  Makefile  .env.example  pytest.ini  plan.md
engine/        common/ (config, storage, db, events, bus, outbox, ids, catalog, pseudonymise)
               cqrs/ (commands, writer_queue, handlers, projectors, runtime)
               api/ (command_api, query_api, hunt_routes, rule_routes, ti_routes, dashboard)
               generator/ normaliser/ summary/ indexer/ features/ seal/ orchestrator/
               rules/ (compiler, capabilities, planner, tier3, executor, service)     cost/ (estimator, calibrate)
               ti/ (bundler, llm_provider, validator, tables, rollups, service, scheduler, attack, connectors/)
               retention/ (policy, enforcer)   dashboard/   cli.py   bootstrap.py
policies/      drop_policy, features, lifecycle, pricing, coverage_thresholds, llm_egress, ti_feeds,
               warninglists, retention (.yaml)
rules/         sigma/ (19-rule benchmark corpus), pipelines/ (pySigma ECS pipeline, logsources)
data/          attack/ (ATT&CK subset bundle), feeds/samples/ (synthetic feed samples)
schemas/       ecs/, events/ (exported JSON Schemas), llm/pattern_output.schema.json
scenarios/     default.yaml, history.yaml          scripts/  dev.ps1, build_attack_subset.py, build_feed_samples.py
benchmarks/    ground_truth_check, index_check, milestone_report, fidelity, cost, report, results/
infra/         postgres/init, minio/init.sh        tests/    unit, integration (M0-M8, v3), e2e
docs/          demo-script.md, evaluation.md
```
