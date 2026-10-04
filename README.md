# Artefact-based Retrospective Threat Hunting Engine

Cost-efficient retrospective threat hunting over archived security logs. The full design is in
[plan.md](plan.md) (v2.1).

**Status:** milestones **M0 (Foundations)** and **M1 (Data in)** are implemented. M2 (summaries) onward is not started.

## What exists

| Milestone | Built |
|-----------|-------|
| M0 | Compose stack (MinIO with Object Lock, Postgres, Lakekeeper Iceberg REST catalog, Redis Streams); Postgres `meta` (write side) and `readmodel` (query side) schemas; versioned event contracts (`schemas/events/`); CQRS skeleton: command API → single-writer queues → transactional outbox → relay → event bus → projector → query API |
| M1 | Synthetic enterprise generator (8 native log formats) + 9 labelled attack scenarios; YAML-driven ECS normaliser; entity resolution (user aliases → SID, DHCP lease-based IP→host, static IPs, per-sensor clock-skew correction); raw landing as partitioned zstd Parquet; quarantine for invalid rows; ground truth stored outside the engine |

## Quick start

### With Docker (the target environment)

```bash
make up          # builds the engine image, starts everything, waits for health
make ping        # M0 exit check
make seed        # generate 7 days × 40 users and ingest (RUN_ID/DAYS/USERS overridable)
make check       # M1 exit checks: ECS validity + all ground-truth events landed
```

On Windows without `make`, use the PowerShell equivalent with the same targets:
`.\scripts\dev.ps1 up`, `ping`, `seed`, `check`, `e2e`. Docker Desktop on Windows 11 Home needs
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
6. **Dagster is not in the stack yet.** M0/M1 don't need orchestration (the CLI submits commands). It arrives
   with M2, when partitioned assets start to matter.

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
* No GeoIP enrichment yet, so there is no `source.geo.*`. `summary.user_daily` "geos" (M2) will need it.
* Late data and sealing (M4): a batch that lands in an existing partition adds a new
  `part-<batch>.parquet`. Seal checks don't exist yet.

## Layout

```
docker-compose.yml  Makefile  .env.example  pytest.ini  plan.md
engine/        common/ (config, storage, db, events, bus, outbox, ids, catalog)
               cqrs/ (commands, writer_queue, handlers, projectors, runtime)
               api/ (command_api, query_api)   generator/   normaliser/   cli.py   bootstrap.py
schemas/ecs/   fields.yaml + mappings/*.yaml          schemas/events/  exported JSON Schemas
scenarios/     default.yaml                           benchmarks/      ground_truth_check.py, ground_truth/
infra/         postgres/init, minio/init.sh           tests/           unit, integration, e2e
```
