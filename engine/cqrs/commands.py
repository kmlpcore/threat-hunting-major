"""Command contracts.

Each command names the writer queue that serialises it. One queue per write
target (later: one per Iceberg table) keeps commits single-writer.
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, Field


class Command(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command_type: ClassVar[str]
    queue: ClassVar[str]

    def idempotency_key(self) -> str:
        raise NotImplementedError

    def target_queue(self) -> str:
        """The writer queue this instance goes to (maintenance commands route to the queue that
        owns the tables they touch, keeping every table single-writer)."""
        return self.queue


class Ping(Command):
    """No-op command that exercises the whole CQRS loop (M0 exit criterion)."""
    command_type: ClassVar[str] = "Ping"
    queue: ClassVar[str] = "system"
    message: str = "ping"
    nonce: str | None = None

    def idempotency_key(self) -> str:
        return f"ping:{self.nonce or uuid.uuid4()}"


class LoadInventory(Command):
    """Load the identity directory and asset inventory used for entity resolution."""
    command_type: ClassVar[str] = "LoadInventory"
    queue: ClassVar[str] = "meta"
    uri: str  # <bucket>/<prefix>/ containing identities.json and assets.json
    version: str = "1"

    def idempotency_key(self) -> str:
        return f"inventory:{self.uri}:{self.version}"


class IngestBatch(Command):
    """Normalise one native-format batch to ECS and land it as raw Parquet."""
    command_type: ClassVar[str] = "IngestBatch"
    queue: ClassVar[str] = "raw"
    batch_id: str
    batch_uri: str
    source: str

    def idempotency_key(self) -> str:
        # (partition-set, stage, job_version): a new mapping version may re-ingest the same batch.
        from engine.normaliser.mapping import load_mapping
        return f"ingest:{self.batch_id}:ecs={load_mapping(self.source).version}"


class BuildSummaries(Command):
    """Raw ECS rows of one source-day -> Iceberg summary tables (M2). Queue = the summary tables' writer."""
    command_type: ClassVar[str] = "BuildSummaries"
    queue: ClassVar[str] = "summary"
    source: str
    day: str
    generation: str

    def idempotency_key(self) -> str:
        from engine.summary.policy import load_policy
        return f"summary:{self.source}:{self.day}:policy={load_policy().version}:gen={self.generation}"


class BuildIndex(Command):
    """Bloom sidecars + BM25/keyword index for one source-day (M3)."""
    command_type: ClassVar[str] = "BuildIndex"
    queue: ClassVar[str] = "index"
    source: str
    day: str
    generation: str

    def idempotency_key(self) -> str:
        from engine.indexer.fts_tantivy import INDEX_VERSION
        return f"index:{self.source}:{self.day}:v={INDEX_VERSION}:gen={self.generation}"


class RegisterFeature(Command):
    """Add a feature version (from policies/features.yaml) to the registry; triggers a backfill (M4)."""
    command_type: ClassVar[str] = "RegisterFeature"
    queue: ClassVar[str] = "features"
    feature: str
    version: str

    def idempotency_key(self) -> str:
        from engine.features.definitions import get_definition
        return f"register:{self.feature}@{self.version}:{get_definition(self.feature, self.version).definition_hash}"


class ExtractFeatures(Command):
    """Summary tables -> artefact rows for one feature version and day (M4). Never reads raw."""
    command_type: ClassVar[str] = "ExtractFeatures"
    queue: ClassVar[str] = "features"
    feature: str
    version: str
    day: str
    generation: str

    def idempotency_key(self) -> str:
        return f"features:{self.feature}@{self.version}:{self.day}:gen={self.generation}"


class SealPartition(Command):
    """Seal one hour partition: manifest + sealed=true tags that gate the archive lifecycle (M4)."""
    command_type: ClassVar[str] = "SealPartition"
    queue: ClassVar[str] = "seal"
    partition_id: str
    generation: str

    def idempotency_key(self) -> str:
        return f"seal:{self.partition_id}:gen={self.generation}"


class SubmitRule(Command):
    """Compile a Sigma rule, plan it across tiers and estimate its cost (M5). Unless `dry_run`,
    an auto-approved plan is queued for execution straight away; otherwise it waits for ApproveRun."""
    command_type: ClassVar[str] = "SubmitRule"
    queue: ClassVar[str] = "rules"
    rule_yaml: str
    start: datetime
    end: datetime
    run_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    dry_run: bool = False
    origin: str = "hunter"
    submitted_by: str = "hunter"
    replay_of: str | None = None           # re-run an earlier run at its pinned snapshots
    context: dict = Field(default_factory=dict)

    def idempotency_key(self) -> str:
        return f"rule-run:{self.run_id}"


class ApproveRun(Command):
    """Record an approval for a run above the auto-approve cost (M5)."""
    command_type: ClassVar[str] = "ApproveRun"
    queue: ClassVar[str] = "rules"
    run_id: str
    approver: str
    role: str = "hunter"                   # hunter | manager

    def idempotency_key(self) -> str:
        return f"approve:{self.run_id}:{self.approver}"


class ExecuteRule(Command):
    """Execute an approved plan at pinned snapshots and write results.* (M5)."""
    command_type: ClassVar[str] = "ExecuteRule"
    queue: ClassVar[str] = "results"
    run_id: str

    def idempotency_key(self) -> str:
        return f"execute:{self.run_id}"


class RecordRuleObservations(Command):
    """Rule hits of a run -> ti.operational (origin=rule) + indicator sightings (M6)."""
    command_type: ClassVar[str] = "RecordRuleObservations"
    queue: ClassVar[str] = "ti"
    run_id: str
    enrich: bool = True                    # queue EnrichBehavior afterwards when an LLM provider is set

    def idempotency_key(self) -> str:
        return f"ti-observations:{self.run_id}"


class EnrichBehavior(Command):
    """Bundle, redact and send a run's behaviour to the LLM provider; validate and store patterns (M6)."""
    command_type: ClassVar[str] = "EnrichBehavior"
    queue: ClassVar[str] = "ti"
    run_id: str
    nonce: str = ""                        # set to force a re-enrichment (identical bundles stay cached)

    def idempotency_key(self) -> str:
        return f"ti-enrich:{self.run_id}:{self.nonce}"


class ReviewPattern(Command):
    """Analyst verdict on one observation, or on every observation of a pattern (M6)."""
    command_type: ClassVar[str] = "ReviewPattern"
    queue: ClassVar[str] = "ti"
    target_id: str                         # observation_id or pattern_id
    verdict: str                           # validated | rejected
    reviewer: str

    def idempotency_key(self) -> str:
        return f"ti-review:{self.target_id}:{self.verdict}:{self.reviewer}"


class BuildStrategicRollup(Command):
    """Rebuild ti.strategic for one period type from ti.operational + ti.tactical (M6)."""
    command_type: ClassVar[str] = "BuildStrategicRollup"
    queue: ClassVar[str] = "ti"
    period_type: str                       # week | month | quarter | year
    input_snapshot: str = ""               # ti.operational snapshot that triggered it (idempotency)

    def idempotency_key(self) -> str:
        return f"ti-rollup:{self.period_type}:{self.input_snapshot or uuid.uuid4()}"


class PullFeed(Command):
    """Run one feed connector: fetch, parse, normalise, merge into ti.tactical, queue the retro-sweep (M7)."""
    command_type: ClassVar[str] = "PullFeed"
    queue: ClassVar[str] = "ti"
    connector: str
    since: str | None = None
    payload_uri: str | None = None         # pushed payload (POST /ti/push/{connector}) instead of a fetch
    slot: str = Field(default_factory=lambda: str(uuid.uuid4()))   # scheduler slot (idempotency)

    def idempotency_key(self) -> str:
        return f"feed:{self.connector}:{self.slot}"


class RecordIndicator(Command):
    """An analyst-supplied indicator; like a feed record it triggers a retro-sweep (M7)."""
    command_type: ClassVar[str] = "RecordIndicator"
    queue: ClassVar[str] = "ti"
    value: str
    type: str | None = None
    threat_type: str | None = None
    malware_family: str | None = None
    confidence: int = 75
    tlp: str = "TLP:AMBER"
    tags: list[str] = Field(default_factory=list)
    analyst: str = "analyst"

    def idempotency_key(self) -> str:
        return f"indicator:{self.analyst}:{self.type}:{self.value.strip().lower()}"


class RecordFeedSightings(Command):
    """Results of a feed retro-sweep -> org sightings in ti.tactical + ti.operational (origin=feed_match) (M7)."""
    command_type: ClassVar[str] = "RecordFeedSightings"
    queue: ClassVar[str] = "ti"
    run_id: str

    def idempotency_key(self) -> str:
        return f"ti-sightings:{self.run_id}"


class ReleaseDeferred(Command):
    """Queue budget-deferred feed sweeps that fit today's budget (M7)."""
    command_type: ClassVar[str] = "ReleaseDeferred"
    queue: ClassVar[str] = "rules"
    day: str

    def idempotency_key(self) -> str:
        return f"release-deferred:{self.day}"


LAYER_QUEUES = {"raw": "raw", "summary": "summary", "artefacts": "features", "results": "results",
                "index_keyword": "index", "index_text": "index", "ti_tactical": "ti", "ti_operational": "ti",
                "ti_strategic": "ti", "feed_raw": "ti"}
TABLE_QUEUES = {"summary": "summary", "artefacts": "features", "results": "results", "index": "index", "ti": "ti",
                "ti_staging": "ti"}


class ApplyRetention(Command):
    """Apply policies/retention.yaml to one layer: delete what is past retention (never what is
    under legal hold or WORM-locked), tag result-referenced snapshots and expire the rest (M8)."""
    command_type: ClassVar[str] = "ApplyRetention"
    queue: ClassVar[str] = "maintenance"
    layer: str
    dry_run: bool = False
    as_of: str | None = None               # ISO date to evaluate retention at (testing / simulation)
    slot: str = Field(default_factory=lambda: str(uuid.uuid4()))

    def idempotency_key(self) -> str:
        return f"retention:{self.layer}:{self.slot}"

    def target_queue(self) -> str:
        return LAYER_QUEUES.get(self.layer, "maintenance")


class CompactTable(Command):
    """Rewrite an Iceberg table's day partitions into one file each (fewer small files) (M8)."""
    command_type: ClassVar[str] = "CompactTable"
    queue: ClassVar[str] = "maintenance"
    table: str
    slot: str = Field(default_factory=lambda: str(uuid.uuid4()))

    def idempotency_key(self) -> str:
        return f"compact:{self.table}:{self.slot}"

    def target_queue(self) -> str:
        return TABLE_QUEUES.get(self.table.split(".", 1)[0], "maintenance")


class ReadabilityDrill(Command):
    """Read a sample of partitions from every retained year, including archive restores (M8)."""
    command_type: ClassVar[str] = "ReadabilityDrill"
    queue: ClassVar[str] = "maintenance"
    slot: str = Field(default_factory=lambda: str(uuid.uuid4()))
    partitions_per_year: int | None = None

    def idempotency_key(self) -> str:
        return f"readability:{self.slot}"


class SetLegalHold(Command):
    """Place or release a legal hold on raw partitions / derived days matching a prefix (M8)."""
    command_type: ClassVar[str] = "SetLegalHold"
    queue: ClassVar[str] = "raw"
    scope: str                             # partition prefix, e.g. "source=sysmon/date=2026-09-09"
    reason: str
    actor: str
    on: bool = True

    def idempotency_key(self) -> str:
        return f"legal-hold:{self.scope}:{self.on}:{self.actor}:{self.reason}"


COMMAND_TYPES: dict[str, type[Command]] = {c.command_type: c for c in (
    Ping, LoadInventory, IngestBatch, BuildSummaries, BuildIndex, RegisterFeature, ExtractFeatures, SealPartition,
    SubmitRule, ApproveRun, ExecuteRule, RecordRuleObservations, EnrichBehavior, ReviewPattern,
    BuildStrategicRollup, PullFeed, RecordIndicator, RecordFeedSightings, ReleaseDeferred, ApplyRetention,
    CompactTable, ReadabilityDrill, SetLegalHold)}
QUEUES = sorted({c.queue for c in COMMAND_TYPES.values()} | set(LAYER_QUEUES.values()))
