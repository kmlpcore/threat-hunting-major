"""Command contracts.

Each command names the writer queue that serialises it. One queue per write
target (later: one per Iceberg table) keeps commits single-writer.
"""
from __future__ import annotations

import uuid
from typing import ClassVar

from pydantic import BaseModel, ConfigDict


class Command(BaseModel):
    model_config = ConfigDict(extra="forbid")
    command_type: ClassVar[str]
    queue: ClassVar[str]

    def idempotency_key(self) -> str:
        raise NotImplementedError


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


COMMAND_TYPES: dict[str, type[Command]] = {c.command_type: c for c in (
    Ping, LoadInventory, IngestBatch, BuildSummaries, BuildIndex, RegisterFeature, ExtractFeatures, SealPartition)}
QUEUES = sorted({c.queue for c in COMMAND_TYPES.values()})
