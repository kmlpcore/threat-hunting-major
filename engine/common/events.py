"""Domain event contracts.

Every event travels inside an Envelope. Payload models are versioned
(`event_version`); JSON Schemas are exported to schemas/events/ with
`python -m engine.common.events export`.
"""
from __future__ import annotations

import json
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict, Field

from engine.common.db import utcnow


class Event(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_type: ClassVar[str]
    event_version: ClassVar[int] = 1


class Envelope(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    event_type: str
    event_version: int
    occurred_at: datetime = Field(default_factory=utcnow)
    command_id: str | None = None
    payload: dict[str, Any]

    @classmethod
    def wrap(cls, event: Event, command_id: str | None = None) -> "Envelope":
        return cls(event_type=event.event_type, event_version=event.event_version, command_id=command_id,
                   payload=event.model_dump(mode="json"))

    def unwrap(self) -> Event:
        return EVENT_TYPES[self.event_type].model_validate(self.payload)


# --------------------------------------------------------------------------- M0: CQRS plumbing
class CommandCompleted(Event):
    event_type: ClassVar[str] = "CommandCompleted"
    command_id: str
    command_type: str
    attempts: int
    detail: dict[str, Any] = {}


class CommandFailed(Event):
    event_type: ClassVar[str] = "CommandFailed"
    command_id: str
    command_type: str
    attempts: int
    error: str
    will_retry: bool


class PingRecorded(Event):
    event_type: ClassVar[str] = "PingRecorded"
    message: str
    recorded_at: datetime


# --------------------------------------------------------------------------- M1: data in
class InventoryLoaded(Event):
    event_type: ClassVar[str] = "InventoryLoaded"
    uri: str
    identities: int
    aliases: int
    assets: int
    static_leases: int


class PartitionWrite(BaseModel):
    model_config = ConfigDict(extra="forbid")
    partition_id: str
    source: str
    date: str
    hour: str
    file: str
    rows: int
    bytes: int
    min_ts: datetime
    max_ts: datetime


class BatchNormalised(Event):
    event_type: ClassVar[str] = "BatchNormalised"
    batch_id: str
    source: str
    batch_uri: str
    ecs_mapping_version: str
    rows_in: int
    rows_out: int
    rows_invalid: int
    quarantine_uri: str | None
    leases_recorded: int = 0
    resolution: dict[str, int] = {}
    partitions: list[PartitionWrite]
    late_partitions: list[str] = []      # partitions that were already sealed (late data, reseal follows)


# --------------------------------------------------------------------------- M2-M4
class SummariesBuilt(Event):
    event_type: ClassVar[str] = "SummariesBuilt"
    source: str
    day: str
    generation: str
    policy_version: str
    action: str
    raw_rows: int
    raw_bytes: int
    partitions: list[str]
    tables: dict[str, dict[str, Any]]


class IndexBuilt(Event):
    event_type: ClassVar[str] = "IndexBuilt"
    source: str
    day: str
    generation: str
    index_version: str
    docs: int
    index_bytes: int
    bloom_filters: int
    partitions: list[str]


class FeatureRegistered(Event):
    event_type: ClassVar[str] = "FeatureRegistered"
    feature: str
    version: str
    definition_hash: str
    inputs: list[str]
    output_table: str
    window_days: int
    newly_registered: bool


class ArtefactsBuilt(Event):
    event_type: ClassVar[str] = "ArtefactsBuilt"
    feature: str
    version: str
    day: str
    generation: str
    rows: int
    output_table: str
    snapshot_id: int | None
    input_snapshots: dict[str, int | None]
    input_bytes: int
    raw_bytes_read: int
    input_sources: list[str]


class PartitionSealed(Event):
    event_type: ClassVar[str] = "PartitionSealed"
    partition_id: str
    source: str
    day: str
    seal_version: int
    generation: str
    rows: int
    files: list[dict[str, Any]]
    job_versions: dict[str, Any]
    snapshot_ids: dict[str, Any]


EVENT_TYPES: dict[str, type[Event]] = {
    cls.event_type: cls
    for cls in (CommandCompleted, CommandFailed, PingRecorded, InventoryLoaded, BatchNormalised, SummariesBuilt,
                IndexBuilt, FeatureRegistered, ArtefactsBuilt, PartitionSealed)
}

# Events named in plan.md section 4.4 that later milestones will define.
PLANNED_EVENT_TYPES = (
    "RuleSubmitted", "RulePlanned", "RuleEvaluated", "RestoreRequested", "BehaviorPatternRecorded", "PatternReviewed",
    "IndicatorRecorded", "FeedPulled", "StrategicRollupBuilt", "RunApproved", "RetentionApplied", "TableCompacted",
)


def export_schemas(out_dir: Path) -> list[Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    envelope = out_dir / "Envelope.schema.json"
    envelope.write_text(json.dumps(Envelope.model_json_schema(), indent=2) + "\n", encoding="utf-8")
    written.append(envelope)
    for name, cls in sorted(EVENT_TYPES.items()):
        schema = cls.model_json_schema()
        schema["x-event-type"] = name
        schema["x-event-version"] = cls.event_version
        path = out_dir / f"{name}.v{cls.event_version}.schema.json"
        path.write_text(json.dumps(schema, indent=2) + "\n", encoding="utf-8")
        written.append(path)
    return written


if __name__ == "__main__":
    if sys.argv[1:2] == ["export"]:
        from engine.common.config import REPO_ROOT
        for p in export_schemas(Path(sys.argv[2]) if len(sys.argv) > 2 else REPO_ROOT / "schemas" / "events"):
            print(p)
    else:
        print("usage: python -m engine.common.events export [out_dir]")
