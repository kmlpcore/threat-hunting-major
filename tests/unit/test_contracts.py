from sqlalchemy.dialects import postgresql
from sqlalchemy.schema import CreateTable

from engine.common.db import metadata
from engine.common.events import EVENT_TYPES, Envelope, PingRecorded, export_schemas
from engine.common.db import utcnow
from engine.cqrs.commands import COMMAND_TYPES, Ping


def test_postgres_ddl_compiles_for_every_table():
    for table in metadata.sorted_tables:
        ddl = str(CreateTable(table).compile(dialect=postgresql.dialect()))
        assert f"{table.schema}.{table.name}" in ddl


def test_envelope_roundtrip():
    env = Envelope.wrap(PingRecorded(message="x", recorded_at=utcnow()), command_id="c1")
    again = Envelope.model_validate(env.model_dump(mode="json"))
    assert again.unwrap() == env.unwrap()


def test_every_planned_event_is_defined():
    from engine.common.events import PLANNED_EVENT_TYPES
    assert PLANNED_EVENT_TYPES == ()
    assert {"RuleSubmitted", "RulePlanned", "RuleEvaluated", "RestoreRequested", "RunApproved",
            "BehaviorPatternRecorded", "PatternReviewed", "IndicatorRecorded", "FeedPulled", "StrategicRollupBuilt",
            "RetentionApplied", "TableCompacted"} <= set(EVENT_TYPES)


def test_event_schema_export(tmp_path):
    paths = export_schemas(tmp_path)
    assert len(paths) == len(EVENT_TYPES) + 1


def test_command_registry_and_idempotency_keys():
    assert set(COMMAND_TYPES) == {
        "Ping", "LoadInventory", "IngestBatch", "BuildSummaries", "BuildIndex", "RegisterFeature", "ExtractFeatures",
        "SealPartition", "SubmitRule", "ApproveRun", "ExecuteRule", "RecordRuleObservations", "EnrichBehavior",
        "ReviewPattern", "BuildStrategicRollup", "PullFeed", "RecordIndicator", "RecordFeedSightings",
        "ReleaseDeferred", "ApplyRetention", "CompactTable", "ReadabilityDrill", "SetLegalHold"}
    from engine.cqrs.commands import ApplyRetention, CompactTable
    assert ApplyRetention(layer="summary").target_queue() == "summary"     # maintenance stays single-writer
    assert CompactTable(table="ti.operational").target_queue() == "ti"
    assert Ping(nonce="n").idempotency_key() == Ping(nonce="n").idempotency_key()
    assert Ping().idempotency_key() != Ping().idempotency_key()
