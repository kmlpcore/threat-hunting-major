"""The three TI tables (plan.md section 3.10a) and their writers.

    ti.tactical     one row per indicator per source        (IOCs; feeds + internal discoveries)
    ti.operational  one row per behaviour observed in the org (rule hits, LLM patterns, feed matches)
    ti.strategic    one row per period x tactic x technique x asset class x business unit x family
    ti_staging.feed_raw   every feed payload exactly as received (replay / audit only)

Writes go through the `ti` command queue only (single writer). Upserts read the affected
keys, merge in Python and overwrite exactly those keys in one Iceberg commit.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from datetime import datetime, timezone

import pyarrow as pa
from pyiceberg.expressions import In

from engine.common.catalog import ensure_table, get_catalog

TACTICAL = "ti.tactical"
OPERATIONAL = "ti.operational"
STRATEGIC = "ti.strategic"
FEED_RAW = "ti_staging.feed_raw"

TS = pa.timestamp("us", tz="UTC")
LIST = pa.list_(pa.string())

TACTICAL_SCHEMA = pa.schema([
    ("indicator_id", pa.string()), ("type", pa.string()), ("value", pa.string()), ("source", pa.string()),
    ("source_ref", pa.string()), ("threat_type", pa.string()), ("malware_family", pa.string()),
    ("malware_aliases", LIST), ("attack_techniques", LIST), ("confidence", pa.int64()), ("tlp", pa.string()),
    ("first_seen", TS), ("last_seen", TS), ("expires_at", TS), ("org_sightings", pa.int64()),
    ("org_first_sighting", TS), ("org_last_sighting", TS), ("status", pa.string()), ("tags", LIST),
    ("reference", pa.string()), ("connector_version", pa.string()), ("ingested_at", TS),
])

OPERATIONAL_SCHEMA = pa.schema([
    ("observation_id", pa.string()), ("pattern_id", pa.string()), ("pattern_version", pa.string()),
    ("title", pa.string()), ("narrative", pa.string()), ("attack_tactics", LIST), ("attack_techniques", LIST),
    ("kill_chain_phase", pa.string()), ("threat_family", pa.string()), ("campaign_ref", pa.string()),
    ("matched_indicator_ids", LIST), ("rule_id", pa.string()), ("rule_version_hash", pa.string()),
    ("rule_run_id", pa.string()), ("entity_type", pa.string()), ("entity_pseudonym", pa.string()),
    ("asset_class", pa.string()), ("business_unit", pa.string()), ("severity", pa.string()),
    ("confidence", pa.int64()), ("first_seen", TS), ("last_seen", TS), ("observed_at", TS),
    ("evidence_refs", LIST), ("origin", pa.string()), ("llm_provider", pa.string()), ("llm_model", pa.string()),
    ("prompt_version", pa.string()), ("status", pa.string()), ("reviewed_by", pa.string()),
    ("recorded_at", TS), ("period_day", pa.string()),
])

STRATEGIC_SCHEMA = pa.schema([
    ("period_type", pa.string()), ("period_start", pa.string()), ("tactic", pa.string()),
    ("technique_id", pa.string()), ("threat_family", pa.string()), ("threat_type", pa.string()),
    ("asset_class", pa.string()), ("business_unit", pa.string()), ("observations", pa.int64()),
    ("distinct_entities", pa.int64()), ("distinct_patterns", pa.int64()), ("feed_indicator_hits", pa.int64()),
    ("delta_vs_prev_period", pa.int64()), ("delta_vs_same_period_last_year", pa.int64()),
    ("top_patterns", LIST), ("top_families", LIST), ("rollup_version", pa.string()), ("built_at", TS),
])

FEED_RAW_SCHEMA = pa.schema([
    ("connector", pa.string()), ("connector_version", pa.string()), ("pulled_at", TS), ("cursor", pa.string()),
    ("url", pa.string()), ("sha256", pa.string()), ("bytes", pa.int64()), ("records", pa.int64()),
    ("payload", pa.string()), ("day", pa.string()),
])

SCHEMAS = {TACTICAL: TACTICAL_SCHEMA, OPERATIONAL: OPERATIONAL_SCHEMA, STRATEGIC: STRATEGIC_SCHEMA,
           FEED_RAW: FEED_RAW_SCHEMA}
PARTITIONS = {TACTICAL: (), OPERATIONAL: (), STRATEGIC: ("period_type",), FEED_RAW: ("day",)}


def table(settings, name: str):
    return ensure_table(get_catalog(settings), name, SCHEMAS[name], partition_by=PARTITIONS[name])


def read_keys(settings, name: str, key: str, values: list[str]) -> list[dict]:
    if not values:
        return []
    t = table(settings, name)
    if t.current_snapshot() is None:
        return []
    return t.scan(row_filter=In(key, list(set(values)))).to_arrow().to_pylist()


def read_all(settings, name: str, snapshot_id: int | None = None) -> tuple[list[dict], int | None]:
    t = table(settings, name)
    snap = snapshot_id or (t.current_snapshot().snapshot_id if t.current_snapshot() else None)
    if snap is None:
        return [], None
    return t.scan(snapshot_id=snap).to_arrow().to_pylist(), snap


def upsert(settings, name: str, key: str, rows: list[dict]) -> int | None:
    """Replace every row whose `key` is among `rows`' keys with `rows` (one commit)."""
    if not rows:
        return None
    import warnings
    t = table(settings, name)
    data = pa.Table.from_pylist(rows, schema=SCHEMAS[name])
    keys = sorted({r[key] for r in rows})
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="Delete operation did not match any records")
        if t.current_snapshot() is None:
            t.append(data)
        else:
            t.overwrite(data, overwrite_filter=In(key, keys))
    t.refresh()
    return t.current_snapshot().snapshot_id


def replace_all(settings, name: str, rows: list[dict], **match) -> int | None:
    from engine.common.catalog import replace_rows
    t = table(settings, name)
    return replace_rows(t, pa.Table.from_pylist(rows, schema=SCHEMAS[name]), **match)


def append(settings, name: str, rows: list[dict]) -> int | None:
    if not rows:
        return None
    t = table(settings, name)
    t.append(pa.Table.from_pylist(rows, schema=SCHEMAS[name]))
    t.refresh()
    return t.current_snapshot().snapshot_id


# --------------------------------------------------------------------------- indicator normalisation
HASH_TYPES = {32: "md5", 40: "sha1", 64: "sha256"}


def refang(value: str) -> str:
    v = value.strip()
    v = re.sub(r"(?i)^hxxp", "http", v)
    return v.replace("[.]", ".").replace("(.)", ".").replace("[:]", ":").replace("[dot]", ".")


def detect_type(value: str) -> str | None:
    v = value.strip()
    try:
        ip = ipaddress.ip_address(v)
        return "ipv4" if ip.version == 4 else "ipv6"
    except ValueError:
        pass
    if re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}:\d{1,5}", v):
        return "ip:port"
    if re.fullmatch(r"[0-9a-fA-F]+", v) and len(v) in HASH_TYPES:
        return HASH_TYPES[len(v)]
    if re.match(r"(?i)^[a-z][a-z0-9+.-]*://", v):
        return "url"
    if re.fullmatch(r"(?i)[a-z0-9_-]+(\.[a-z0-9_-]+)+\.?", v):
        return "domain"
    return None


def normalise(type_: str, value: str) -> str:
    v = refang(value)
    if type_ in ("domain",):
        return v.lower().rstrip(".")
    if type_ in ("md5", "sha1", "sha256", "ja3"):
        return v.lower()
    if type_ == "url":
        scheme, rest = v.split("://", 1)
        host, _, path = rest.partition("/")
        return f"{scheme.lower()}://{host.lower()}/{path}" if path or rest.endswith("/") else f"{scheme.lower()}://{host.lower()}"
    if type_ in ("ipv4", "ipv6"):
        return str(ipaddress.ip_address(v))
    return v


def indicator_id(type_: str, value: str) -> str:
    return hashlib.sha256(f"{type_}\x1f{normalise(type_, value)}".encode()).hexdigest()[:24]


def sweep_values(type_: str, value: str) -> list[str]:
    """Values to look for in logs (an ip:port indicator is swept as its IP; a URL also by its host)."""
    v = normalise(type_, value)
    if type_ == "ip:port":
        return [v.rsplit(":", 1)[0]]
    if type_ == "url":
        host = v.split("://", 1)[1].split("/", 1)[0].split(":", 1)[0]
        return [host]
    return [v]


def now() -> datetime:
    return datetime.now(timezone.utc)
