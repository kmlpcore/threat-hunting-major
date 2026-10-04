"""Declarative source → ECS mappings (schemas/ecs/mappings/<source>.yaml).

A mapping turns one native record into a flat dict of ECS fields. Value specs:

    "Path.To.Field"                       read a field (literal key first, then nested path)
    {const: value}                        constant
    {from: path, transform: t | [t..], map: {...}, default: x, null_if: [...]}
    {template: "{A} {B}"}                 format string over native fields
    [spec, spec, ...]                     first non-null (coalesce)

`overrides` apply extra field/entity specs when a native field matches a value
(e.g. Windows group-membership events put the actor in Subject* fields).
"""
from __future__ import annotations

import csv
import io
import ipaddress
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from typing import Any, Callable

import yaml

from engine.common.config import REPO_ROOT

MAPPINGS_DIR = REPO_ROOT / "schemas" / "ecs" / "mappings"
_MISSING = object()


# --------------------------------------------------------------------------- transforms
def _hostname(v: str) -> str:
    v = str(v).strip().lower()
    return v if _is_ip(v) else v.split(".", 1)[0]


def _is_ip(v: str) -> bool:
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        return False


def _basename(v: str) -> str:
    return re.split(r"[\\/]", str(v))[-1]


def _hash_from(algo: str) -> Callable[[str], str | None]:
    def f(v: str) -> str | None:
        m = re.search(rf"(?:^|,){algo}=([0-9A-Fa-f]+)", str(v))
        return m.group(1).lower() if m else None
    return f


def _dn_cn(v: str) -> str:
    m = re.match(r"\s*CN=([^,]+)", str(v), re.I)
    return m.group(1) if m else str(v)


def _arn_principal(v: str) -> str | None:
    # arn:aws:iam::123:user/alice  |  arn:aws:sts::123:assumed-role/Role/alice
    tail = str(v).rsplit(":", 1)[-1]
    return tail.rsplit("/", 1)[-1] if "/" in tail else None


def _mac(v: str) -> str:
    raw = re.sub(r"[^0-9A-Fa-f]", "", str(v)).upper()
    return "-".join(raw[i:i + 2] for i in range(0, len(raw), 2)) if len(raw) == 12 else str(v)


TRANSFORMS: dict[str, Callable[[Any], Any]] = {
    "lower": lambda v: str(v).lower(),
    "upper": lambda v: str(v).upper(),
    "str": str,
    "int": lambda v: int(float(v)),
    "float": float,
    "hostname": _hostname,
    "basename": _basename,
    "sha256_from_hashes": _hash_from("SHA256"),
    "md5_from_hashes": _hash_from("MD5"),
    "dn_cn": _dn_cn,
    "arn_principal_name": _arn_principal,
    "pct_to_ratio": lambda v: round(float(v) / 100.0, 6),
    "mac": _mac,
    "strip": lambda v: str(v).strip(),
    "first": lambda v: v[0] if isinstance(v, list) and v else v,
    "split_comma": lambda v: [p for p in str(v).split(",") if p],
    "seconds_to_ns": lambda v: int(float(v) * 1e9),
    "ms_to_ns": lambda v: int(float(v) * 1e6),
    "ips_only": lambda v: [a for a in (v if isinstance(v, list) else [v]) if _is_ip(str(a))],
    "http_outcome": lambda v: "success" if int(v) < 400 else "failure",
    "first_label": lambda v: str(v).split(".", 1)[0],
}


# --------------------------------------------------------------------------- derivations
_MULTI_PART_SUFFIXES = {"co.uk", "org.uk", "ac.uk", "com.au", "net.au", "co.in", "co.jp", "com.br", "co.nz",
                        "com.cn", "com.sg"}


def registered_domain(name: str | None) -> str | None:
    if not name:
        return None
    labels = name.strip(".").lower().split(".")
    if len(labels) < 2 or _is_ip(name):
        return None
    n = 3 if ".".join(labels[-2:]) in _MULTI_PART_SUFFIXES and len(labels) >= 3 else 2
    return ".".join(labels[-n:])


def _derive_url_parts(row: dict, d: dict) -> None:
    from urllib.parse import urlsplit
    url = row.get(d["from"])
    if not url:
        return
    try:
        parts = urlsplit(url)
        port = parts.port
    except ValueError:
        return
    row.setdefault("url.scheme", parts.scheme or None)
    row.setdefault("url.domain", (parts.hostname or "").lower() or None)
    row.setdefault("url.port", port)
    row.setdefault("url.path", parts.path or None)
    row.setdefault("url.query", parts.query or None)
    row.setdefault("url.registered_domain", registered_domain(parts.hostname))


def _derive_dns(row: dict, d: dict) -> None:
    name = (row.get(d["from"]) or "").strip(".").lower()
    if not name:
        return
    reg = registered_domain(name)
    row["dns.question.registered_domain"] = reg
    if reg and name != reg and name.endswith("." + reg):
        row["dns.question.subdomain"] = name[: -len(reg) - 1]


@dataclass(frozen=True)
class NetworkConfig:
    internal: tuple[ipaddress._BaseNetwork, ...]

    def is_internal(self, ip: str | None) -> bool | None:
        if not ip:
            return None
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            return None
        return any(addr in net for net in self.internal)


@lru_cache
def network_config() -> NetworkConfig:
    spec = yaml.safe_load((MAPPINGS_DIR / "_common.yaml").read_text())
    return NetworkConfig(tuple(ipaddress.ip_network(n) for n in spec["internal_networks"]))


def _derive_direction(row: dict, _d: dict) -> None:
    net = network_config()
    s, d = net.is_internal(row.get("source.ip")), net.is_internal(row.get("destination.ip"))
    if s is None or d is None:
        return
    row["network.direction"] = {(True, True): "internal", (True, False): "outbound",
                                (False, True): "inbound", (False, False): "external"}[(s, d)]


def _derive_copy(row: dict, d: dict) -> None:
    if row.get(d["from"]) is not None and row.get(d["to"]) is None:
        row[d["to"]] = row[d["from"]]


def _derive_network_bytes(row: dict, _d: dict) -> None:
    sb, db = row.get("source.bytes"), row.get("destination.bytes")
    if sb is not None or db is not None:
        row["network.bytes"] = int(sb or 0) + int(db or 0)


DERIVATIONS: dict[str, Callable[[dict, dict], None]] = {
    "copy": _derive_copy,
    "url_parts": _derive_url_parts,
    "dns_parts": _derive_dns,
    "network_direction": _derive_direction,
    "network_bytes": _derive_network_bytes,
}


# --------------------------------------------------------------------------- mapping model
def lookup(record: dict, path: str):
    if path in record:
        return record[path]
    cur: Any = record
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return _MISSING
    return cur


def _null(v) -> bool:
    return v is _MISSING or v is None or v == "" or v == []


def eval_spec(spec, record: dict):
    """Evaluate a value spec against a native record. Returns None when absent."""
    if spec is None:
        return None
    if isinstance(spec, str):
        v = lookup(record, spec)
        return None if _null(v) else v
    if isinstance(spec, list):
        for s in spec:
            v = eval_spec(s, record)
            if not _null(v):
                return v
        return None
    if "const" in spec:
        return spec["const"]
    if "template" in spec:
        try:
            return spec["template"].format_map(_TemplateRecord(record))
        except KeyError:
            return None
    v = lookup(record, spec["from"])
    if not _null(v) and str(v) in {str(x) for x in spec.get("null_if", [])}:
        v = _MISSING
    if not _null(v) and "map" in spec:
        table = {str(k): val for k, val in spec["map"].items()}
        v = table.get(str(v), spec.get("map_default", _MISSING))
    if not _null(v):
        transforms = spec.get("transform", [])
        for t in [transforms] if isinstance(transforms, str) else transforms:
            v = TRANSFORMS[t](v)
            if _null(v):
                break
    if _null(v):
        return spec.get("default")
    return v


class _TemplateRecord(dict):
    def __init__(self, record: dict):
        super().__init__()
        self.record = record

    def __missing__(self, key):
        v = lookup(self.record, key)
        if v is _MISSING:
            raise KeyError(key)
        return v


@dataclass
class Override:
    when: dict[str, set[str]]
    fields: dict[str, Any]
    entities: dict[str, Any]
    drop: list[str]

    def matches(self, record: dict) -> bool:
        return all(str(eval_spec(path, record)) in values for path, values in self.when.items())


@dataclass
class Mapping:
    source: str
    version: str
    dataset: str
    format: str
    timestamp: dict
    clock_skew_seconds: float
    static: dict[str, Any]
    fields: dict[str, Any]
    entities: dict[str, Any]
    derive: list[dict]
    overrides: list[Override] = field(default_factory=list)
    parse: dict = field(default_factory=dict)
    options: dict = field(default_factory=dict)

    # -- parsing of line-oriented sources -----------------------------------
    def parse_record(self, record: dict) -> dict | None:
        if self.format == "json":
            return record
        line = record.get("message", "")
        if self.format == "regex":
            m = self._regex.match(line)
            return m.groupdict() if m else None
        if self.format == "csv":
            values = next(csv.reader(io.StringIO(line)))
            cols = self.parse["columns"]
            return dict(zip(cols, values)) if len(values) >= len(cols) else None
        raise ValueError(f"unknown format {self.format}")

    @property
    def _regex(self) -> re.Pattern:
        if not hasattr(self, "_compiled"):
            object.__setattr__(self, "_compiled", re.compile(self.parse["pattern"]))
        return self._compiled  # type: ignore[attr-defined]

    def timestamp_of(self, native: dict) -> datetime | None:
        raw = eval_spec(self.timestamp.get("from") or {"template": self.timestamp["template"]}, native)
        if raw is None:
            return None
        fmt = self.timestamp.get("format", "iso8601")
        if fmt == "epoch":
            ts = datetime.fromtimestamp(float(raw), tz=timezone.utc)
        elif fmt == "iso8601":
            ts = datetime.fromisoformat(str(raw).replace("Z", "+00:00"))
        else:
            ts = datetime.strptime(str(raw), fmt)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        return ts.astimezone(timezone.utc) + timedelta(seconds=self.clock_skew_seconds)

    def apply(self, native: dict) -> tuple[dict, dict]:
        """Return (ecs_fields, entity_specs_evaluated)."""
        fields, entities, drop = dict(self.fields), {k: dict(v) for k, v in self.entities.items()}, []
        for ov in self.overrides:
            if ov.matches(native):
                fields.update(ov.fields)
                for k, v in ov.entities.items():
                    entities.setdefault(k, {}).update(v)
                drop += ov.drop
        row: dict[str, Any] = dict(self.static)
        for name, spec in fields.items():
            if name in drop:
                continue
            v = eval_spec(spec, native)
            if v is not None:
                row[name] = v
        evaluated = {kind: {k: (eval_spec(s, native) if k != "ip_fields" else s) for k, s in spec.items()}
                     for kind, spec in entities.items()}
        return row, evaluated

    def post_process(self, row: dict) -> None:
        for d in self.derive:
            DERIVATIONS[d["fn"]](row, d)


@lru_cache
def load_mapping(source: str) -> Mapping:
    path = MAPPINGS_DIR / f"{source}.yaml"
    if not path.exists():
        raise FileNotFoundError(f"no ECS mapping for source {source!r} at {path}")
    spec = yaml.safe_load(path.read_text())
    overrides = [Override(when={k: {str(x) for x in (v if isinstance(v, list) else [v])}
                                for k, v in o["when"].items()},
                          fields=o.get("fields", {}), entities=o.get("entities", {}), drop=o.get("drop", []))
                 for o in spec.get("overrides", [])]
    return Mapping(
        source=spec["source"], version=str(spec["version"]), dataset=spec["dataset"],
        format=spec.get("format", "json"), timestamp=spec["timestamp"],
        clock_skew_seconds=float(spec.get("clock_skew_seconds", 0)), static=spec.get("static", {}),
        fields=spec.get("fields", {}), entities=spec.get("entities", {}), derive=spec.get("derive", []),
        overrides=overrides, parse=spec.get("parse", {}), options=spec.get("options", {}),
    )


def available_sources() -> list[str]:
    return sorted(p.stem for p in MAPPINGS_DIR.glob("*.yaml") if not p.stem.startswith("_"))
