"""ECS field catalogue: Arrow schema, type coercion and validation."""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import pyarrow as pa
import yaml

from engine.common.config import REPO_ROOT

FIELDS_FILE = REPO_ROOT / "schemas" / "ecs" / "fields.yaml"
_ARROW = {
    "date": pa.timestamp("us", tz="UTC"), "keyword": pa.string(), "text": pa.string(), "ip": pa.string(),
    "long": pa.int64(), "float": pa.float64(), "boolean": pa.bool_(),
}
EARLIEST = datetime(2000, 1, 1, tzinfo=timezone.utc)


@dataclass(frozen=True)
class EcsCatalog:
    ecs_version: str
    fields: dict[str, str]          # name → type (with [] suffix for arrays)
    required: tuple[str, ...]
    allowed: dict[str, frozenset]
    expected_types: dict[str, frozenset]

    @property
    def arrow_schema(self) -> pa.Schema:
        cols = []
        for name, typ in self.fields.items():
            base = _ARROW[typ.removesuffix("[]")]
            cols.append(pa.field(name, pa.list_(base) if typ.endswith("[]") else base,
                                 nullable=name not in self.required))
        return pa.schema(cols, metadata={b"ecs.version": self.ecs_version.encode()})


@lru_cache
def catalog() -> EcsCatalog:
    spec = yaml.safe_load(FIELDS_FILE.read_text())
    return EcsCatalog(
        ecs_version=spec["ecs_version"],
        fields=dict(spec["fields"]),
        required=tuple(spec["required"]),
        allowed={k: frozenset(v) for k, v in spec["allowed"].items()},
        expected_types={k: frozenset(v) for k, v in spec["expected_types"].items()},
    )


class CoercionError(ValueError):
    pass


def _ip(value) -> str:
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError as exc:
        raise CoercionError(f"not an IP: {value!r}") from exc


def _date(value) -> datetime:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    raise CoercionError(f"not a datetime: {value!r}")


def _scalar(typ: str, value):
    if typ in ("keyword", "text"):
        return str(value)
    if typ == "long":
        if isinstance(value, bool):
            raise CoercionError(f"bool for long: {value!r}")
        try:
            return int(float(value)) if isinstance(value, str) else int(value)
        except (TypeError, ValueError) as exc:
            raise CoercionError(f"not a long: {value!r}") from exc
    if typ == "float":
        try:
            return float(value)
        except (TypeError, ValueError) as exc:
            raise CoercionError(f"not a float: {value!r}") from exc
    if typ == "boolean":
        if isinstance(value, bool):
            return value
        return str(value).lower() in ("true", "1", "yes")
    if typ == "ip":
        return _ip(value)
    if typ == "date":
        return _date(value)
    raise CoercionError(f"unknown type {typ}")


def coerce(row: dict) -> tuple[dict, list[str]]:
    """Coerce values to their ECS types. Unknown fields are errors (keeps the schema honest)."""
    cat = catalog()
    out, errors = {}, []
    for name, value in row.items():
        typ = cat.fields.get(name)
        if typ is None:
            errors.append(f"unknown ECS field {name}")
            continue
        if value is None or value == "" or value == []:
            continue
        try:
            if typ.endswith("[]"):
                values = value if isinstance(value, (list, tuple)) else [value]
                base = typ[:-2]
                out[name] = list(dict.fromkeys(_scalar(base, v) for v in values if v not in (None, "")))
            else:
                out[name] = _scalar(typ, value)
        except CoercionError as exc:
            errors.append(f"{name}: {exc}")
    return out, errors


def validate(row: dict) -> list[str]:
    """Validate an already-coerced row against required fields and allowed values."""
    cat = catalog()
    errors = [f"missing required {f}" for f in cat.required if row.get(f) in (None, "", [])]
    for name, allowed in cat.allowed.items():
        value = row.get(name)
        values = value if isinstance(value, list) else [value] if value is not None else []
        errors += [f"{name}={v!r} not allowed" for v in values if v not in allowed]
    for category in row.get("event.category") or []:
        expected = cat.expected_types.get(category)
        if expected:
            errors += [f"event.type {t!r} unexpected for category {category!r}"
                       for t in row.get("event.type") or [] if t not in expected]
    ts = row.get("@timestamp")
    if isinstance(ts, datetime) and not (EARLIEST <= ts <= datetime.now(timezone.utc) + timedelta(days=1)):
        errors.append(f"@timestamp out of range: {ts.isoformat()}")
    for name in ("source.ip", "destination.ip"):
        if row.get(name) is not None:
            try:
                ipaddress.ip_address(row[name])
            except ValueError:
                errors.append(f"{name} invalid")
    return errors


def to_table(rows: list[dict]) -> pa.Table:
    return pa.Table.from_pylist(rows, schema=catalog().arrow_schema)
