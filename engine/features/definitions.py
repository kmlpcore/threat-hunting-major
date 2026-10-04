"""Feature definitions (policies/features.yaml) and the feature registry."""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from functools import lru_cache

import yaml
from sqlalchemy import select
from sqlalchemy.engine import Connection

from engine.common.config import REPO_ROOT
from engine.common.db import features, upsert, utcnow
from engine.summary.tables import TABLES

FEATURES_FILE = REPO_ROOT / "policies" / "features.yaml"


@dataclass(frozen=True)
class FeatureDef:
    name: str
    version: str
    active: bool
    description: str
    inputs: tuple[str, ...]
    window_days: int
    sql: str

    @property
    def key(self) -> str:
        return f"{self.name}@{self.version}"

    @property
    def output_table(self) -> str:
        return f"artefacts.{self.name}"

    @property
    def input_sources(self) -> tuple[str, ...]:
        return tuple(sorted({TABLES[t].source for t in self.inputs}))

    @property
    def definition_hash(self) -> str:
        body = {"inputs": list(self.inputs), "window_days": self.window_days, "sql": self.sql.strip()}
        return hashlib.sha256(json.dumps(body, sort_keys=True).encode()).hexdigest()[:16]


@lru_cache
def load_definitions() -> dict[str, FeatureDef]:
    spec = yaml.safe_load(FEATURES_FILE.read_text())
    out = {}
    for f in spec["features"]:
        d = FeatureDef(name=f["name"], version=str(f["version"]), active=bool(f.get("active", False)),
                       description=" ".join(str(f.get("description", "")).split()), inputs=tuple(f["inputs"]),
                       window_days=int(f.get("window_days", 0)), sql=f["sql"])
        unknown = set(d.inputs) - set(TABLES)
        if unknown:
            raise ValueError(f"feature {d.key}: unknown input tables {unknown}")
        out[d.key] = d
    return out


def get_definition(name: str, version: str) -> FeatureDef:
    key = f"{name}@{version}"
    defs = load_definitions()
    if key not in defs:
        raise KeyError(f"no feature definition {key} in {FEATURES_FILE.name}")
    return defs[key]


def register(conn: Connection, d: FeatureDef) -> bool:
    """Add a feature version to the registry. Versions are immutable: re-registering with a
    different definition is refused. Returns True if newly registered."""
    row = conn.execute(select(features).where(features.c.name == d.name, features.c.version == d.version)).first()
    if row is not None:
        if row.definition_hash != d.definition_hash:
            raise ValueError(f"{d.key} is already registered with a different definition; bump the version")
        if row.status != "active":
            upsert(conn, features, {"name": d.name, "version": d.version}, {"status": "active"})
            return True
        return False
    conn.execute(features.insert().values(name=d.name, version=d.version, definition_hash=d.definition_hash,
                                          inputs=list(d.inputs), output_table=d.output_table,
                                          window_days=d.window_days, status="active", registered_at=utcnow()))
    return True


def active_features(conn: Connection) -> list[FeatureDef]:
    defs = load_definitions()
    rows = conn.execute(select(features.c.name, features.c.version).where(features.c.status == "active")).all()
    return [defs[f"{r.name}@{r.version}"] for r in rows if f"{r.name}@{r.version}" in defs]
