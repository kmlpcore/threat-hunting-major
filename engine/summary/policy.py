"""Drop / aggregate policy loader (policies/drop_policy.yaml)."""
from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache

import yaml

from engine.common.config import REPO_ROOT

POLICY_FILE = REPO_ROOT / "policies" / "drop_policy.yaml"


@dataclass(frozen=True)
class SourcePolicy:
    source: str
    action: str                     # aggregate | keep_raw_only
    tables: tuple[str, ...]
    high_value: tuple[dict, ...]


@dataclass(frozen=True)
class DropPolicy:
    version: str
    sources: dict[str, SourcePolicy]

    def for_source(self, source: str) -> SourcePolicy:
        # Unknown sources are kept raw-only rather than silently summarised or dropped.
        return self.sources.get(source, SourcePolicy(source, "keep_raw_only", (), ()))


def _quote(v) -> str:
    return "'" + str(v).replace("'", "''") + "'"


def high_value_where(sp: SourcePolicy) -> str | None:
    """SQL WHERE clause (over the `raw` relation) selecting high-value rows, or None.

    Matching is case-insensitive (policy >= 1.1.0). Sigma compares strings case-insensitively,
    so this is what lets the coverage planner prove that a rule's matches are all retained."""
    ors = []
    for cond in sp.high_value:
        ands = []
        for field, spec in cond.items():
            col = f'lower(CAST("{field}" AS VARCHAR))'
            if isinstance(spec, dict) and "contains_any" in spec:
                ands.append("(" + " OR ".join(f"contains({col}, {_quote(str(s).lower())})"
                                              for s in spec["contains_any"]) + ")")
            else:
                ands.append(f"{col} IN ({', '.join(_quote(str(v).lower()) for v in spec)})")
        if ands:
            ors.append("(" + " AND ".join(ands) + ")")
    return " OR ".join(ors) if ors else None


@lru_cache
def load_policy() -> DropPolicy:
    spec = yaml.safe_load(POLICY_FILE.read_text())
    sources = {name: SourcePolicy(name, s.get("action", "keep_raw_only"), tuple(s.get("tables", [])),
                                  tuple(s.get("high_value", [])))
               for name, s in spec["sources"].items()}
    return DropPolicy(version=str(spec["version"]), sources=sources)
