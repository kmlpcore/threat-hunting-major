"""Local MITRE ATT&CK reference (STIX 2.1 bundle) used to validate every technique and tactic
that enters a TI table. The full official bundle is used when present; otherwise the shipped
subset (scripts/build_attack_subset.py)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache

from engine.common.config import REPO_ROOT

FULL = REPO_ROOT / "data" / "attack" / "enterprise-attack.json"
SUBSET = REPO_ROOT / "data" / "attack" / "enterprise-attack-subset.json"


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    revoked: bool


@dataclass(frozen=True)
class Attack:
    source: str
    techniques: dict[str, Technique]
    tactics: dict[str, str]           # shortname -> TA id

    def technique(self, tid: str) -> Technique | None:
        t = self.techniques.get(str(tid).upper().strip())
        return t if t and not t.revoked else None

    def valid_tactic(self, name: str) -> bool:
        return str(name).lower().replace("_", "-").strip() in self.tactics

    def tactics_of(self, techniques) -> list[str]:
        out = []
        for tid in techniques:
            t = self.technique(tid)
            for tac in (t.tactics if t else ()):
                if tac not in out:
                    out.append(tac)
        return out


@lru_cache
def attack() -> Attack:
    path = FULL if FULL.exists() else SUBSET
    bundle = json.loads(path.read_text(encoding="utf-8"))
    techniques, tactics = {}, {}
    for o in bundle["objects"]:
        ext = next((r for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if o["type"] == "x-mitre-tactic" and ext:
            tactics[o["x_mitre_shortname"]] = ext["external_id"]
        elif o["type"] == "attack-pattern" and ext:
            techniques[ext["external_id"]] = Technique(
                ext["external_id"], o["name"],
                tuple(p["phase_name"] for p in o.get("kill_chain_phases", []) if p["kill_chain_name"] == "mitre-attack"),
                bool(o.get("revoked") or o.get("x_mitre_deprecated")))
    return Attack(path.name, techniques, tactics)
