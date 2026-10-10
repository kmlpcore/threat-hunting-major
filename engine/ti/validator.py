"""Validation of LLM output before anything is stored (plan.md section 3.9, step 4).

* technique IDs must exist (and not be revoked) in the local ATT&CK bundle; unknown IDs are
  dropped, and a pattern left without a valid technique is rejected;
* tactics must be ATT&CK tactic short names; otherwise they are derived from the techniques;
* every pattern must cite evidence ids that exist in the bundle it was given;
* confidence below the policy threshold -> status `proposed` (analyst review), otherwise
  `auto_validated`. Analyst review later moves rows to `validated` or `rejected`.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from engine.ti.attack import attack
from engine.ti.bundler import egress_policy

TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
SEVERITIES = ("low", "medium", "high", "critical")


@dataclass
class Validated:
    accepted: list[dict] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)       # {pattern, reasons}
    dropped_techniques: list[str] = field(default_factory=list)


def validate(content: dict, evidence_ids: set[str]) -> Validated:
    pol = egress_policy()["validation"]
    att = attack()
    out = Validated()
    patterns = content.get("patterns") if isinstance(content, dict) else None
    if not isinstance(patterns, list):
        out.rejected.append({"pattern": content, "reasons": ["output is not {'patterns': [...]}"]})
        return out
    for p in patterns:
        reasons = []
        if not isinstance(p, dict):
            out.rejected.append({"pattern": p, "reasons": ["pattern is not an object"]})
            continue
        title = str(p.get("title") or "").strip()
        if len(title) < 3:
            reasons.append("missing title")
        techs = []
        for t in p.get("techniques") or []:
            t = str(t).strip().upper()
            if TECH_RE.match(t) and att.technique(t):
                if t not in techs:
                    techs.append(t)
            else:
                out.dropped_techniques.append(t)
        if not techs:
            reasons.append("no valid ATT&CK technique id")
        cited = [str(e) for e in (p.get("evidence_ids") or [])]
        unknown = [e for e in cited if e not in evidence_ids]
        if pol.get("require_evidence", True) and (not cited or unknown):
            reasons.append(f"evidence ids not in bundle: {unknown}" if unknown else "no evidence cited")
        try:
            confidence = int(round(float(p.get("confidence"))))
        except (TypeError, ValueError):
            confidence = None
            reasons.append("confidence is not a number")
        if confidence is not None and not 0 <= confidence <= 100:
            reasons.append("confidence outside 0-100")
        if reasons:
            out.rejected.append({"pattern": p, "reasons": reasons})
            continue
        tactics = [str(t).lower().replace("_", "-") for t in (p.get("tactics") or []) if att.valid_tactic(t)]
        derived = att.tactics_of(techs)
        tactics = [t for t in tactics if t in derived] or derived
        severity = str(p.get("severity") or "").lower()
        out.accepted.append({
            "title": title[:200], "narrative": str(p.get("narrative") or "")[:4000], "techniques": techs,
            "tactics": tactics, "kill_chain_phase": p.get("kill_chain_phase") or (tactics[0] if tactics else None),
            "severity": severity if severity in SEVERITIES else ("high" if confidence >= 75 else "medium"),
            "confidence": confidence, "evidence_ids": cited,
            "status": "auto_validated" if confidence >= pol["auto_validate_confidence"] else "proposed"})
    return out
