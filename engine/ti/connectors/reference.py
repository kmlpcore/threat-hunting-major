"""Reference data feeds: MITRE ATT&CK (Enterprise STIX bundle) and CISA KEV."""
from __future__ import annotations

import json
import logging
import os
from datetime import datetime
from pathlib import Path

from engine.common.config import REPO_ROOT
from engine.ti.connectors.sdk import FeedConnector, Indicator, RawPayload, parse_ts, raw_json

log = logging.getLogger(__name__)


class MitreAttack(FeedConnector):
    """Keeps the local ATT&CK bundle (used to validate every technique in the TI tables) current."""
    name = "mitre_attack"
    version = "1"
    feed_generation = "reference"

    def fetch(self, since: datetime | None) -> list[RawPayload]:
        return [self.http.get(self.source_url())]

    def parse(self, raw: RawPayload) -> list[Indicator]:
        return []

    def apply_reference(self, raws: list[RawPayload]) -> dict:
        bundle = raw_json(raws[0])
        objects = bundle.get("objects", []) if isinstance(bundle, dict) else []
        techniques = [o for o in objects if o.get("type") == "attack-pattern"]
        if bundle.get("type") != "bundle" or not techniques:
            raise ValueError("not an ATT&CK STIX bundle")
        written = None
        if not self.offline:            # the sample is the shipped subset: never install it as "full"
            target = Path(os.environ.get("ATTACK_BUNDLE_PATH", REPO_ROOT / "data" / "attack" / "enterprise-attack.json"))
            try:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(raws[0].body)
                written = str(target)
                from engine.ti.attack import attack
                attack.cache_clear()
            except OSError as exc:
                log.warning("could not write the ATT&CK bundle to %s: %s", target, exc)
        return {"attack_patterns": len(techniques),
                "tactics": sum(1 for o in objects if o.get("type") == "x-mitre-tactic"), "installed": written}


class CisaKev(FeedConnector):
    """CISA Known Exploited Vulnerabilities: CVEs exploited in the wild (type `cve`, not swept)."""
    name = "cisa_kev"
    version = "1"
    feed_generation = "reference"

    def fetch(self, since: datetime | None) -> list[RawPayload]:
        return [self.http.get(self.source_url())]

    def parse(self, raw: RawPayload) -> list[Indicator]:
        data = raw_json(raw)
        out = []
        for v in data.get("vulnerabilities", []):
            ts = parse_ts(v.get("dateAdded"))
            ransomware = str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"
            out.append(Indicator(value=v["cveID"], type="cve", source_ref=v["cveID"],
                                 threat_type="exploited_vulnerability", confidence=100, first_seen=ts, last_seen=ts,
                                 tags=[t for t in (v.get("vendorProject"), v.get("product"),
                                                   "ransomware" if ransomware else None) if t],
                                 reference=v.get("vulnerabilityName")))
        return out

    def apply_reference(self, raws: list[RawPayload]) -> dict:
        data = raw_json(raws[0])
        return {"catalog_version": data.get("catalogVersion"), "count": data.get("count"),
                "released": data.get("dateReleased")}
