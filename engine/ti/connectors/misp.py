"""MISP (REST API /attributes/restSearch, JSON). Attribute types map to indicator types; the
attribute's TLP tag becomes the indicator's TLP; to_ids attributes get higher confidence."""
from __future__ import annotations

from datetime import datetime

from engine.ti.connectors.sdk import FeedConnector, Indicator, RawPayload, parse_ts, raw_json

TYPES = {"ip-dst": "ipv4", "ip-src": "ipv4", "domain": "domain", "hostname": "domain", "url": "url",
         "md5": "md5", "sha1": "sha1", "sha256": "sha256", "ja3-fingerprint-md5": "ja3",
         "ip-dst|port": "ip:port", "ip-src|port": "ip:port", "domain|ip": "domain"}


class MISP(FeedConnector):
    name = "misp"
    version = "1"
    feed_generation = "legacy"

    def fetch(self, since: datetime | None) -> list[RawPayload]:
        if self.offline:
            return [self.sample()]
        key = self.secret()
        if not key:
            raise ValueError("MISP_API_KEY is not set")
        body = {"returnFormat": "json", "type": sorted(TYPES), "to_ids": True, "includeEventTags": True}
        if since:
            body["timestamp"] = int(since.timestamp())
        return [self.http.post(self.config["url"], json=body,
                               headers={"Authorization": key, "Accept": "application/json"})]

    def parse(self, raw: RawPayload) -> list[Indicator]:
        data = raw_json(raw)
        attrs = (data.get("response") or {}).get("Attribute", []) if isinstance(data, dict) else []
        out = []
        for a in attrs:
            typ = TYPES.get(a.get("type"))
            if not typ:
                continue
            value = a["value"]
            if typ == "ip:port":
                value = value.replace("|", ":")
            elif a.get("type") == "domain|ip":
                value = value.split("|", 1)[0]
            tags = [t.get("name", "") for t in (a.get("Tag") or []) + ((a.get("Event") or {}).get("Tag") or [])]
            tlp = next((t for t in tags if t.lower().startswith("tlp:")), None)
            family = next((t.split("=", 1)[1].strip('"') for t in tags if "malpedia=" in t or "threat-actor=" in t),
                          None)
            ts = parse_ts(int(a["timestamp"])) if str(a.get("timestamp", "")).isdigit() else parse_ts(a.get("timestamp"))
            out.append(Indicator(value=value, type=typ, source_ref=f"{a.get('event_id')}/{a.get('id')}",
                                 threat_type=a.get("category"), malware_family=family,
                                 confidence=80 if a.get("to_ids") else 50, tlp=tlp, first_seen=ts, last_seen=ts,
                                 tags=[t for t in tags if not t.lower().startswith("tlp:")],
                                 reference=(a.get("Event") or {}).get("info")))
        return out
