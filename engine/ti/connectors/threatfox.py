"""ThreatFox (abuse.ch) IOC database.

Two transports:
  * api    POST https://threatfox-api.abuse.ch/api/v1/ {"query": "get_iocs", "days": N}
           with the `Auth-Key` header (free abuse.ch account)
  * export the JSON export of recent IOCs ({"<id>": [{"ioc_value": ...}]})

IOC types: ip:port, domain, url, md5_hash, sha1_hash, sha256_hash.
"""
from __future__ import annotations

from datetime import datetime

from engine.ti.connectors.sdk import FeedConnector, Indicator, RawPayload, parse_ts, raw_json

TYPES = {"ip:port": "ip:port", "domain": "domain", "url": "url", "md5_hash": "md5", "sha1_hash": "sha1",
         "sha256_hash": "sha256"}


def _split(v) -> list[str]:
    if not v:
        return []
    if isinstance(v, list):
        return [str(x).strip() for x in v if x]
    return [x.strip() for x in str(v).split(",") if x.strip()]


class ThreatFox(FeedConnector):
    name = "threatfox"
    version = "1"
    feed_generation = "legacy"

    def fetch(self, since: datetime | None) -> list[RawPayload]:
        if self.offline:
            return [self.sample()]
        key = self.secret()
        if self.config.get("mode", "api") == "api":
            if not key:
                raise ValueError("THREATFOX_AUTH_KEY is not set (ThreatFox API requires an abuse.ch Auth-Key)")
            days = int(self.config.get("days", 1))
            if since is not None:
                days = max(1, min(7, (datetime.now(since.tzinfo) - since).days + 1))
            return [self.http.post(self.config["url"], json={"query": "get_iocs", "days": days},
                                   headers={"Auth-Key": key})]
        headers = {"Auth-Key": key} if key else {}
        return [self.http.get(self.config["export_url"], headers=headers)]

    def parse(self, raw: RawPayload) -> list[Indicator]:
        data = raw_json(raw)
        if isinstance(data, dict) and "query_status" in data:
            if data["query_status"] not in ("ok", "no_result"):
                raise ValueError(f"ThreatFox API error: {data['query_status']}")
            items = data.get("data") or []
            if isinstance(items, str):               # "no_result" returns a message string
                items = []
            return [self._api(i) for i in items if i.get("ioc_type") in TYPES]
        out = []
        for ioc_id, entries in (data or {}).items():
            for e in entries:
                if e.get("ioc_type") in TYPES:
                    out.append(self._export(ioc_id, e))
        return out

    @staticmethod
    def _api(i: dict) -> Indicator:
        return Indicator(
            value=i["ioc"], type=TYPES[i["ioc_type"]], source_ref=str(i.get("id")), threat_type=i.get("threat_type"),
            malware_family=i.get("malware_printable") or i.get("malware"),
            malware_aliases=_split(i.get("malware_alias")) + ([i["malware"]] if i.get("malware") else []),
            confidence=i.get("confidence_level"), first_seen=parse_ts(i.get("first_seen")),
            last_seen=parse_ts(i.get("last_seen")) or parse_ts(i.get("first_seen")), tags=_split(i.get("tags")),
            reference=i.get("reference") or f"https://threatfox.abuse.ch/ioc/{i.get('id')}/")

    @staticmethod
    def _export(ioc_id: str, e: dict) -> Indicator:
        return Indicator(
            value=e["ioc_value"], type=TYPES[e["ioc_type"]], source_ref=str(ioc_id), threat_type=e.get("threat_type"),
            malware_family=e.get("malware_printable") or e.get("malware"),
            malware_aliases=_split(e.get("malware_alias")), confidence=e.get("confidence_level"),
            first_seen=parse_ts(e.get("first_seen_utc")),
            last_seen=parse_ts(e.get("last_seen_utc")) or parse_ts(e.get("first_seen_utc")),
            tags=_split(e.get("tags")), reference=e.get("reference"))
