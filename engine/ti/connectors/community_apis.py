"""Community REST feeds (v3, modern): AlienVault OTX pulses and the AbuseIPDB blacklist."""
from __future__ import annotations

from datetime import datetime

from engine.ti.connectors.sdk import FeedConnector, Indicator, RawPayload, parse_ts, raw_json

OTX_TYPES = {"IPv4": "ipv4", "IPv6": "ipv6", "domain": "domain", "hostname": "domain", "URL": "url",
             "FileHash-SHA256": "sha256", "FileHash-MD5": "md5", "FileHash-SHA1": "sha1"}


class OTX(FeedConnector):
    """GET /api/v1/pulses/subscribed?modified_since=... (X-OTX-API-KEY), paginated by `next`."""
    name = "otx"
    version = "1"
    feed_generation = "modern"
    default_config = {"enabled": False, "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
                      "auth_env": "OTX_API_KEY", "sample": "data/feeds/samples/otx_pulses.json"}

    def fetch(self, since: datetime | None) -> list[RawPayload]:
        if self.offline:
            return [self.sample()]
        key = self.secret()
        if not key:
            raise ValueError("OTX_API_KEY is not set")
        url, params, out = self.config["url"], {"limit": 50}, []
        if since:
            params["modified_since"] = since.isoformat()
        for _ in range(200):
            resp = self.http.get(url, headers={"X-OTX-API-KEY": key}, params=params)
            out.append(resp)
            nxt = raw_json(resp).get("next")
            if not nxt:
                break
            url, params = nxt, {}
        return out

    def parse(self, raw: RawPayload) -> list[Indicator]:
        out = []
        for pulse in raw_json(raw).get("results", []):
            techs = [a["id"] if isinstance(a, dict) else str(a) for a in pulse.get("attack_ids") or []]
            fams = [f["display_name"] if isinstance(f, dict) else str(f) for f in pulse.get("malware_families") or []]
            for i in pulse.get("indicators", []):
                typ = OTX_TYPES.get(i.get("type"))
                if not typ:
                    continue
                out.append(Indicator(value=i["indicator"], type=typ, source_ref=f"{pulse['id']}/{i.get('id', '')}",
                                     malware_family=fams[0] if fams else None, malware_aliases=fams[1:],
                                     attack_techniques=techs, confidence=70, tlp=pulse.get("TLP"),
                                     first_seen=parse_ts(i.get("created")), last_seen=parse_ts(pulse.get("modified")),
                                     tags=pulse.get("tags") or [], reference=pulse.get("name")))
        return out


class AbuseIPDB(FeedConnector):
    """GET /api/v2/blacklist?confidenceMinimum=N (Key header)."""
    name = "abuseipdb"
    version = "1"
    feed_generation = "modern"
    default_config = {"enabled": False, "url": "https://api.abuseipdb.com/api/v2/blacklist",
                      "auth_env": "ABUSEIPDB_API_KEY", "confidence_minimum": 90,
                      "sample": "data/feeds/samples/abuseipdb_blacklist.json"}

    def fetch(self, since: datetime | None) -> list[RawPayload]:
        if self.offline:
            return [self.sample()]
        key = self.secret()
        if not key:
            raise ValueError("ABUSEIPDB_API_KEY is not set")
        return [self.http.get(self.config["url"], headers={"Key": key, "Accept": "application/json"},
                              params={"confidenceMinimum": int(self.config.get("confidence_minimum", 90))})]

    def parse(self, raw: RawPayload) -> list[Indicator]:
        return [Indicator(value=d["ipAddress"], threat_type="abusive_ip", confidence=d.get("abuseConfidenceScore"),
                          first_seen=parse_ts(d.get("lastReportedAt")), last_seen=parse_ts(d.get("lastReportedAt")),
                          tags=[d.get("countryCode") or ""], reference="https://www.abuseipdb.com/check/" + d["ipAddress"])
                for d in raw_json(raw).get("data", [])]
