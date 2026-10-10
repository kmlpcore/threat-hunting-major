"""STIX 2.1 indicators from a TAXII 2.1 collection (v3, modern feeds).

fetch: GET {api_root}/collections/{collection}/objects/?added_after=<cursor>, following the
`more` / `next` pagination; cursor = X-TAXII-Date-Added-Last. parse: STIX patterns of
`pattern_type: stix`; every `<object>:value = '...'` / `file:hashes.'SHA-256' = '...'` comparison
becomes an indicator. TLP comes from the standard TLP marking definitions.
"""
from __future__ import annotations

import json
import re
from datetime import datetime

from engine.ti.connectors.sdk import FeedConnector, Indicator, RawPayload, parse_ts, raw_json

TLP_MARKINGS = {
    "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9": "TLP:CLEAR",
    "marking-definition--34098fce-860f-48ae-8e50-ebd3cc5e41da": "TLP:GREEN",
    "marking-definition--f88d31f6-486f-44da-b317-01333bde0b82": "TLP:AMBER",
    "marking-definition--5e57c739-391a-4eb3-b6be-7d15ca92d5ed": "TLP:RED",
    "marking-definition--94868c89-83c2-464b-929b-a1a8aa3c8487": "TLP:CLEAR",
    "marking-definition--bab4a63c-aed9-4cf5-a766-dfca5abac2bb": "TLP:GREEN",
    "marking-definition--55d920b0-5e8b-4f79-9ee9-91f868d9b421": "TLP:AMBER",
    "marking-definition--939a9414-2ddd-4d32-a0cd-375ea402b003": "TLP:AMBER+STRICT",
    "marking-definition--e828b379-4e03-4974-9ac4-e53a884c97c1": "TLP:RED",
}
COMPARISON = re.compile(
    r"(ipv4-addr|ipv6-addr|domain-name|url|file):(value|hashes\.'?(SHA-256|SHA-1|MD5)'?)\s*=\s*'([^']+)'", re.I)
TYPES = {"ipv4-addr": "ipv4", "ipv6-addr": "ipv6", "domain-name": "domain", "url": "url",
         "sha-256": "sha256", "sha-1": "sha1", "md5": "md5"}
ACCEPT = "application/taxii+json;version=2.1"


class Taxii21(FeedConnector):
    name = "taxii21"
    version = "1"
    feed_generation = "modern"
    default_config = {"enabled": False, "collection": "indicators", "auth_env": "TAXII21_TOKEN",
                      "sample": "data/feeds/samples/taxii21_objects.json", "schedule_minutes": 60}

    def fetch(self, since: datetime | None) -> list[RawPayload]:
        if self.offline:
            return [self.sample()]
        base = self.config["url"].rstrip("/")
        url = f"{base}/collections/{self.config['collection']}/objects/"
        headers = {"Accept": ACCEPT}
        token = self.secret()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        params = {"match[type]": "indicator"}
        if since:
            params["added_after"] = since.isoformat().replace("+00:00", "Z")
        out = []
        for _ in range(100):                            # pagination guard
            resp = self.http.get(url, headers=headers, params=params)
            body = raw_json(resp)
            out.append(resp)
            if not body.get("more") or not body.get("next"):
                break
            params["next"] = body["next"]
        return out

    def parse(self, raw: RawPayload) -> list[Indicator]:
        body = raw_json(raw)
        out = []
        for o in body.get("objects", []):
            if o.get("type") != "indicator" or o.get("pattern_type", "stix") != "stix":
                continue
            tlp = next((TLP_MARKINGS[m] for m in o.get("object_marking_refs", []) if m in TLP_MARKINGS), None)
            for kind, _, hash_type, value in COMPARISON.findall(o.get("pattern", "")):
                typ = TYPES.get((hash_type or kind).lower())
                out.append(Indicator(
                    value=value, type=typ, source_ref=o["id"], threat_type=(o.get("indicator_types") or [None])[0],
                    confidence=o.get("confidence"), tlp=tlp, first_seen=parse_ts(o.get("valid_from")),
                    last_seen=parse_ts(o.get("modified")) or parse_ts(o.get("valid_from")),
                    tags=[*(o.get("labels") or []), o.get("name") or ""],
                    attack_techniques=[r["external_id"] for r in o.get("external_references", [])
                                       if r.get("source_name") == "mitre-attack" and r.get("external_id")],
                    reference=json.dumps({"name": o.get("name")})))
        return out
