"""Push / streaming feeds (v3): a sender POSTs a JSON batch to the command API
(POST /ti/push/{connector}); the API stores it and queues PullFeed with that payload, so pushed
indicators go through exactly the same normalisation, TLP, dedupe and retro-sweep path.

    {"indicators": [{"value": "...", "type": "domain", "threat_type": "...", "confidence": 70,
                     "tlp": "TLP:GREEN", "malware_family": "...", "tags": [...]}]}
"""
from __future__ import annotations

from datetime import datetime

from engine.ti.connectors.sdk import FeedConnector, Indicator, RawPayload, parse_ts, raw_json


class Webhook(FeedConnector):
    name = "webhook"
    version = "1"
    feed_generation = "modern"
    default_config = {"enabled": False, "sample": "data/feeds/samples/webhook_push.json"}

    def fetch(self, since: datetime | None) -> list[RawPayload]:
        # Push-only: payloads arrive through PullFeed(payload_uri=...). Offline mode replays the sample.
        return [self.sample()] if self.offline else []

    def parse(self, raw: RawPayload) -> list[Indicator]:
        body = raw_json(raw)
        items = body.get("indicators", body if isinstance(body, list) else [])
        return [Indicator(value=i["value"], type=i.get("type"), threat_type=i.get("threat_type"),
                          malware_family=i.get("malware_family"), confidence=i.get("confidence"), tlp=i.get("tlp"),
                          first_seen=parse_ts(i.get("first_seen")), last_seen=parse_ts(i.get("last_seen")),
                          tags=i.get("tags") or [], source_ref=i.get("id"), reference=i.get("reference"))
                for i in items if i.get("value")]
