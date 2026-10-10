"""Generic plain-text / CSV blocklists (one IP, domain or URL per line; first column of a CSV).
Comment lines start with '#' or ';'. Defanged values (hxxp, [.]) are re-fanged by the SDK."""
from __future__ import annotations

from datetime import datetime

from engine.ti.connectors.sdk import FeedConnector, Indicator, RawPayload


class CsvBlocklist(FeedConnector):
    name = "csv_blocklist"
    version = "1"
    feed_generation = "legacy"

    def fetch(self, since: datetime | None) -> list[RawPayload]:
        return [self.http.get(self.source_url())]

    def parse(self, raw: RawPayload) -> list[Indicator]:
        out = []
        for line in raw.body.decode("utf-8-sig", "replace").splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            value = line.split(",")[0].split()[0].strip().strip('"')
            if value.lower() in ("ip", "domain", "url", "indicator", "value"):
                continue
            out.append(Indicator(value=value, tags=["blocklist"], reference=raw.url))
        return out
