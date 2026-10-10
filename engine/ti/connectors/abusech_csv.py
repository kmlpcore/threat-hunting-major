"""abuse.ch bulk CSV / JSON feeds: URLhaus, MalwareBazaar, Feodo Tracker, SSL Blacklist."""
from __future__ import annotations

import csv
import io
from datetime import datetime

from engine.ti.connectors.sdk import FeedConnector, Indicator, RawPayload, parse_ts, raw_json


def _rows(raw: RawPayload) -> list[list[str]]:
    text = raw.body.decode("utf-8-sig", "replace")
    lines = [ln for ln in text.splitlines() if ln.strip() and not ln.lstrip().startswith("#")]
    return [r for r in csv.reader(io.StringIO("\n".join(lines)), skipinitialspace=True) if r]


class _AbuseChDownload(FeedConnector):
    feed_generation = "legacy"

    def fetch(self, since: datetime | None) -> list[RawPayload]:
        if self.offline:
            return [self.sample()]
        key = self.secret()
        return [self.http.get(self.config["url"], headers={"Auth-Key": key} if key else {})]


class URLhaus(_AbuseChDownload):
    """id,dateadded,url,url_status,last_online,threat,tags,urlhaus_link,reporter"""
    name = "urlhaus"
    version = "1"

    def parse(self, raw):
        out = []
        for r in _rows(raw):
            if len(r) < 8 or r[0] == "id":
                continue
            tags = [t for t in r[6].split(",") if t]
            out.append(Indicator(value=r[2], type="url", source_ref=r[0], threat_type="payload_delivery"
                                 if r[5] == "malware_download" else r[5], malware_family=tags[0] if tags else None,
                                 confidence=80 if r[3] == "online" else 60, first_seen=parse_ts(r[1]),
                                 last_seen=parse_ts(r[4]) or parse_ts(r[1]), tags=tags, reference=r[7]))
        return out


class MalwareBazaar(_AbuseChDownload):
    """first_seen_utc,sha256_hash,md5_hash,sha1_hash,reporter,file_name,file_type_guess,mime_type,signature,..."""
    name = "malwarebazaar"
    version = "1"

    def parse(self, raw):
        out = []
        for r in _rows(raw):
            if len(r) < 9 or r[1] == "sha256_hash":
                continue
            ts, fam = parse_ts(r[0]), (r[8] if r[8] not in ("", "n/a") else None)
            for value, typ in ((r[1], "sha256"), (r[2], "md5")):
                out.append(Indicator(value=value, type=typ, source_ref=r[1], threat_type="payload",
                                     malware_family=fam, confidence=90, first_seen=ts, last_seen=ts,
                                     tags=[x for x in (r[6], fam) if x],
                                     reference=f"https://bazaar.abuse.ch/sample/{r[1]}/"))
        return out


class FeodoTracker(_AbuseChDownload):
    """JSON list: ip_address, port, status, hostname, as_number, as_name, country, first_seen, last_online, malware"""
    name = "feodo"
    version = "1"

    def parse(self, raw):
        out = []
        for e in raw_json(raw):
            out.append(Indicator(value=e["ip_address"], type="ipv4", source_ref=f"{e['ip_address']}:{e.get('port')}",
                                 threat_type="botnet_cc", malware_family=e.get("malware"),
                                 confidence=90 if e.get("status") == "online" else 70,
                                 first_seen=parse_ts(e.get("first_seen")),
                                 last_seen=parse_ts(e.get("last_online")) or parse_ts(e.get("first_seen")),
                                 tags=[f"port:{e.get('port')}", e.get("country") or ""],
                                 reference="https://feodotracker.abuse.ch/browse/host/" + e["ip_address"] + "/"))
        return out


class SSLBlacklist(_AbuseChDownload):
    """CSV: Firstseen,DstIP,DstPort (botnet C2 servers identified by SSL certificate)"""
    name = "sslbl"
    version = "1"

    def parse(self, raw):
        out = []
        for r in _rows(raw):
            if len(r) < 3 or r[1] == "DstIP":
                continue
            out.append(Indicator(value=r[1], type="ipv4", source_ref=f"{r[1]}:{r[2]}", threat_type="botnet_cc",
                                 confidence=80, first_seen=parse_ts(r[0]), last_seen=parse_ts(r[0]),
                                 tags=[f"port:{r[2]}", "sslbl"], reference="https://sslbl.abuse.ch/"))
        return out
