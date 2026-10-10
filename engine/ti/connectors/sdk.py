"""TI feed connector SDK (plan.md section 3.10b).

A connector only implements

    class MyFeed(FeedConnector):
        name = "myfeed"; version = "1"; feed_generation = "legacy" | "modern" | "reference"
        default_config = {...}                         # optional; policies/ti_feeds.yaml overrides it
        def fetch(self, since) -> list[RawPayload]     # pull or bulk download (self.http does the I/O)
        def parse(self, raw) -> list[Indicator]        # into the ti.tactical shape

and drops the module into engine/ti/connectors/. It is discovered automatically; nothing
outside this package changes. The framework does everything else: credentials (env / secret
store), rate limits and retries, cursoring (`since`), value normalisation, confidence
rescaling, TLP, expiry/decay, warninglists, deduplication by indicator_id, writes through the
command path (queue `ti`), events, and the batched IOC retro-sweep for indicators never seen
before.
"""
from __future__ import annotations

import hashlib
import importlib
import ipaddress
import json
import logging
import os
import pkgutil
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import lru_cache
from pathlib import Path

import httpx
import yaml
from sqlalchemy import select

from engine.common.config import REPO_ROOT
from engine.common.db import feed_state, upsert, utcnow
from engine.common.events import FeedPulled, IndicatorRecorded
from engine.ti import tables as T

log = logging.getLogger(__name__)
TLP_ORDER = ["TLP:CLEAR", "TLP:GREEN", "TLP:AMBER", "TLP:AMBER+STRICT", "TLP:RED"]
TLP_ALIASES = {"TLP:WHITE": "TLP:CLEAR", "WHITE": "TLP:CLEAR", "CLEAR": "TLP:CLEAR", "GREEN": "TLP:GREEN",
               "AMBER": "TLP:AMBER", "AMBER+STRICT": "TLP:AMBER+STRICT", "RED": "TLP:RED"}
SWEEP_FIELDS = {
    "ip": ["source.ip", "destination.ip", "related.ip"],
    "domain": ["dns.question.name", "dns.question.registered_domain", "url.domain", "url.registered_domain",
               "destination.domain"],
    "sha256": ["process.hash.sha256", "file.hash.sha256", "related.hash"],
}
THREAT_TYPE_TECHNIQUES = {"botnet_cc": ["T1071"], "payload_delivery": ["T1105"], "payload": ["T1204.002"],
                          "phishing": ["T1566"], "cc_skimming": ["T1056"], "malware_download": ["T1105"]}
TAG_TECHNIQUES = {"miner": ["T1496"], "xmrig": ["T1496"], "cryptominer": ["T1496"], "coinminer": ["T1496"],
                  "cobaltstrike": ["T1071.001"], "cobalt strike": ["T1071.001"], "ransomware": ["T1486"],
                  "dns-tunnel": ["T1071.004"], "exfil": ["T1048"]}


@dataclass
class RawPayload:
    url: str
    body: bytes
    content_type: str = ""
    cursor: str | None = None          # connector-provided cursor after this payload


@dataclass
class Indicator:
    """Canonical record a connector returns; the framework turns it into a ti.tactical row."""
    value: str
    type: str | None = None            # detected when None
    source_ref: str | None = None
    threat_type: str | None = None
    malware_family: str | None = None
    malware_aliases: list[str] = field(default_factory=list)
    attack_techniques: list[str] = field(default_factory=list)
    confidence: float | None = None    # on the connector's own scale
    confidence_scale: float = 100.0
    tlp: str | None = None
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    tags: list[str] = field(default_factory=list)
    reference: str | None = None


class Http:
    """HTTP for connectors: retries with backoff, a per-connector minimum interval, and `file:`
    / repository-relative paths so samples and fixtures work offline."""

    def __init__(self, min_interval_s: float = 1.0, retries: int = 4, timeout_s: float = 60,
                 transport: httpx.BaseTransport | None = None):
        self.client = httpx.Client(timeout=timeout_s, follow_redirects=True, transport=transport,
                                   headers={"User-Agent": "threat-hunting-engine/0.9 (+ti-connectors)"})
        self.min_interval, self.retries, self._last = min_interval_s, retries, 0.0

    @staticmethod
    def local_path(url: str) -> Path | None:
        if url.startswith("file://"):
            return Path(url[7:])
        if "://" not in url:
            p = Path(url)
            return p if p.is_absolute() else REPO_ROOT / p
        return None

    def request(self, method: str, url: str, **kw) -> RawPayload:
        local = self.local_path(url)
        if local is not None:
            return RawPayload(str(local), local.read_bytes(), "")
        delay = 2.0
        for attempt in range(1, self.retries + 1):
            wait = self._last + self.min_interval - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()
            try:
                r = self.client.request(method, url, **kw)
            except httpx.HTTPError:
                if attempt == self.retries:
                    raise
                time.sleep(delay)
                delay *= 2
                continue
            if r.status_code in (429, 500, 502, 503, 504) and attempt < self.retries:
                time.sleep(min(float(r.headers.get("retry-after", delay)), 120))
                delay *= 2
                continue
            r.raise_for_status()
            return RawPayload(url, r.content, r.headers.get("content-type", ""))
        raise RuntimeError("unreachable")

    def get(self, url: str, **kw) -> RawPayload:
        return self.request("GET", url, **kw)

    def post(self, url: str, **kw) -> RawPayload:
        return self.request("POST", url, **kw)


class FeedConnector:
    name: str = ""
    version: str = "1"
    feed_generation: str = "legacy"    # legacy | modern | reference
    default_config: dict = {}

    def __init__(self, config: dict, http: Http, offline: bool):
        self.config, self.http, self.offline = config, http, offline

    # -- what a connector implements -------------------------------------------------------
    def fetch(self, since: datetime | None) -> list[RawPayload]:
        raise NotImplementedError

    def parse(self, raw: RawPayload) -> list[Indicator]:
        raise NotImplementedError

    def apply_reference(self, raws: list[RawPayload]) -> dict:
        """Reference feeds (ATT&CK, ...) may update local reference data here."""
        return {}

    # -- helpers ---------------------------------------------------------------------------
    @property
    def schedule_minutes(self) -> int:
        return int(self.config.get("schedule_minutes", 60))

    def secret(self) -> str | None:
        env = self.config.get("auth_env")
        return os.environ.get(env) if env else None

    def sample(self) -> RawPayload:
        return self.http.get(self.config["sample"])

    def source_url(self) -> str:
        if self.offline or not self.config.get("url"):
            return self.config["sample"]
        return self.config["url"]


# --------------------------------------------------------------------------- registry + config
@lru_cache
def registry() -> dict[str, type[FeedConnector]]:
    import engine.ti.connectors as pkg
    found: dict[str, type[FeedConnector]] = {}
    for mod in pkgutil.iter_modules(pkg.__path__):
        if mod.name in ("sdk",) or mod.name.startswith("_"):
            continue
        m = importlib.import_module(f"engine.ti.connectors.{mod.name}")
        for obj in vars(m).values():
            if isinstance(obj, type) and issubclass(obj, FeedConnector) and obj is not FeedConnector and obj.name:
                found[obj.name] = obj
    return found


@lru_cache
def feeds_policy() -> dict:
    return yaml.safe_load((REPO_ROOT / "policies" / "ti_feeds.yaml").read_text())


@lru_cache
def warninglists() -> dict:
    return yaml.safe_load((REPO_ROOT / "policies" / "warninglists.yaml").read_text())["lists"]


def feed_config(name: str) -> dict:
    cls = registry().get(name)
    if cls is None:
        raise KeyError(f"unknown connector {name!r}; known: {sorted(registry())}")
    pol = feeds_policy()
    cfg = {**pol.get("defaults", {}), **(cls.default_config or {}), **(pol.get("feeds", {}).get(name) or {})}
    cfg.setdefault("enabled", False)
    return cfg


def offline_mode() -> bool:
    env = os.environ.get("TI_FEEDS_OFFLINE")
    if env is not None:
        return env.lower() in ("1", "true", "yes")
    return bool(feeds_policy().get("offline", True))


def make_connector(name: str, transport: httpx.BaseTransport | None = None) -> FeedConnector:
    cfg = feed_config(name)
    return registry()[name](cfg, Http(transport=transport), offline_mode())


def tlp_norm(v: str | None, default: str = "TLP:CLEAR") -> str:
    if not v:
        return default
    s = str(v).upper().strip().replace(" ", "")
    s = s if s.startswith("TLP:") else f"TLP:{s}"
    s = TLP_ALIASES.get(s, TLP_ALIASES.get(s[4:], s))
    return s if s in TLP_ORDER else default


def tlp_allows(tlp: str, maximum: str) -> bool:
    return TLP_ORDER.index(tlp_norm(tlp)) <= TLP_ORDER.index(tlp_norm(maximum))


def warninglisted(type_: str, value: str) -> str | None:
    for name, lst in warninglists().items():
        kind, values = lst.get("type"), lst.get("values") or []
        if kind == "ip" and type_ in ("ipv4", "ipv6", "ip:port") and value.split(":")[0] in values:
            return name
        if kind == "cidr" and type_ in ("ipv4", "ip:port"):
            try:
                ip = ipaddress.ip_address(value.rsplit(":", 1)[0] if type_ == "ip:port" else value)
                if any(ip in ipaddress.ip_network(c) for c in values):
                    return name
            except ValueError:
                pass
        if kind == "domain_suffix" and type_ in ("domain", "url"):
            host = value.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
            if any(host == d or host.endswith("." + d) for d in values):
                return name
    return None


def parse_ts(v) -> datetime | None:
    if v in (None, "", "None"):
        return None
    if isinstance(v, datetime):
        return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
    if isinstance(v, (int, float)):
        return datetime.fromtimestamp(float(v), tz=timezone.utc)
    s = str(v).strip().replace(" UTC", "").replace("Z", "+00:00")
    for fmt in (None, "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            d = datetime.fromisoformat(s) if fmt is None else datetime.strptime(s, fmt)
            return d if d.tzinfo else d.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


# --------------------------------------------------------------------------- ingest
def _techniques(ind: Indicator) -> list[str]:
    from engine.ti.attack import attack
    att = attack()
    techs = [t.upper() for t in ind.attack_techniques if att.technique(t)]
    if not techs:
        techs = list(THREAT_TYPE_TECHNIQUES.get((ind.threat_type or "").lower(), []))
        for tag in [*ind.tags, ind.malware_family or ""]:
            techs += TAG_TECHNIQUES.get(str(tag).lower(), [])
    return sorted({t for t in techs if att.technique(t)})


def to_rows(source: str, version: str, cfg: dict, records: list[Indicator]) -> list[dict]:
    pol = feeds_policy()
    decay = pol.get("decay_days", {})
    weight = float(cfg.get("confidence_weight", 1.0))
    now = T.now()
    rows: dict[str, dict] = {}
    for r in records:
        try:
            typ = r.type or T.detect_type(T.refang(r.value))
            if typ is None:
                continue
            value = T.normalise(typ, r.value) if typ != "cve" else r.value.strip().upper()
        except Exception:  # noqa: BLE001 - one malformed record must not fail the pull
            log.debug("skipping malformed indicator %r from %s", r.value, source)
            continue
        iid = T.indicator_id(typ, value) if typ != "cve" else hashlib.sha256(f"cve\x1f{value}".encode()).hexdigest()[:24]
        conf = r.confidence if r.confidence is not None else cfg.get("default_confidence", 75)
        conf = int(max(0, min(100, round(float(conf) / float(r.confidence_scale or 100) * 100 * weight))))
        last = r.last_seen or r.first_seen or now
        first = r.first_seen or last
        days = decay.get(typ)
        wl = warninglisted(typ, value)
        row = {"indicator_id": iid, "type": typ, "value": value, "source": source, "source_ref": r.source_ref,
               "threat_type": r.threat_type, "malware_family": r.malware_family,
               "malware_aliases": sorted({a for a in r.malware_aliases if a}), "attack_techniques": _techniques(r),
               "confidence": conf, "tlp": tlp_norm(r.tlp, tlp_norm(cfg.get("tlp"))), "first_seen": first,
               "last_seen": last, "expires_at": last + timedelta(days=days) if days else None,
               "org_sightings": 0, "org_first_sighting": None, "org_last_sighting": None,
               "status": "false_positive" if wl else "active",
               "tags": sorted({str(t) for t in r.tags if t} | ({f"warninglist:{wl}"} if wl else set())),
               "reference": r.reference, "connector_version": f"{source}/{version}", "ingested_at": now}
        if row["expires_at"] and row["expires_at"] < now and row["status"] == "active":
            row["status"] = "expired"
        prev = rows.get(iid)
        if prev:
            row["confidence"] = max(row["confidence"], prev["confidence"])
            row["tags"] = sorted(set(row["tags"]) | set(prev["tags"]))
            row["first_seen"] = min(row["first_seen"], prev["first_seen"])
            row["last_seen"] = max(row["last_seen"], prev["last_seen"])
        rows[iid] = row
    return list(rows.values())


def sweepable(row: dict) -> list[tuple[str, str]]:
    """(group, value) pairs a retro-sweep can look for through the exact-term index."""
    if row["status"] != "active":
        return []
    out = []
    for v in T.sweep_values(row["type"], row["value"]):
        t = T.detect_type(v)
        if t in ("ipv4", "ipv6"):
            out.append(("ip", v))
        elif t == "domain":
            out.append(("domain", v))
        elif t == "sha256":
            out.append(("sha256", v))
    return out


def sweep_rule(source: str, rows: list[dict]) -> str:
    groups: dict[str, set[str]] = {"ip": set(), "domain": set(), "sha256": set()}
    for r in rows:
        for g, v in sweepable(r):
            groups[g].add(v)
    detection, n = {}, 0
    for g, values in groups.items():
        if not values:
            continue
        for f in SWEEP_FIELDS[g]:
            n += 1
            detection[f"sel_{n}"] = {f: sorted(values)}
    detection["condition"] = "1 of sel_*"
    rule = {"title": f"Retro-sweep: {sum(len(v) for v in groups.values())} new indicator value(s) from {source}",
            "id": str(uuid.uuid5(uuid.NAMESPACE_URL, "sweep:" + ",".join(sorted(r["indicator_id"] for r in rows)))),
            "status": "experimental", "description": "Generated IOC sweep over the full retention window (M7).",
            "author": "ti-connectors", "logsource": {"product": "ecs"}, "detection": detection, "level": "high",
            "tags": ["attack.command_and_control"]}
    return yaml.safe_dump(rule, sort_keys=False)


def ingest(ctx, source: str, version: str, cfg: dict, records: list[Indicator], sweep_label: str) -> dict:
    """Merge canonical records into ti.tactical; emit events; queue the retro-sweep."""
    from engine.cqrs.commands import SubmitRule
    from engine.cqrs.writer_queue import enqueue
    from engine.retention.policy import minimum_years
    rows = to_rows(source, version, cfg, records)
    ids = [r["indicator_id"] for r in rows]
    existing = T.read_keys(ctx.settings, T.TACTICAL, "indicator_id", ids)
    known_ids = {e["indicator_id"] for e in existing}
    same_source = {e["indicator_id"]: e for e in existing if e["source"] == source}
    for r in rows:
        prev = same_source.get(r["indicator_id"])
        if prev:                                     # keep org sightings and the earliest first_seen
            for k in ("org_sightings", "org_first_sighting", "org_last_sighting"):
                r[k] = prev.get(k)
            r["first_seen"] = min(x for x in (prev.get("first_seen"), r["first_seen"]) if x)
            if prev["status"] in ("revoked", "false_positive") and r["status"] == "active":
                r["status"] = prev["status"]         # analyst decisions stick
    others = [e for e in existing if e["source"] != source]
    now = T.now()
    stale, _ = T.read_all(ctx.settings, T.TACTICAL)
    expired = [dict(e, status="expired") for e in stale if e["source"] == source and e["status"] == "active"
               and e.get("expires_at") and e["expires_at"] < now and e["indicator_id"] not in set(ids)]
    T.upsert(ctx.settings, T.TACTICAL, "indicator_id", rows + others + expired)

    new_rows = [r for r in rows if r["indicator_id"] not in known_ids]
    events = [IndicatorRecorded(indicator_id=r["indicator_id"], type=r["type"], value=r["value"], source=source,
                                threat_type=r["threat_type"], malware_family=r["malware_family"],
                                confidence=r["confidence"], tlp=r["tlp"], status=r["status"], new=True)
              for r in new_rows[:500]]
    sweep_run, to_sweep = None, [r for r in new_rows if sweepable(r)]
    to_sweep = to_sweep[: int(cfg.get("sweep_max_indicators", 2000))]
    if to_sweep and cfg.get("sweep_new_indicators", True):
        sweep_run = str(uuid.uuid4())
        end = now
        start = end - timedelta(days=365 * minimum_years() + 4)
        enqueue(ctx.conn, SubmitRule(rule_yaml=sweep_rule(source, to_sweep), start=start, end=end, run_id=sweep_run,
                                     origin="feed_sweep", submitted_by=f"ti-connectors:{source}",
                                     context={"indicator_ids": [r["indicator_id"] for r in to_sweep],
                                              "connector": source, "trigger": sweep_label}),
                submitted_by="ti-connectors")
    return {"rows": rows, "new": len(new_rows), "updated": len(rows) - len(new_rows),
            "suppressed": sum(1 for r in rows if r["status"] == "false_positive"),
            "expired": len(expired), "events": events, "sweep_run_id": sweep_run, "swept": len(to_sweep)}


def pull(ctx, name: str, since: str | None, payload_uri: str | None = None) -> tuple[list, dict]:
    conn = make_connector(name)
    cfg = conn.config
    state = ctx.conn.execute(select(feed_state).where(feed_state.c.connector == name)).first()
    cursor = since or (state.cursor if state else None)
    if payload_uri:                                   # pushed batch (webhook / stream consumer)
        raws = [RawPayload(payload_uri, ctx.store.get_bytes(payload_uri), "application/json")]
    else:
        raws = conn.fetch(parse_ts(cursor))
    now = T.now()
    T.append(ctx.settings, T.FEED_RAW, [{
        "connector": name, "connector_version": conn.version, "pulled_at": now, "cursor": cursor, "url": r.url,
        "sha256": hashlib.sha256(r.body).hexdigest(), "bytes": len(r.body), "records": None,
        "payload": r.body[:5_000_000].decode("utf-8", "replace"), "day": now.date().isoformat()} for r in raws])
    records = [i for r in raws for i in conn.parse(r)]
    detail = conn.apply_reference(raws) if conn.feed_generation == "reference" else {}
    result = ingest(ctx, name, conn.version, cfg, records, f"pull:{name}:{now.isoformat()}") if records else \
        {"rows": [], "new": 0, "updated": 0, "suppressed": 0, "expired": 0, "events": [], "sweep_run_id": None,
         "swept": 0}
    new_cursor = next((r.cursor for r in reversed(raws) if r.cursor), None) or \
        max((r["last_seen"] for r in result["rows"] if r["last_seen"]), default=now).isoformat()
    upsert(ctx.conn, feed_state, {"connector": name}, {
        "generation": conn.feed_generation, "version": conn.version, "cursor": new_cursor, "last_pull_at": utcnow(),
        "last_status": "ok", "records": len(records), "new": result["new"], "error": None,
        "offline": conn.offline})
    event = FeedPulled(connector=name, version=conn.version, generation=conn.feed_generation,
                       offline=conn.offline, payloads=len(raws), records=len(records), indicators_new=result["new"],
                       indicators_updated=result["updated"], suppressed=result["suppressed"],
                       expired=result["expired"], cursor=new_cursor, sweep_run_id=result["sweep_run_id"],
                       swept=result["swept"], reference=detail)
    return [*result["events"], event], {"connector": name, "records": len(records), "new": result["new"],
                                        "suppressed": result["suppressed"], "sweep_run_id": result["sweep_run_id"],
                                        **({"reference": detail} if detail else {})}


def raw_json(raw: RawPayload):
    return json.loads(raw.body.decode("utf-8-sig"))
