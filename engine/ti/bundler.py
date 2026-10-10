"""Behaviour bundles for TI enrichment (plan.md section 3.9, steps 1-2).

A bundle is everything the engine knows about one entity in one time window: the rule hits
on it (from every rule's latest run) plus the artefact rows for that entity and day. Before a
bundle can leave the boundary it is redacted:

  * users, hosts, IPs and groups become HMAC pseudonyms (policies/llm_egress.yaml);
  * command lines become features (length, entropy, flags, LOLBin match) unless the policy
    explicitly allows sending them; URLs are reduced to their (external) domain;
  * a final pass replaces any remaining known identifier (from the identity directory, the
    asset inventory and the bundle's own values), and `assert_clean` refuses to send a
    payload that still contains one.

Raw logs are never part of a bundle: only rule hits and artefacts.
"""
from __future__ import annotations

import hashlib
import json
import math
import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import lru_cache

import yaml
from pyiceberg.expressions import EqualTo, In
from sqlalchemy import select

from engine.common.catalog import get_catalog
from engine.common.config import REPO_ROOT, Settings
from engine.common.db import assets, identities, identity_aliases, ip_leases, rule_runs, rules
from engine.common.pseudonymise import is_internal_ip, is_ip, pseudonym

LOLBINS = {"certutil.exe", "rundll32.exe", "mshta.exe", "bitsadmin.exe", "regsvr32.exe", "wmic.exe", "msiexec.exe",
           "cscript.exe", "wscript.exe", "installutil.exe", "psexesvc.exe", "powershell.exe", "cmd.exe"}
USER_FIELDS = {"user.name", "user.target.name", "user_name", "principal", "users"}
HOST_FIELDS = {"host.name", "host_name", "entity_host"}
IP_FIELDS = {"source.ip", "destination.ip", "src_ips", "dest_ip", "ip", "related.ip"}


@lru_cache
def egress_policy() -> dict:
    return yaml.safe_load((REPO_ROOT / "policies" / "llm_egress.yaml").read_text())


def entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    return round(-sum(n / len(s) * math.log2(n / len(s)) for n in c.values()), 3)


def cmdline_features(cmd: str | None) -> dict | None:
    if not cmd:
        return None
    tokens = cmd.replace('"', " ").split()
    exe = tokens[0].split("\\")[-1].lower() if tokens else ""
    flags = sorted({t.lower() for t in tokens[1:] if t.startswith(("-", "/")) and len(t) <= 24})[:15]
    long_tokens = [t for t in tokens if len(t) >= 40]
    return {"executable": exe, "length": len(cmd), "entropy": entropy(cmd), "flags": flags,
            "lolbin": exe in LOLBINS, "has_url": "http://" in cmd.lower() or "https://" in cmd.lower(),
            "url_domains": sorted({m.lower() for m in re.findall(r"https?://([A-Za-z0-9.-]+)", cmd)}),
            "long_token_count": len(long_tokens),
            "base64_like": any(re.fullmatch(r"[A-Za-z0-9+/=]{40,}", t) for t in long_tokens),
            "mentions": sorted({w for w in ("downloadstring", "iex", "frombase64string", "urlcache", "stratum",
                                            "whoami", "net group", "domain admins", "transfer", "-enc",
                                            "hidden", "bypass", "donate-level")
                                if w in cmd.lower()})}


@dataclass
class Bundle:
    bundle_id: str
    entity_type: str
    entity: str                      # original value (never sent)
    entity_pseudonym: str
    window_start: datetime
    window_end: datetime
    asset_class: str | None
    business_unit: str | None
    evidence: list[dict] = field(default_factory=list)       # redacted, sent
    refs: dict[str, str] = field(default_factory=dict)       # evidence id -> internal reference
    hits: list[dict] = field(default_factory=list)           # original hits (never sent)
    rule_ids: set[str] = field(default_factory=set)

    def payload(self) -> dict:
        """Exactly what may leave the boundary (plain JSON types only)."""
        return json.loads(json.dumps({
            "entity": {"type": self.entity_type, "id": self.entity_pseudonym, "asset_class": self.asset_class,
                       "business_unit": self.business_unit},
            "window": {"start": self.window_start.isoformat(), "end": self.window_end.isoformat()},
            "evidence": self.evidence}, default=str))

    @property
    def bundle_hash(self) -> str:
        return hashlib.sha256(json.dumps(self.payload(), sort_keys=True, default=str).encode()).hexdigest()[:32]


class Redactor:
    def __init__(self, conn, settings: Settings):
        self.settings = settings
        pol = egress_policy()["egress"]
        self.send_cmd = bool(pol.get("send_command_lines"))
        self.internal_suffixes = tuple("." + s.lstrip(".") for s in pol.get("internal_domain_suffixes", []))
        # Known identifiers -> pseudonym: the final replace pass and the egress check use these.
        self.known: dict[str, str] = {}
        for r in conn.execute(select(identities.c.name, identities.c.upn, identities.c.display_name)
                              .where(identities.c.kind != "builtin")):
            for v in (r.name, r.upn, r.display_name):
                if v and len(v) >= 4:
                    self.known[v.lower()] = pseudonym(settings, "user", r.name)
        for r in conn.execute(select(identity_aliases.c.alias, identity_aliases.c.user_id)):
            if r.alias and len(r.alias) >= 4 and not r.alias.startswith("s-1-"):
                self.known.setdefault(r.alias.lower(), pseudonym(settings, "user", r.alias))
        for r in conn.execute(select(assets.c.host_name, assets.c.fqdn, assets.c.static_ip)):
            for v in (r.host_name, r.fqdn):
                if v:
                    self.known[v.lower()] = pseudonym(settings, "host", r.host_name)
            if r.static_ip:
                self.known[r.static_ip] = pseudonym(settings, "ip", r.static_ip)
        for r in conn.execute(select(ip_leases.c.ip).distinct()):
            self.known[r.ip] = pseudonym(settings, "ip", r.ip)
        self.restricted = restricted_indicator_values(settings, pol.get("tlp_max", "TLP:AMBER"))

    def internal_domain(self, d: str) -> bool:
        d = d.lower().rstrip(".")
        return any(d.endswith(s) or d == s.lstrip(".") for s in self.internal_suffixes)

    def value(self, fieldname: str, v):
        if v is None:
            return None
        if isinstance(v, list):
            return [self.value(fieldname, x) for x in v]
        s = str(v)
        if s.lower() in self.restricted:
            return pseudonym(self.settings, "ioc", s)          # TLP above the egress maximum
        f = fieldname.lower()
        if f in USER_FIELDS or f.endswith("user.name"):
            return pseudonym(self.settings, "user", s)
        if f in HOST_FIELDS:
            return pseudonym(self.settings, "host", s)
        if f in ("group.name", "group_name"):
            return pseudonym(self.settings, "group", s)
        if f in IP_FIELDS or is_ip(s):
            return pseudonym(self.settings, "ip", s) if is_ip(s) else self.scrub(s)
        if f in ("process.command_line", "process.parent.command_line"):
            return self.scrub(s) if self.send_cmd else cmdline_features(s)
        if f in ("url.full",):
            m = re.match(r"(?i)^[a-z]+://([^/:]+)", s)
            dom = m.group(1).lower() if m else None
            return {"domain": dom if dom and not self.internal_domain(dom) else pseudonym(self.settings, "host", dom),
                    "path_length": len(s.split("/", 3)[3]) if s.count("/") >= 3 else 0}
        if f in ("dns.question.name", "registered_domain", "dns.question.registered_domain", "url.domain",
                 "destination.domain", "entity_domain"):
            return pseudonym(self.settings, "host", s) if self.internal_domain(s) else s.lower()
        return self.scrub(s) if isinstance(v, str) else v

    def scrub(self, s: str) -> str:
        """Replace any known identifier or internal IP still present in free text."""
        out = s
        for ip in set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", out)):
            if is_internal_ip(ip) or ip in self.known:
                out = out.replace(ip, pseudonym(self.settings, "ip", ip))
        low = out.lower()
        for ident in sorted(self.known, key=len, reverse=True):
            if not is_ip(ident) and ident in low:
                out = re.sub(rf"(?<![A-Za-z0-9_.-]){re.escape(ident)}(?![A-Za-z0-9_-])", self.known[ident], out,
                             flags=re.IGNORECASE)
                low = out.lower()
        return out

    def row(self, row: dict) -> dict:
        return {k: self.value(k, v) for k, v in row.items() if v is not None and k not in ("built_at", "day",
                                                                                            "feature_version")}

    def leaks(self, payload: dict, extra: set[str] = frozenset()) -> list[str]:
        text = json.dumps(payload, default=str).lower()
        found = []
        for ident in set(self.known) | self.restricted | {e.lower() for e in extra if e}:
            if is_ip(ident):
                if re.search(rf"(?<![\d.]){re.escape(ident)}(?![\d.])", text):
                    found.append(ident)
            elif len(ident) >= 4 and re.search(rf"(?<![a-z0-9_.-]){re.escape(ident)}(?![a-z0-9_-])", text):
                found.append(ident)
        for ip in set(re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)):
            if is_internal_ip(ip):
                found.append(ip)
        return sorted(set(found))


def restricted_indicator_values(settings: Settings, tlp_max: str) -> set[str]:
    """Indicator values whose TLP marking is above `tlp_max` (they may not leave the boundary)."""
    from engine.ti import tables as T
    from engine.ti.connectors.sdk import tlp_allows
    try:
        rows, _ = T.read_all(settings, T.TACTICAL)
    except Exception:  # noqa: BLE001 - no TI tables yet
        return set()
    out = set()
    for r in rows:
        if not tlp_allows(r.get("tlp") or "TLP:CLEAR", tlp_max):
            out.update(v.lower() for v in T.sweep_values(r["type"], r["value"]))
            out.add(r["value"].lower())
    return out


def assert_clean(redactor: Redactor, payload: dict, extra: set[str]) -> None:
    leaks = redactor.leaks(payload, extra)
    if leaks:
        raise PermissionError(f"egress refused: payload still contains {len(leaks)} identifier(s)")


def entity_context(conn, entity_type: str, entity: str) -> tuple[str | None, str | None]:
    if entity_type == "host":
        r = conn.execute(select(assets.c.asset_class, assets.c.business_unit)
                         .where(assets.c.host_name == entity.lower())).first()
        return (r.asset_class, r.business_unit) if r else ("unknown", None)
    if entity_type == "user":
        r = conn.execute(select(identities.c.department, identities.c.kind)
                         .where(identities.c.name == entity.lower())).first()
        return ("user" if not r or r.kind == "human" else r.kind), (r.department or None) if r else None
    return "network", None


def entity_of(hit: dict) -> tuple[str, str]:
    if hit.get("host_name"):
        return "host", str(hit["host_name"]).lower()
    if hit.get("user_name"):
        return "user", str(hit["user_name"]).lower()
    if hit.get("source_ip"):
        return "ip", str(hit["source_ip"]).lower()
    ent = hit["entity_key"].rsplit("@", 1)[0]
    return ("ip" if is_ip(ent) else "entity"), ent


def run_hits(settings: Settings, run_id: str) -> list[dict]:
    from pyiceberg.exceptions import NoSuchTableError
    try:
        t = get_catalog(settings).load_table("results.rule_hits")
    except NoSuchTableError:
        return []
    return t.scan(row_filter=EqualTo("run_id", run_id)).to_arrow().to_pylist()


def latest_runs(conn) -> dict[str, str]:
    """rule_id -> latest succeeded, non-replay run id."""
    out: dict[str, tuple] = {}
    for r in conn.execute(select(rule_runs.c.rule_id, rule_runs.c.run_id, rule_runs.c.finished_at)
                          .where(rule_runs.c.status == "succeeded", rule_runs.c.replay_of.is_(None))):
        if r.rule_id not in out or (r.finished_at and out[r.rule_id][1] and r.finished_at > out[r.rule_id][1]):
            out[r.rule_id] = (r.run_id, r.finished_at)
    return {k: v[0] for k, v in out.items()}


def build_bundles(conn, settings: Settings, run_id: str, redactor: Redactor | None = None) -> list[Bundle]:
    """Bundles for every entity the run hit, with context from the latest run of every rule."""
    from pyiceberg.exceptions import NoSuchTableError
    redactor = redactor or Redactor(conn, settings)
    pol = egress_policy()
    window = timedelta(hours=pol["bundling"]["window_hours"])
    own = run_hits(settings, run_id)
    if not own:
        return []
    keys = sorted({h["entity_key"] for h in own})
    cat = get_catalog(settings)
    latest = set(latest_runs(conn).values()) | {run_id}
    hits = cat.load_table("results.rule_hits").scan(row_filter=In("entity_key", keys)).to_arrow().to_pylist()
    hits = [h for h in hits if h["run_id"] in latest]
    titles = {r.rule_id: (r.title, (r.compiled or {}).get("techniques", []), r.level)
              for r in conn.execute(select(rules.c.rule_id, rules.c.title, rules.c.compiled, rules.c.level))}

    by_entity: dict[tuple[str, str], list[dict]] = defaultdict(list)
    for h in hits:
        by_entity[entity_of(h)].append(h)
    days = sorted({h["day"] for h in hits})
    artefacts: dict[str, list[dict]] = {}
    for table in ("artefacts.process_lineage_edges", "artefacts.auth_graph_edges", "artefacts.candidates"):
        try:
            t = cat.load_table(table)
        except NoSuchTableError:
            continue
        artefacts[table] = t.scan(row_filter=In("day", days)).to_arrow().to_pylist() if days else []

    out: list[Bundle] = []
    for (etype, entity), ehits in sorted(by_entity.items()):
        ehits.sort(key=lambda h: h["ts"] or datetime.min.replace(tzinfo=timezone.utc))
        groups: list[list[dict]] = []
        for h in ehits:
            if groups and h["ts"] and groups[-1][0]["ts"] and h["ts"] - groups[-1][0]["ts"] <= window:
                groups[-1].append(h)
            else:
                groups.append([h])
        asset_class, bu = entity_context(conn, etype, entity)
        for g in groups:
            if not any(h["run_id"] == run_id for h in g):
                continue                      # bundles only for what this run found
            g = g[: pol["egress"]["max_hits_per_bundle"]]
            start = g[0]["ts"] or datetime.min.replace(tzinfo=timezone.utc)
            end = g[-1]["ts"] or start
            b = Bundle(bundle_id="", entity_type=etype, entity=entity,
                       entity_pseudonym=pseudonym(settings, etype if etype in ("host", "user", "ip") else "entity",
                                                  entity),
                       window_start=start, window_end=end, asset_class=asset_class, business_unit=bu, hits=g)
            for i, h in enumerate(g, 1):
                eid = f"e{i}"
                title, techs, level = titles.get(h["rule_id"], ("?", [], None))
                ev = json.loads(h["evidence"] or "{}")
                grp = json.loads(h["group_key"]) if h.get("group_key") else None
                b.evidence.append({"id": eid, "kind": "rule_hit", "rule": title, "rule_level": level,
                                   "rule_techniques": techs, "tier": h["tier"], "exact": h["exact"],
                                   "ts": h["ts"].isoformat() if h["ts"] else None, "count": h["count"],
                                   "fields": {k: redactor.value(k, v) for k, v in ev.items()},
                                   "group": {k: redactor.value(k, v) for k, v in grp.items()} if grp else None})
                b.refs[eid] = f"hit:{h['run_id']}:{h['hit_key']}"
                b.rule_ids.add(h["rule_id"])
            n = 0
            day = start.date().isoformat() if start.year > 1 else None
            for table, rows in artefacts.items():
                for row in rows:
                    if row.get("day") != day or n >= pol["egress"]["max_artefact_rows_per_bundle"]:
                        continue
                    vals = {str(row.get(c, "")).lower() for c in ("host_name", "user_name", "entity")}
                    if entity not in vals:
                        continue
                    n += 1
                    aid = f"a{n}"
                    b.evidence.append({"id": aid, "kind": "artefact", "table": table.split(".", 1)[1],
                                       "row": redactor.row(row)})
                    b.refs[aid] = f"art:{table}:{hashlib.sha256(json.dumps(row, sort_keys=True, default=str).encode()).hexdigest()[:16]}"
            b.bundle_id = b.bundle_hash
            out.append(b)
    return out
