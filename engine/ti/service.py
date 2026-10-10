"""TI command handlers (queue `ti`, the single writer of the ti.* tables).

    RecordRuleObservations(run_id)   rule hits -> ti.operational (origin=rule), sightings of
                                     known indicators, internal indicators -> ti.tactical
    EnrichBehavior(run_id)           bundles -> redaction -> LLM -> validation -> ti.operational
                                     (origin=llm) + internal indicators
    ReviewPattern(target, verdict)   analyst verdict on an observation or a whole pattern
    BuildStrategicRollup(period)     ti.operational + ti.tactical -> ti.strategic
"""
from __future__ import annotations

import hashlib
import logging
from collections import Counter, defaultdict
from datetime import datetime, timezone

from sqlalchemy import select

from engine.common import stages
from engine.common.db import llm_egress, rules, utcnow
from engine.common.events import BehaviorPatternRecorded, PatternReviewed, StrategicRollupBuilt
from engine.common.pseudonymise import is_internal_ip, pseudonym
from engine.ti import tables as T
from engine.ti.attack import attack
from engine.ti.bundler import Redactor, assert_clean, build_bundles, egress_policy, entity_context, entity_of, run_hits

log = logging.getLogger(__name__)
LEVEL_CONFIDENCE = {"critical": 95, "high": 85, "medium": 70, "low": 55, "informational": 40}


def _h(*parts) -> str:
    return hashlib.sha256("\x1f".join(map(str, parts)).encode()).hexdigest()[:24]


def _utc(d):
    return d if d is None or d.tzinfo else d.replace(tzinfo=timezone.utc)


def _external(value: str, redactor: Redactor) -> bool:
    t = T.detect_type(value)
    if t in ("ipv4", "ipv6"):
        return not is_internal_ip(value)
    if t == "domain":
        return not redactor.internal_domain(value)
    return t in ("md5", "sha1", "sha256")


def _active_indicators(settings, values: set[str]) -> dict[str, list[dict]]:
    """value -> active tactical rows whose sweep values include it."""
    rows, _ = T.read_all(settings, T.TACTICAL)
    out: dict[str, list[dict]] = defaultdict(list)
    for r in rows:
        if r["status"] != "active":
            continue
        for v in T.sweep_values(r["type"], r["value"]):
            if v in values:
                out[v].append(r)
    return out


def update_sightings(settings, sightings: dict[str, list[datetime]]) -> list[dict]:
    """indicator_id -> sighting timestamps. Recomputes org_* columns for every source row."""
    if not sightings:
        return []
    existing = T.read_keys(settings, T.TACTICAL, "indicator_id", list(sightings))
    for r in existing:
        ts = sorted(t for t in sightings[r["indicator_id"]] if t)
        r["org_sightings"] = max(r.get("org_sightings") or 0, len(ts))
        if ts:
            r["org_first_sighting"] = min([x for x in (r.get("org_first_sighting"), ts[0]) if x])
            r["org_last_sighting"] = max([x for x in (r.get("org_last_sighting"), ts[-1]) if x])
    T.upsert(settings, T.TACTICAL, "indicator_id", existing)
    return existing


def record_internal_indicators(settings, found: dict[tuple[str, str], list[datetime]], techniques: list[str],
                               connector: str) -> int:
    """(type, value) -> sighting times. Adds/refreshes source=internal rows; feed rows keep theirs."""
    if not found:
        return 0
    ids = {T.indicator_id(t, v): (t, v) for t, v in found}
    existing = {(r["indicator_id"], r["source"]): r for r in T.read_keys(settings, T.TACTICAL, "indicator_id",
                                                                          list(ids))}
    now = T.now()
    rows = [r for r in existing.values()]
    for iid, (typ, val) in ids.items():
        ts = sorted(x for x in found[(typ, val)] if x)
        cur = existing.get((iid, "internal"))
        if cur is None:
            cur = {"indicator_id": iid, "type": typ, "value": T.normalise(typ, val), "source": "internal",
                   "source_ref": None, "threat_type": None, "malware_family": None, "malware_aliases": [],
                   "attack_techniques": [], "confidence": 50, "tlp": "TLP:AMBER", "first_seen": ts[0] if ts else now,
                   "last_seen": ts[-1] if ts else now, "expires_at": None, "org_sightings": 0,
                   "org_first_sighting": None, "org_last_sighting": None, "status": "active", "tags": ["internal"],
                   "reference": None, "connector_version": connector, "ingested_at": now}
            rows.append(cur)
        cur["attack_techniques"] = sorted(set(cur["attack_techniques"] or []) | set(techniques))
        cur["org_sightings"] = max(cur.get("org_sightings") or 0, len(ts))
        if ts:
            cur["last_seen"] = max([x for x in (cur.get("last_seen"), ts[-1]) if x])
            cur["org_first_sighting"] = min([x for x in (cur.get("org_first_sighting"), ts[0]) if x])
            cur["org_last_sighting"] = max([x for x in (cur.get("org_last_sighting"), ts[-1]) if x])
    T.upsert(settings, T.TACTICAL, "indicator_id", rows)
    return len(ids)


def _observation_events(rows: list[dict]) -> list[BehaviorPatternRecorded]:
    return [BehaviorPatternRecorded(
        observation_id=r["observation_id"], pattern_id=r["pattern_id"], title=r["title"], origin=r["origin"],
        status=r["status"], techniques=r["attack_techniques"], tactics=r["attack_tactics"],
        entity_pseudonym=r["entity_pseudonym"], asset_class=r["asset_class"], business_unit=r["business_unit"],
        severity=r["severity"], confidence=r["confidence"], rule_run_id=r["rule_run_id"],
        observed_at=r["observed_at"], threat_family=r["threat_family"],
        matched_indicators=len(r["matched_indicator_ids"] or [])) for r in rows]


# --------------------------------------------------------------------------- rule observations
def record_rule_observations(cmd, ctx):
    from engine.cqrs.handlers import HandlerResult
    from engine.cqrs.writer_queue import enqueue
    settings = ctx.settings
    hits = run_hits(settings, cmd.run_id)
    if not hits:
        return HandlerResult(detail={"run_id": cmd.run_id, "observations": 0})
    rule_id = hits[0]["rule_id"]
    rule = ctx.conn.execute(select(rules).where(rules.c.rule_id == rule_id)).first()
    compiled = rule.compiled if rule else {}
    att = attack()
    techniques = [t for t in compiled.get("techniques", []) if att.technique(t)]
    tactics = [t for t in compiled.get("tactics", []) if att.valid_tactic(t)] or att.tactics_of(techniques)
    redactor = Redactor(ctx.conn, settings)
    observables = {o for h in hits for o in (h.get("observables") or [])}
    known = _active_indicators(settings, observables)

    groups: dict[str, list[dict]] = defaultdict(list)
    for h in hits:
        groups[h["entity_key"]].append(h)
    rows, sightings, internal = [], defaultdict(list), defaultdict(list)
    for key, g in sorted(groups.items()):
        etype, entity = entity_of(g[0])
        asset_class, bu = entity_context(ctx.conn, etype, entity)
        ts = sorted(h["ts"] for h in g if h["ts"])
        matched_rows = {r["indicator_id"]: r for h in g for o in (h.get("observables") or []) for r in known.get(o, [])}
        for h in g:
            for o in h.get("observables") or []:
                for r in known.get(o, []):
                    sightings[r["indicator_id"]].append(h["ts"])
                if (rule.level if rule else None) in ("high", "critical") and _external(o, redactor):
                    t = T.detect_type(o)
                    if t:
                        internal[(t, o)].append(h["ts"])
        families = Counter(r["malware_family"] for r in matched_rows.values() if r.get("malware_family"))
        exact = all(h["exact"] for h in g)
        base_conf = LEVEL_CONFIDENCE.get((rule.level if rule else None) or "medium", 70)
        rows.append({
            "observation_id": _h("rule", rule_id, key), "pattern_id": f"rule:{rule_id}",
            "pattern_version": hits[0]["rule_version_hash"], "title": rule.title if rule else rule_id,
            "narrative": f"{len(g)} hit(s) of rule '{rule.title if rule else rule_id}' on {etype} "
                         f"{pseudonym(settings, etype if etype in ('host', 'user', 'ip') else 'entity', entity)} "
                         f"(tier {max(h['tier'] for h in g)}{'' if exact else ', upper-bound candidate'})",
            "attack_tactics": tactics, "attack_techniques": techniques,
            "kill_chain_phase": tactics[0] if tactics else None,
            "threat_family": families.most_common(1)[0][0] if families else None, "campaign_ref": None,
            "matched_indicator_ids": sorted(matched_rows), "rule_id": rule_id,
            "rule_version_hash": hits[0]["rule_version_hash"], "rule_run_id": cmd.run_id, "entity_type": etype,
            "entity_pseudonym": pseudonym(settings, etype if etype in ("host", "user", "ip") else "entity", entity),
            "asset_class": asset_class, "business_unit": bu,
            "severity": (rule.level if rule else None) or "medium",
            "confidence": base_conf if exact else max(base_conf - 10, 50),
            "first_seen": ts[0] if ts else None, "last_seen": ts[-1] if ts else None,
            "observed_at": ts[0] if ts else None,
            "evidence_refs": [f"hit:{cmd.run_id}:{h['hit_key']}" for h in g][:50], "origin": "rule",
            "llm_provider": None, "llm_model": None, "prompt_version": None, "status": "auto_validated",
            "reviewed_by": None, "recorded_at": T.now(), "period_day": ts[0].date().isoformat() if ts else None})
    T.upsert(settings, T.OPERATIONAL, "observation_id", rows)
    update_sightings(settings, sightings)
    n_internal = record_internal_indicators(settings, internal, techniques, "internal-rules-v1")
    events = _observation_events(rows)
    if settings.llm_provider and cmd.enrich:
        from engine.cqrs.commands import EnrichBehavior
        enqueue(ctx.conn, EnrichBehavior(run_id=cmd.run_id), submitted_by="ti")
    return HandlerResult(events=events, detail={"run_id": cmd.run_id, "observations": len(rows),
                                                "indicator_sightings": len(sightings),
                                                "internal_indicators": n_internal})


# --------------------------------------------------------------------------- LLM enrichment
def enrich_behavior(cmd, ctx):
    from engine.cqrs.handlers import HandlerResult
    from engine.ti.llm_provider import make_provider
    from engine.ti.validator import validate
    settings = ctx.settings
    provider = make_provider(settings)
    if provider is None:
        raise ValueError("LLM_PROVIDER is not set: behaviour enrichment is disabled")
    pol = egress_policy()
    prompt_version = pol["prompt_version"]
    redactor = Redactor(ctx.conn, settings)
    bundles = build_bundles(ctx.conn, settings, cmd.run_id, redactor)
    rows, internal, rejected, sent, cached = [], defaultdict(list), [], 0, 0
    techniques_all: set[str] = set()
    for b in bundles:
        payload = b.payload()
        originals = {b.entity} | {str(h.get(k)) for h in b.hits for k in ("host_name", "user_name", "source_ip")
                                  if h.get(k) and (k != "source_ip" or is_internal_ip(str(h.get(k))))}
        assert_clean(redactor, payload, originals)
        prior = ctx.conn.execute(select(llm_egress).where(
            llm_egress.c.bundle_hash == b.bundle_hash, llm_egress.c.provider == provider.name,
            llm_egress.c.model == provider.model, llm_egress.c.prompt_version == prompt_version,
            llm_egress.c.status == "ok")).first()
        if prior is not None:
            content, cached = prior.response, cached + 1
        else:
            res = provider.complete(payload)
            content, sent = res.content, sent + 1
            ctx.conn.execute(llm_egress.insert().values(
                bundle_hash=b.bundle_hash, provider=provider.name, model=provider.model,
                prompt_version=prompt_version, run_id=cmd.run_id, payload=payload, response=content,
                prompt_tokens=res.prompt_tokens, completion_tokens=res.completion_tokens, status="ok",
                created_at=utcnow()))
        v = validate(content, set(b.refs))
        rejected.extend(v.rejected)
        for p in v.accepted:
            techniques_all.update(p["techniques"])
            pid = _h("llm", p["title"].lower(), ",".join(sorted(p["techniques"])))
            ts = sorted(h["ts"] for h in b.hits if h["ts"])
            rows.append({
                "observation_id": _h("llm", pid, b.entity_pseudonym, b.window_start.isoformat()),
                "pattern_id": pid, "pattern_version": prompt_version, "title": p["title"],
                "narrative": p["narrative"], "attack_tactics": p["tactics"], "attack_techniques": p["techniques"],
                "kill_chain_phase": p["kill_chain_phase"], "threat_family": None, "campaign_ref": None,
                "matched_indicator_ids": [], "rule_id": None, "rule_version_hash": None, "rule_run_id": cmd.run_id,
                "entity_type": b.entity_type, "entity_pseudonym": b.entity_pseudonym, "asset_class": b.asset_class,
                "business_unit": b.business_unit, "severity": p["severity"], "confidence": p["confidence"],
                "first_seen": ts[0] if ts else None, "last_seen": ts[-1] if ts else None,
                "observed_at": ts[0] if ts else None, "evidence_refs": [b.refs[e] for e in p["evidence_ids"]],
                "origin": "llm", "llm_provider": provider.name, "llm_model": provider.model,
                "prompt_version": prompt_version, "status": p["status"], "reviewed_by": None,
                "recorded_at": T.now(), "period_day": ts[0].date().isoformat() if ts else None})
            for h in b.hits:
                for o in h.get("observables") or []:
                    t = T.detect_type(o)
                    if t and _external(o, redactor):
                        internal[(t, o)].append(h["ts"])
    T.upsert(settings, T.OPERATIONAL, "observation_id", rows)
    record_internal_indicators(settings, internal, sorted(techniques_all), "internal-llm-v1")
    return HandlerResult(events=_observation_events(rows), detail={
        "run_id": cmd.run_id, "bundles": len(bundles), "sent": sent, "cached": cached, "patterns": len(rows),
        "rejected": len(rejected), "rejection_reasons": [r["reasons"] for r in rejected][:10]})


# --------------------------------------------------------------------------- review + rollup
def review_pattern(cmd, ctx):
    from engine.cqrs.handlers import HandlerResult
    from pyiceberg.expressions import EqualTo, Or
    if cmd.verdict not in ("validated", "rejected"):
        raise ValueError("verdict must be validated or rejected")
    t = T.table(ctx.settings, T.OPERATIONAL)
    rows = t.scan(row_filter=Or(EqualTo("observation_id", cmd.target_id),
                                EqualTo("pattern_id", cmd.target_id))).to_arrow().to_pylist() \
        if t.current_snapshot() else []
    if not rows:
        raise ValueError(f"no observation or pattern {cmd.target_id}")
    for r in rows:
        r["status"], r["reviewed_by"] = cmd.verdict, cmd.reviewer
    T.upsert(ctx.settings, T.OPERATIONAL, "observation_id", rows)
    return HandlerResult(events=[PatternReviewed(target_id=cmd.target_id, verdict=cmd.verdict, reviewer=cmd.reviewer,
                                                 observations=len(rows))],
                         detail={"observations": len(rows), "verdict": cmd.verdict})


def build_strategic_rollup(cmd, ctx):
    from engine.cqrs.handlers import HandlerResult
    from engine.ti.rollups import build
    operational, op_snap = T.read_all(ctx.settings, T.OPERATIONAL)
    tactical, _ = T.read_all(ctx.settings, T.TACTICAL)
    rows = build(operational, tactical, cmd.period_type)
    snap = T.replace_all(ctx.settings, T.STRATEGIC, rows, period_type=cmd.period_type)
    stages.record(ctx.conn, "ti_rollup", cmd.period_type, str(op_snap), "1",
                  {"rows": len(rows), "snapshot_id": snap}, ctx.command_id)
    return HandlerResult(events=[StrategicRollupBuilt(
        period_type=cmd.period_type, rows=len(rows), periods=len({r["period_start"] for r in rows}),
        input_snapshot=op_snap, tactics=sorted({r["tactic"] for r in rows}))],
        detail={"period_type": cmd.period_type, "rows": len(rows)})


def after_rule_run(ctx, run, res) -> list:
    """Follow-up of ExecuteRule: queue TI recording for runs that found something."""
    from engine.cqrs.commands import RecordFeedSightings, RecordRuleObservations
    from engine.cqrs.writer_queue import enqueue
    if run.replay_of:
        return []
    if run.origin == "feed_sweep":
        enqueue(ctx.conn, RecordFeedSightings(run_id=run.run_id), submitted_by="rule-service")
    elif res["hits"]:
        enqueue(ctx.conn, RecordRuleObservations(run_id=run.run_id), submitted_by="rule-service")
    return []


# --------------------------------------------------------------------------- feeds (M7)
def pull_feed(cmd, ctx):
    from engine.cqrs.handlers import HandlerResult
    from engine.ti.connectors.sdk import pull
    events, detail = pull(ctx, cmd.connector, cmd.since, cmd.payload_uri)
    return HandlerResult(events=events, detail=detail)


def record_indicator(cmd, ctx):
    from engine.cqrs.handlers import HandlerResult
    from engine.ti.connectors.sdk import Indicator, ingest
    ind = Indicator(value=cmd.value, type=cmd.type, threat_type=cmd.threat_type, malware_family=cmd.malware_family,
                    confidence=cmd.confidence, tlp=cmd.tlp, tags=[*cmd.tags, f"analyst:{cmd.analyst}"])
    res = ingest(ctx, "analyst", "1", {"tlp": cmd.tlp, "sweep_new_indicators": True}, [ind],
                 f"analyst:{cmd.analyst}")
    if not res["rows"]:
        raise ValueError(f"not a recognisable indicator: {cmd.value!r}")
    return HandlerResult(events=res["events"], detail={"indicator_id": res["rows"][0]["indicator_id"],
                                                       "new": res["new"], "sweep_run_id": res["sweep_run_id"]})


THREAT_TITLES = {"botnet_cc": "C2 server", "payload_delivery": "payload delivery host", "payload": "malware sample",
                 "exploited_vulnerability": "exploited vulnerability"}


def record_feed_sightings(cmd, ctx):
    from engine.common.db import rule_runs
    from engine.cqrs.handlers import HandlerResult
    run = ctx.conn.execute(select(rule_runs).where(rule_runs.c.run_id == cmd.run_id)).first()
    ids = list((run.context or {}).get("indicator_ids") or []) if run else []
    hits = run_hits(ctx.settings, cmd.run_id)
    indicators = T.read_keys(ctx.settings, T.TACTICAL, "indicator_id", ids)
    by_value: dict[str, list[dict]] = defaultdict(list)
    for r in indicators:
        for v in T.sweep_values(r["type"], r["value"]):
            by_value[v].append(r)
    att = attack()
    sightings: dict[str, list] = defaultdict(list)
    obs: dict[tuple[str, str], dict] = {}
    for h in hits:
        etype, entity = entity_of(h)
        for o in h.get("observables") or []:
            for ind in by_value.get(o, []):
                sightings[ind["indicator_id"]].append(h["ts"])
                key = (ind["indicator_id"], h["entity_key"])
                g = obs.setdefault(key, {"ind": ind, "hits": [], "etype": etype, "entity": entity})
                g["hits"].append(h)
    rows = []
    for (iid, ekey), g in sorted(obs.items()):
        ind = g["ind"]
        same = [r for r in indicators if r["indicator_id"] == iid]
        techniques = sorted({t for r in same for t in (r.get("attack_techniques") or []) if att.technique(t)})
        family = next((r["malware_family"] for r in same if r.get("malware_family")), None)
        ttype = next((r["threat_type"] for r in same if r.get("threat_type")), None)
        asset_class, bu = entity_context(ctx.conn, g["etype"], g["entity"])
        ts = sorted(h["ts"] for h in g["hits"] if h["ts"])
        tactics = att.tactics_of(techniques)
        pseud = pseudonym(ctx.settings, g["etype"] if g["etype"] in ("host", "user", "ip") else "entity", g["entity"])
        rows.append({
            "observation_id": _h("feed", iid, ekey), "pattern_id": f"feed:{iid}", "pattern_version": "1",
            "title": f"Sighting of {family or 'known'} {THREAT_TITLES.get(ttype or '', 'indicator')} "
                     f"({ind['type']} {ind['value']})",
            "narrative": f"{len(g['hits'])} event(s) on {g['etype']} {pseud} matched indicator {ind['value']} "
                         f"from {', '.join(sorted({r['source'] for r in same}))}",
            "attack_tactics": tactics, "attack_techniques": techniques,
            "kill_chain_phase": tactics[0] if tactics else None, "threat_family": family, "campaign_ref": None,
            "matched_indicator_ids": [iid], "rule_id": run.rule_id if run else None,
            "rule_version_hash": run.rule_version_hash if run else None, "rule_run_id": cmd.run_id,
            "entity_type": g["etype"], "entity_pseudonym": pseud, "asset_class": asset_class, "business_unit": bu,
            "severity": "high" if max(r["confidence"] for r in same) >= 75 else "medium",
            "confidence": max(r["confidence"] for r in same), "first_seen": ts[0] if ts else None,
            "last_seen": ts[-1] if ts else None, "observed_at": ts[0] if ts else None,
            "evidence_refs": [f"hit:{cmd.run_id}:{h['hit_key']}" for h in g["hits"]][:50], "origin": "feed_match",
            "llm_provider": None, "llm_model": None, "prompt_version": None, "status": "auto_validated",
            "reviewed_by": None, "recorded_at": T.now(), "period_day": ts[0].date().isoformat() if ts else None})
    T.upsert(ctx.settings, T.OPERATIONAL, "observation_id", rows)
    updated = update_sightings(ctx.settings, sightings)
    return HandlerResult(events=_observation_events(rows), detail={
        "run_id": cmd.run_id, "indicators_swept": len(ids), "indicators_sighted": len(sightings),
        "observations": len(rows), "tactical_rows_updated": len(updated)})

