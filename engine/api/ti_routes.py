"""Query-side TI endpoints (plan.md section 4.4). The TI tables are read as snapshot-pinned
Iceberg scans; every response carries the snapshot id it read."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime

from fastapi import APIRouter, Query

from engine.common.db import as_utc
from engine.ti import tables as T
from engine.ti.rollups import compare


def _clean(rows: list[dict]) -> list[dict]:
    return [{k: as_utc(v) if isinstance(v, datetime) else v for k, v in r.items()} for r in rows]


def build_router(rt) -> APIRouter:
    r = APIRouter(prefix="/ti")
    s = rt.settings

    @r.get("/tactical")
    def tactical(type: str | None = None, source: str | None = None, sighted: bool | None = None,
                 status: str | None = None, q: str | None = None, limit: int = Query(500, le=20000),
                 snapshot_id: int | None = None):
        rows, snap = T.read_all(s, T.TACTICAL, snapshot_id)
        if type:
            rows = [x for x in rows if x["type"] == type]
        if source:
            rows = [x for x in rows if x["source"] == source or x["source"].startswith(source + ":")]
        if sighted is not None:
            rows = [x for x in rows if bool(x.get("org_sightings")) == sighted]
        if status:
            rows = [x for x in rows if x["status"] == status]
        if q:
            rows = [x for x in rows if q.lower() in x["value"]]
        rows.sort(key=lambda x: (-(x.get("org_sightings") or 0), x["value"]))
        return {"snapshot_id": snap, "count": len(rows), "items": _clean(rows[:limit]),
                "by_source": dict(Counter(x["source"] for x in rows))}

    @r.get("/operational")
    def operational(technique: str | None = None, family: str | None = None, origin: str | None = None,
                    status: str | None = None, limit: int = Query(500, le=20000), snapshot_id: int | None = None):
        rows, snap = T.read_all(s, T.OPERATIONAL, snapshot_id)
        if technique:
            rows = [x for x in rows if technique.upper() in (x.get("attack_techniques") or [])]
        if family:
            rows = [x for x in rows if (x.get("threat_family") or "").lower() == family.lower()]
        if origin:
            rows = [x for x in rows if x["origin"] == origin]
        if status:
            rows = [x for x in rows if x["status"] == status]
        rows.sort(key=lambda x: x.get("observed_at") or datetime.min, reverse=True)
        return {"snapshot_id": snap, "count": len(rows), "items": _clean(rows[:limit])}

    @r.get("/patterns")
    def patterns(status: str | None = None, technique: str | None = None, snapshot_id: int | None = None):
        rows, snap = T.read_all(s, T.OPERATIONAL, snapshot_id)
        groups: dict[str, dict] = {}
        for x in rows:
            if status and x["status"] != status:
                continue
            if technique and technique.upper() not in (x.get("attack_techniques") or []):
                continue
            g = groups.setdefault(x["pattern_id"], {
                "pattern_id": x["pattern_id"], "title": x["title"], "origin": x["origin"],
                "techniques": x.get("attack_techniques") or [], "tactics": x.get("attack_tactics") or [],
                "observations": 0, "entities": set(), "statuses": Counter(), "first_seen": None, "last_seen": None,
                "llm_model": x.get("llm_model")})
            g["observations"] += 1
            g["entities"].add(x.get("entity_pseudonym"))
            g["statuses"][x["status"]] += 1
            for k, f in (("first_seen", min), ("last_seen", max)):
                if x.get(k):
                    g[k] = x[k] if g[k] is None else f(g[k], x[k])
        items = []
        for g in groups.values():
            g["entities"] = len(g["entities"] - {None})
            g["statuses"] = dict(g["statuses"])
            items.append(g)
        items.sort(key=lambda g: -g["observations"])
        return {"snapshot_id": snap, "count": len(items), "items": _clean(items)}

    @r.get("/observations")
    def observations(period: str = "month", snapshot_id: int | None = None):
        from engine.ti.rollups import period_start
        rows, snap = T.read_all(s, T.OPERATIONAL, snapshot_id)
        out: dict[str, Counter] = defaultdict(Counter)
        for x in rows:
            if x.get("observed_at"):
                out[period_start(x["observed_at"].date(), period).isoformat()][x["origin"]] += 1
        return {"snapshot_id": snap, "period": period,
                "items": [{"period_start": k, **v, "total": sum(v.values())} for k, v in sorted(out.items())]}

    @r.get("/strategic")
    def strategic(period: str = "quarter", compare_: str | None = Query(None, alias="compare"),
                  by: str = "tactic", snapshot_id: int | None = None):
        rows, snap = T.read_all(s, T.STRATEGIC, snapshot_id)
        rows = [x for x in rows if x["period_type"] == period]
        rows.sort(key=lambda x: (x["period_start"], -x["observations"]))
        out = {"snapshot_id": snap, "period": period, "count": len(rows), "items": _clean(rows)}
        if compare_ in ("yoy", "prev"):
            out["comparison"] = compare(rows, period, by)
        return out

    @r.get("/feeds")
    def feeds():
        """Connector health: configuration + last pull (read model) for every registered connector."""
        from sqlalchemy import select
        from engine.common.db import rm_feeds
        from engine.ti.connectors.sdk import feed_config, offline_mode, registry
        with rt.engine.connect() as conn:
            health = {x.connector: dict(x._mapping) for x in conn.execute(select(rm_feeds))}
        items = []
        for name, cls in sorted(registry().items()):
            cfg = feed_config(name)
            h = health.get(name) or {}
            items.append({"connector": name, "version": cls.version, "generation": cls.feed_generation,
                          "enabled": bool(cfg.get("enabled")), "schedule_minutes": cfg.get("schedule_minutes"),
                          "tlp": cfg.get("tlp"), "url": cfg.get("url"), "auth_env": cfg.get("auth_env"),
                          **{k: as_utc(v) if isinstance(v, datetime) else v for k, v in h.items()
                             if k not in ("connector", "version", "generation")}})
        return {"offline": offline_mode(), "items": items}

    @r.get("/export")
    def export(tlp_max: str = "TLP:GREEN", format: str = "json", include_inactive: bool = False):
        """Indicator export with TLP enforcement: nothing marked above `tlp_max` is returned."""
        from fastapi.responses import PlainTextResponse
        from engine.ti.connectors.sdk import tlp_allows, tlp_norm
        rows, snap = T.read_all(s, T.TACTICAL)
        allowed = [x for x in rows if tlp_allows(x["tlp"], tlp_max)
                   and (include_inactive or x["status"] == "active")]
        withheld = len([x for x in rows if not tlp_allows(x["tlp"], tlp_max)])
        if format == "csv":
            lines = ["type,value,source,threat_type,malware_family,confidence,tlp,last_seen"]
            lines += [f'{x["type"]},{x["value"]},{x["source"]},{x["threat_type"] or ""},'
                      f'{(x["malware_family"] or "").replace(",", " ")},{x["confidence"]},{x["tlp"]},'
                      f'{as_utc(x["last_seen"]).isoformat() if x["last_seen"] else ""}' for x in allowed]
            return PlainTextResponse("\n".join(lines) + "\n", media_type="text/csv")
        return {"snapshot_id": snap, "tlp_max": tlp_norm(tlp_max), "count": len(allowed), "withheld_by_tlp": withheld,
                "items": _clean([{k: x[k] for k in ("indicator_id", "type", "value", "source", "threat_type",
                                                     "malware_family", "confidence", "tlp", "first_seen", "last_seen",
                                                     "status")} for x in allowed])}

    @r.get("/summary")
    def summary():
        tac, _ = T.read_all(s, T.TACTICAL)
        op, _ = T.read_all(s, T.OPERATIONAL)
        st, _ = T.read_all(s, T.STRATEGIC)
        return {"tactical": {"indicators": len({x["indicator_id"] for x in tac}), "rows": len(tac),
                             "by_source": dict(Counter(x["source"] for x in tac)),
                             "sighted": sum(1 for x in tac if x.get("org_sightings"))},
                "operational": {"rows": len(op), "by_origin": dict(Counter(x["origin"] for x in op)),
                                "by_status": dict(Counter(x["status"] for x in op))},
                "strategic": {"rows": len(st), "by_period": dict(Counter(x["period_type"] for x in st)),
                              "tactics": sorted({x["tactic"] for x in st})}}

    return r
