"""Capability catalog (plan.md section 3.8, "Coverage planner").

Describes what each derived table can answer, and proves for a compiled rule whether a
table covers it. Three kinds of capability:

* HighValueCoverage (tier 2, exact, event level): summary.high_value_events holds the full
  ECS row of every event the drop policy marks high-value. A rule is covered when every
  disjunct of its predicate implies a high-value condition of each of its sources, so every
  event the rule can match was retained.

* DimensionTable (tier 1 artefacts / tier 2 summaries, exact at the table's grain): every
  literal of the rule is on a column the table keeps as a dimension (one value per row),
  so the WHERE clause evaluates exactly on the aggregated rows. Hits are entity x day.

* AggregateCapability (tier 2, sound over-approximation): event_count / value_count
  correlations evaluated on hourly or daily buckets. The table's population must contain
  every event the base rule can match; base literals that cannot be mapped are dropped
  (widening the set) and any sliding window of length T is covered by ceil(T/bucket)+1
  consecutive buckets. Counts over that union are an upper bound, so no true alert is lost;
  extra candidates are possible and are reported as such (`exact: false`).

If nothing here applies, the planner falls back to tier 3 (index-pruned raw restore).
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

from engine.rules.compiler import CompiledRule, Expr, Lit, dnf, lit_sql, literals, q, to_sql
from engine.summary.policy import load_policy

NAME_FIELDS = {"process.executable": "process.name", "process.parent.executable": "process.parent.name"}


def derived(lit: Lit) -> Lit:
    """`process.executable endswith '\\x.exe'` is the same as `process.name == 'x.exe'` in ECS
    (process.name is defined as the executable's base name)."""
    if lit.field in NAME_FIELDS and lit.op == "endswith" and isinstance(lit.value, str) \
            and lit.value.startswith("\\") and "\\" not in lit.value[1:] and len(lit.value) > 1:
        return Lit(NAME_FIELDS[lit.field], "eq", lit.value[1:], cased=lit.cased)
    return lit


def rewrite(e: Expr) -> Expr:
    from engine.rules.compiler import Node
    if isinstance(e, Lit):
        return derived(e)
    return Node(e.kind, tuple(rewrite(i) for i in e.items))


# --------------------------------------------------------------------------- high-value events
def _atom_implied(lit: Lit, field_: str, spec) -> bool:
    if lit.field != field_ or lit.value is None:
        return False
    v = str(lit.value).lower()
    if isinstance(spec, dict) and "contains_any" in spec:
        return lit.op in ("eq", "contains", "startswith", "endswith") and \
            any(str(t).lower() in v for t in spec["contains_any"])
    return lit.op == "eq" and v in {str(x).lower() for x in spec}


def _conj_implies(conj: list[tuple[Lit, bool]], clause: dict) -> bool:
    positives = [derived(lit) for lit, pos in conj if pos]
    return all(any(_atom_implied(lit, f, spec) for lit in positives) for f, spec in clause.items())


@dataclass
class Coverage:
    capability: str
    tier: int
    table: str
    exact: bool
    granularity: str               # event | entity-day | group-day
    reasons: list[str] = field(default_factory=list)
    detail: dict = field(default_factory=dict)


def high_value_coverage(rule: CompiledRule) -> Coverage | None:
    if rule.correlation:
        return None
    conjuncts = dnf(rule.predicate)
    if conjuncts is None:
        return None
    policy = load_policy()
    for source in rule.sources:
        clauses = policy.for_source(source).high_value
        if not clauses:
            return None
        for conj in conjuncts:
            if not any(_conj_implies(conj, c) for c in clauses):
                return None
    return Coverage("high_value_events", 2, "summary.high_value_events", True, "event",
                    [f"every disjunct implies a high-value condition of drop policy {policy.version}"],
                    {"policy_version": policy.version})


# --------------------------------------------------------------------------- dimension tables
@dataclass(frozen=True)
class DimensionTable:
    name: str
    table: str
    tier: int
    sources: tuple[str, ...]
    dims: dict                      # ecs field -> (column expr, lowered: bool)
    entity_col: str
    count_col: str
    time_col: str | None = None     # hourly tables keep the hour
    feature: str | None = None      # name@version for artefacts (coverage = feature stage)
    summary_source: str | None = None
    filters: tuple[tuple[str, str], ...] = ()

    def covers(self, rule: CompiledRule) -> Coverage | None:
        if rule.correlation or set(rule.sources) != set(self.sources):
            return None
        from engine.normaliser import ecs
        types = ecs.catalog().fields
        for lit, _ in literals(rewrite(rule.predicate)):
            d = self.dims.get(lit.field)
            if d is None:
                return None
            numeric = types.get(lit.field, "keyword") in ("long", "float")
            allowed = ("eq", "gt", "gte", "lt", "lte", "exists", "null") if numeric else \
                ("eq", "contains", "startswith", "endswith", "glob", "exists", "null", "re")
            if lit.op not in allowed or (d[1] and lit.cased and lit.op != "re"):
                return None
        return Coverage(self.name, self.tier, self.table, True, "entity-day",
                        [f"every predicate field is a dimension of {self.table}"],
                        {"feature": self.feature, "time_col": self.time_col})

    def where_sql(self, rule: CompiledRule) -> str:
        from engine.normaliser import ecs
        types = ecs.catalog().fields

        def render(lit: Lit) -> str:
            col, _ = self.dims[lit.field]
            return lit_sql(lit, column=col, typ=types.get(lit.field, "keyword").removesuffix("[]"))
        return to_sql(rewrite(rule.predicate), render)


DIMENSION_TABLES = [
    DimensionTable("process_lineage", "artefacts.process_lineage_edges", 1, ("sysmon",),
                   {"process.name": ("process_name", True), "process.parent.name": ("parent_name", True),
                    "host.name": ("host_name", False)},
                   entity_col="host_name", count_col="execs", feature="process_lineage_edges@1",
                   filters=(("feature_version", "1"),)),
    DimensionTable("process_daily", "summary.process_daily", 2, ("sysmon",),
                   {"process.name": ("process_name", True), "process.parent.name": ("parent_name", True),
                    "host.name": ("host_name", False)},
                   entity_col="host_name", count_col="exec_count", summary_source="sysmon"),
    DimensionTable("network_hourly", "summary.network_hourly", 2, ("zeek_conn",),
                   {"host.name": ("host_name", False), "destination.ip": ("dest_ip", False),
                    "destination.port": ("dest_port", False), "network.transport": ("transport", False),
                    "network.direction": ("direction", False)},
                   entity_col="host_name", count_col="conn_count", time_col="hour", summary_source="zeek_conn"),
    DimensionTable("cloud_api_daily", "summary.cloud_api_daily", 2, ("cloudtrail",),
                   {"user.name": ("principal", False), "cloud.service.name": ("service", False),
                    "event.action": ("action", False)},
                   entity_col="principal", count_col="calls", summary_source="cloudtrail"),
]


# --------------------------------------------------------------------------- aggregate (correlation) capabilities
@dataclass
class AggPlan:
    capability: str
    table: str
    sql: str                        # over relation `t` (rows of the table for the day range)
    notes: list[str]
    exact: bool = False


def _bucket_window(timespan_s: int, bucket_s: int) -> tuple[int, str]:
    k = max(1, math.ceil(timespan_s / bucket_s))
    return k, f"INTERVAL '{k * bucket_s} seconds'"


def _threshold(op: str, n: float) -> str | None:
    # Over-approximation is only sound for "at least" style thresholds.
    return {"gte": f">= {n!r}", "gt": f"> {n!r}"}.get(op)


AUTH_POPULATION = {"event.code": {"4624", "4625", "4648"},
                   "event.action": {"logged-in", "logon-failed", "logged-in-explicit"}}
AUTH_FAILURE = {("event.code", "4625"), ("event.outcome", "failure"), ("event.action", "logon-failed")}
AUTH_SUCCESS = {("event.code", "4624"), ("event.code", "4648"), ("event.outcome", "success"),
                ("event.action", "logged-in"), ("event.action", "logged-in-explicit")}


def _auth_hourly(rule: CompiledRule) -> AggPlan | None:
    c = rule.correlation
    if rule.sources != ["windows_security"]:
        return None
    groups = {"user.name": "lower(user_name)", "host.name": "lower(host_name)", "source.ip": "ip"}
    if not set(c.group_by) <= set(groups) or (c.value_field and c.value_field not in groups):
        return None
    thr = _threshold(c.op, c.threshold)
    conjuncts = dnf(rule.predicate, limit=32)
    if thr is None or conjuncts is None:
        return None
    filters, measures, notes = [], set(), []
    for conj in conjuncts:
        pos = [(lit.field, str(lit.value).lower()) for lit, p in conj if p and lit.op == "eq"]
        if not any(f in AUTH_POPULATION and v in AUTH_POPULATION[f] for f, v in pos):
            return None             # cannot prove the base events are authentication events in auth_hourly
        fail, succ = any(x in AUTH_FAILURE for x in pos), any(x in AUTH_SUCCESS for x in pos)
        measures.add("failure" if fail and not succ else "success" if succ and not fail else "success + failure")
        parts = []
        for lit, p in conj:
            if not p:
                notes.append(f"negated literal {lit.describe()} not applied (widens the candidate set)")
                continue
            v = str(lit.value).lower() if lit.value is not None else None
            if lit.op == "eq" and lit.field == "user.name":
                parts.append(f"lower(user_name) = {q(v)}")
            elif lit.op == "eq" and lit.field == "host.name":
                parts.append(f"lower(host_name) = {q(v)}")
            elif lit.op == "eq" and lit.field == "source.ip":
                parts.append(f"list_contains(src_ips, {q(v)})")
                notes.append("source.ip filter uses the hour's src_ips list (not split by outcome)")
            elif lit.op == "eq" and lit.field == "winlog.logon.type":
                parts.append(f"list_contains(list_transform(logon_types, x -> lower(x)), {q(v)})")
                notes.append("logon type filter uses the hour's logon_types list")
            elif (lit.field, v) in AUTH_FAILURE | AUTH_SUCCESS or (lit.field, v) in \
                    {(f, x) for f, xs in AUTH_POPULATION.items() for x in xs}:
                continue            # expressed through the measure column
            else:
                notes.append(f"literal {lit.describe()} not available in auth_hourly (widens the candidate set)")
        filters.append("(" + (" AND ".join(parts) or "TRUE") + ")")
    measure = measures.pop() if len(measures) == 1 else "success + failure"
    k, interval = _bucket_window(c.timespan_s, 3600)
    gcols = [groups[g] + f' AS "{g}"' for g in c.group_by]
    explode = "source.ip" in c.group_by or c.value_field == "source.ip"
    ip_col = "unnest(CASE WHEN len(src_ips) > 0 THEN src_ips ELSE [NULL] END) AS ip, " if explode else ""
    base = (f"SELECT hour AS bucket, day, {ip_col}user_name, host_name, ({measure}) AS cnt FROM t "
            f"WHERE ({' OR '.join(filters)}) AND ({measure}) > 0")
    sql = _window_sql(base, gcols, list(c.group_by), c, interval, thr,
                      value_expr=groups.get(c.value_field) if c.value_field else None, count_expr="cnt")
    notes.append(f"hourly buckets: any {c.timespan_s}s window lies within {k + 1} consecutive hours "
                 f"(counts are an upper bound)")
    return AggPlan("auth_hourly", "summary.auth_hourly", sql, sorted(set(notes)))


def _dns_daily(rule: CompiledRule) -> AggPlan | None:
    c = rule.correlation
    if rule.sources != ["zeek_dns"]:
        return None
    groups = {"host.name": "lower(host_name)", "dns.question.registered_domain": "lower(registered_domain)"}
    if not set(c.group_by) <= set(groups):
        return None
    if c.type == "value_count" and c.value_field not in ("dns.question.name", "dns.question.subdomain"):
        return None
    thr = _threshold(c.op, c.threshold)
    conjuncts = dnf(rule.predicate, limit=32)
    if thr is None or conjuncts is None:
        return None
    filters, notes = [], []
    for conj in conjuncts:
        parts = []
        for lit, p in conj:
            v = str(lit.value).lower() if lit.value is not None else None
            if p and lit.op == "eq" and lit.field == "host.name":
                parts.append(f"lower(host_name) = {q(v)}")
            elif p and lit.op == "eq" and lit.field == "dns.question.registered_domain":
                parts.append(f"lower(registered_domain) = {q(v)}")
            elif p and lit.op == "eq" and lit.field == "dns.question.type":
                parts.append(f"list_contains(list_transform(qtypes, x -> lower(x)), {q(v)})")
                notes.append("query-type filter uses the day's qtypes list (counts include other types)")
            else:
                notes.append(f"literal {lit.describe()} not available in dns_daily (widens the candidate set)")
        filters.append("(" + (" AND ".join(parts) or "TRUE") + ")")
    # distinct names per (host, registered domain, day) <= distinct subdomains + 1 (the bare domain)
    count = "query_count" if c.type == "event_count" else "(distinct_subdomains + 1)"
    k, interval = _bucket_window(c.timespan_s, 86400)
    base = f"SELECT CAST(day AS TIMESTAMP) AS bucket, day, host_name, registered_domain, {count} AS cnt FROM t " \
           f"WHERE {' OR '.join(filters)}"
    gcols = [groups[g] + f' AS "{g}"' for g in c.group_by]
    sql = _window_sql(base, gcols, list(c.group_by), c, interval, thr, value_expr=None, count_expr="cnt")
    notes.append(f"daily buckets: any {c.timespan_s}s window lies within {k + 1} consecutive days; "
                 "distinct counts are summed per day (an upper bound)")
    return AggPlan("dns_daily", "summary.dns_daily", sql, sorted(set(notes)))


def _network_hourly(rule: CompiledRule) -> AggPlan | None:
    c = rule.correlation
    if rule.sources != ["zeek_conn"]:
        return None
    dims = DIMENSION_TABLES[2].dims
    groups = {f: col for f, (col, _) in dims.items()}
    if not set(c.group_by) <= set(groups) or (c.value_field and c.value_field not in groups):
        return None
    thr = _threshold(c.op, c.threshold)
    if thr is None:
        return None
    notes = []
    from engine.normaliser import ecs
    types = ecs.catalog().fields

    def render(lit: Lit) -> str:
        if lit.field in dims:
            return lit_sql(lit, column=dims[lit.field][0], typ=types.get(lit.field, "keyword"))
        notes.append(f"literal {lit.describe()} not available in network_hourly (widens the candidate set)")
        return "TRUE"
    if any(not p and lit.field not in dims for lit, p in literals(rule.predicate)):
        return None                 # a negated unmapped literal cannot be widened soundly by TRUE
    where = to_sql(rule.predicate, render)
    k, interval = _bucket_window(c.timespan_s, 3600)
    base = f"SELECT hour AS bucket, day, host_name, dest_ip, dest_port, transport, direction, conn_count AS cnt " \
           f"FROM t WHERE {where}"
    gcols = [groups[g] + f' AS "{g}"' for g in c.group_by]
    sql = _window_sql(base, gcols, list(c.group_by), c, interval, thr,
                      value_expr=groups.get(c.value_field) if c.value_field else None, count_expr="cnt")
    notes.append(f"hourly buckets: any {c.timespan_s}s window lies within {k + 1} consecutive hours")
    return AggPlan("network_hourly", "summary.network_hourly", sql, sorted(set(notes)))


def _window_sql(base: str, gcols: list[str], gnames: list[str], c, interval: str, thr: str,
                value_expr: str | None, count_expr: str) -> str:
    g = ", ".join(f'"{n}"' for n in gnames)
    part = f"PARTITION BY {g} " if gnames else ""
    sel_g = (", ".join(gcols) + ", ") if gcols else ""
    if c.type == "value_count" and value_expr is not None:
        inner = f"SELECT {sel_g}bucket, day, {value_expr} AS v FROM base WHERE {value_expr} IS NOT NULL"
        agg = f"count(DISTINCT v) OVER ({part}ORDER BY bucket RANGE BETWEEN CURRENT ROW AND {interval} FOLLOWING)"
    else:
        inner = f"SELECT {sel_g}bucket, any_value(day) AS day, sum({count_expr}) AS v FROM base " \
                f"GROUP BY {(g + ', ') if g else ''}bucket"
        agg = f"sum(v) OVER ({part}ORDER BY bucket RANGE BETWEEN CURRENT ROW AND {interval} FOLLOWING)"
    out_g = (g + ", ") if g else ""
    return (f"WITH base AS ({base}), x AS ({inner}), w AS (SELECT {out_g}bucket, day, {agg} AS window_count FROM x) "
            f"SELECT {out_g}day, max(window_count) AS count, min(bucket) AS first_ts, max(bucket) AS last_ts "
            f"FROM w WHERE window_count {thr} GROUP BY {out_g}day")


AGG_CAPABILITIES = [_auth_hourly, _dns_daily, _network_hourly]
AGG_TABLE_SOURCE = {"summary.auth_hourly": "windows_security", "summary.dns_daily": "zeek_dns",
                    "summary.network_hourly": "zeek_conn"}


def aggregate_plan(rule: CompiledRule) -> AggPlan | None:
    if not rule.correlation:
        return None
    for cap in AGG_CAPABILITIES:
        p = cap(rule)
        if p is not None:
            return p
    return None
