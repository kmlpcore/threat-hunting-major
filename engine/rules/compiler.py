"""Sigma → engine IR → DuckDB SQL (plan.md section 3.8, "Compiler").

pySigma parses the rule (and correlation rules), resolves rule references and applies the
ECS processing pipeline (rules/pipelines/ecs_custom.yaml). The parsed condition tree is then
lowered into a small predicate IR that the coverage planner can reason about (which fields,
which operators, can a summary table answer it?) and that renders to DuckDB SQL over ECS
columns. The same SQL runs on raw Parquet, on summary.high_value_events and on restored row
groups, so every tier evaluates identical semantics.

Anything the engine cannot evaluate faithfully (an unknown field, an unsupported modifier or
correlation type) raises CompileError at submit time. Nothing is silently ignored.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Iterable

import yaml

from engine.common.config import REPO_ROOT
from engine.normaliser import ecs

PIPELINE_FILE = REPO_ROOT / "rules" / "pipelines" / "ecs_custom.yaml"
LOGSOURCES_FILE = REPO_ROOT / "rules" / "pipelines" / "logsources.yaml"
COMPILER_VERSION = "1"


class CompileError(ValueError):
    def __init__(self, problems: list[str]):
        super().__init__("; ".join(problems))
        self.problems = problems


# --------------------------------------------------------------------------- IR
@dataclass(frozen=True)
class Lit:
    """field <op> value. String comparisons are case-insensitive unless `cased` (Sigma default)."""
    field: str
    op: str          # eq contains startswith endswith glob re cidr gt gte lt lte exists null
    value: object = None
    cased: bool = False
    flags: str = ""  # regex flags (i, m, s)

    def describe(self) -> str:
        return f"{self.field} {self.op} {self.value!r}" + (" (cased)" if self.cased else "")


@dataclass(frozen=True)
class Node:
    kind: str                     # and | or | not
    items: tuple

    def describe(self) -> str:
        if self.kind == "not":
            return f"NOT ({describe(self.items[0])})"
        return "(" + f" {self.kind.upper()} ".join(describe(i) for i in self.items) + ")"


Expr = Lit | Node


def describe(e: Expr) -> str:
    return e.describe()


def And(*items: Expr) -> Expr:
    flat = []
    for i in items:
        flat.extend(i.items if isinstance(i, Node) and i.kind == "and" else [i])
    return flat[0] if len(flat) == 1 else Node("and", tuple(flat))


def Or(*items: Expr) -> Expr:
    flat = []
    for i in items:
        flat.extend(i.items if isinstance(i, Node) and i.kind == "or" else [i])
    return flat[0] if len(flat) == 1 else Node("or", tuple(flat))


def Not(item: Expr) -> Expr:
    if isinstance(item, Node) and item.kind == "not":
        return item.items[0]
    return Node("not", (item,))


def literals(e: Expr) -> Iterable[tuple[Lit, bool]]:
    """Every literal with its polarity (True = positive)."""
    def walk(n, pos):
        if isinstance(n, Lit):
            yield n, pos
        elif n.kind == "not":
            yield from walk(n.items[0], not pos)
        else:
            for i in n.items:
                yield from walk(i, pos)
    yield from walk(e, True)


def dnf(e: Expr, limit: int = 256) -> list[list[tuple[Lit, bool]]] | None:
    """Disjunctive normal form as lists of (literal, positive). None if it would exceed `limit`."""
    def go(n, pos):
        if isinstance(n, Lit):
            return [[(n, pos)]]
        if n.kind == "not":
            return go(n.items[0], not pos)
        parts = [go(i, pos) for i in n.items]
        if any(p is None for p in parts):
            return None
        is_and = (n.kind == "and") == pos         # De Morgan under negation
        if not is_and:
            out = [c for p in parts for c in p]
            return out if len(out) <= limit else None
        out = [[]]
        for p in parts:
            out = [a + b for a in out for b in p]
            if len(out) > limit:
                return None
        return out
    return go(e, True)


# --------------------------------------------------------------------------- compiled rule
@dataclass
class Correlation:
    type: str                     # event_count | value_count
    group_by: list[str]
    timespan_s: int
    op: str                       # gte gt lte lt eq
    threshold: float
    value_field: str | None = None


@dataclass
class CompiledRule:
    rule_id: str
    title: str
    level: str | None
    description: str
    tags: list[str]
    techniques: list[str]
    tactics: list[str]
    sources: list[str]
    predicate: Expr
    fields: list[str]
    version_hash: str
    yaml_text: str
    correlation: Correlation | None = None
    base_rules: list[str] = field(default_factory=list)
    origin: str = "hunter"

    @property
    def kind(self) -> str:
        return "correlation" if self.correlation else "event"

    def sql_where(self) -> str:
        return to_sql(self.predicate)

    def to_dict(self) -> dict:
        return {"rule_id": self.rule_id, "title": self.title, "level": self.level, "description": self.description,
                "tags": self.tags, "techniques": self.techniques, "tactics": self.tactics, "sources": self.sources,
                "kind": self.kind, "fields": self.fields, "version_hash": self.version_hash,
                "predicate": describe(self.predicate), "sql_where": self.sql_where(),
                "correlation": self.correlation.__dict__ if self.correlation else None,
                "base_rules": self.base_rules, "compiler_version": COMPILER_VERSION}


# --------------------------------------------------------------------------- pipeline + logsources
@lru_cache
def _pipeline():
    from sigma.processing.pipeline import ProcessingPipeline
    return ProcessingPipeline.from_yaml(PIPELINE_FILE.read_text())


@lru_cache
def _logsources() -> list[dict]:
    return yaml.safe_load(LOGSOURCES_FILE.read_text())["logsources"]


def sources_for(logsource) -> list[str] | None:
    have = {k: getattr(logsource, k) for k in ("category", "product", "service")}
    for entry in _logsources():
        if all(have.get(k) == v for k, v in entry["match"].items()):
            return list(entry["sources"])
    return None


# --------------------------------------------------------------------------- lowering
_TACTIC_TAGS = {
    "reconnaissance", "resource_development", "initial_access", "execution", "persistence", "privilege_escalation",
    "defense_evasion", "credential_access", "discovery", "lateral_movement", "collection", "command_and_control",
    "exfiltration", "impact"}


def _attack_tags(tags: list[str]) -> tuple[list[str], list[str]]:
    techniques, tactics = [], []
    for t in tags:
        t = t.lower()
        if not t.startswith("attack."):
            continue
        v = t.split(".", 1)[1]
        if re.fullmatch(r"t\d{4}(\.\d{3})?", v):
            techniques.append(v.upper())
        elif v in _TACTIC_TAGS:
            tactics.append(v.replace("_", "-"))
    return techniques, tactics


def _sigma_string(s) -> tuple[str, str]:
    """SigmaString → (op, value): eq / contains / startswith / endswith, or glob for anything else."""
    from sigma.types import SpecialChars
    parts = list(s.s)
    star = SpecialChars.WILDCARD_MULTI
    if not any(isinstance(p, SpecialChars) for p in parts):
        return "eq", "".join(parts)
    if len(parts) == 3 and parts[0] == star and parts[2] == star and isinstance(parts[1], str):
        return "contains", parts[1]
    if len(parts) == 2 and parts[0] == star and isinstance(parts[1], str):
        return "endswith", parts[1]
    if len(parts) == 2 and parts[1] == star and isinstance(parts[0], str):
        return "startswith", parts[0]
    out = []
    for p in parts:
        if p == star:
            out.append("*")
        elif isinstance(p, SpecialChars):
            out.append("?")
        else:
            out.append(p.replace("\\", "\\\\").replace("*", "\\*").replace("?", "\\?"))
    return "glob", "".join(out)


class _Lowerer:
    def __init__(self):
        self.problems: list[str] = []
        self.catalog = ecs.catalog().fields

    def field_ok(self, name: str | None) -> bool:
        if name is None:
            return True
        if name not in self.catalog:
            self.problems.append(f"field {name!r} is not mapped to ECS (schemas/ecs/fields.yaml) by the pipeline")
            return False
        return True

    def value(self, fieldname: str | None, v) -> Expr | None:
        import sigma.types as T
        f = fieldname or "event.original"          # keyword (field-less) search: full original record
        if isinstance(v, T.SigmaExpansion):
            parts = [self.value(fieldname, x) for x in v.values]
            return Or(*[p for p in parts if p is not None]) if all(p is not None for p in parts) else None
        if isinstance(v, T.SigmaString):
            op, s = _sigma_string(v)
            return Lit(f, op, s, cased=isinstance(v, T.SigmaCasedString))
        if isinstance(v, T.SigmaNumber):
            return Lit(f, "eq", v.number)
        if isinstance(v, T.SigmaBool):
            return Lit(f, "eq", v.boolean)
        if isinstance(v, T.SigmaNull):
            return Lit(f, "null")
        if isinstance(v, T.SigmaExists):
            return Lit(f, "exists") if v.exists else Lit(f, "null")
        if isinstance(v, T.SigmaCIDRExpression):
            if v.network.version != 4:
                self.problems.append(f"IPv6 CIDR {v.network} on {f} is not supported")
                return None
            return Lit(f, "cidr", str(v.network))
        if isinstance(v, T.SigmaCompareExpression):
            op = {1: "lt", 2: "lte", 3: "gt", 4: "gte"}.get(int(v.op.value))
            if op is None:
                self.problems.append(f"unsupported comparison {v.op} on {f}")
                return None
            return Lit(f, op, v.number.number)
        if isinstance(v, T.SigmaRegularExpression):
            rx = v.regexp
            pattern = rx.original if getattr(rx, "original", None) else str(rx)
            flags = "".join(sorted({"i": "i", "m": "m", "s": "s"}.get(fl.name[0].lower(), "")
                                   for fl in (v.flags or set())))
            try:
                re.compile(pattern)
            except re.error as exc:
                self.problems.append(f"invalid regular expression on {f}: {exc}")
                return None
            return Lit(f, "re", pattern, cased=True, flags=flags)
        self.problems.append(f"unsupported Sigma value type {type(v).__name__} on field {f}")
        return None

    def lower(self, node) -> Expr | None:
        from sigma.conditions import (ConditionAND, ConditionFieldEqualsValueExpression, ConditionNOT,
                                      ConditionOR, ConditionValueExpression)
        if isinstance(node, ConditionAND):
            parts = [self.lower(a) for a in node.args]
            return And(*parts) if all(p is not None for p in parts) else None
        if isinstance(node, ConditionOR):
            parts = [self.lower(a) for a in node.args]
            return Or(*parts) if all(p is not None for p in parts) else None
        if isinstance(node, ConditionNOT):
            inner = self.lower(node.args[0])
            return Not(inner) if inner is not None else None
        if isinstance(node, ConditionFieldEqualsValueExpression):
            if not self.field_ok(node.field):
                return None
            return self.value(node.field, node.value)
        if isinstance(node, ConditionValueExpression):
            return self.value(None, node.value)
        self.problems.append(f"unsupported condition element {type(node).__name__}")
        return None


def _hash(text: str) -> str:
    return hashlib.sha256(text.encode()).hexdigest()[:16]


def _rule_id(rule) -> str:
    return str(rule.id) if getattr(rule, "id", None) else _hash(rule.title or "")


def compile_sigma(yaml_text: str, origin: str = "hunter") -> CompiledRule:
    """Compile one Sigma document set: a single detection rule, or a correlation rule plus the
    detection rules it references. Raises CompileError listing every problem found."""
    from sigma.collection import SigmaCollection
    from sigma.exceptions import SigmaError
    from sigma.rule import SigmaRule
    try:
        collection = SigmaCollection.from_yaml(yaml_text)
        collection.resolve_rule_references()
    except SigmaError as exc:
        raise CompileError([f"invalid Sigma: {exc}"]) from exc
    rules = list(collection.rules)
    if not rules:
        raise CompileError(["no Sigma rule found"])
    pipeline = _pipeline()
    for r in rules:
        pipeline.apply(r)

    corr = [r for r in rules if not isinstance(r, SigmaRule)]
    detections = [r for r in rules if isinstance(r, SigmaRule)]
    if len(corr) > 1 or (not corr and len(detections) != 1):
        raise CompileError(["submit exactly one detection rule, or one correlation rule with its base rules"])
    lowerer = _Lowerer()
    head = corr[0] if corr else detections[0]
    bases = [ref.rule for ref in corr[0].rules] if corr else detections

    predicates, sources = [], []
    for r in bases:
        srcs = sources_for(r.logsource)
        if srcs is None:
            lowerer.problems.append(f"rule {r.title!r}: logsource {r.logsource} is not ingested by this engine "
                                    f"(rules/pipelines/logsources.yaml)")
        else:
            sources.extend(s for s in srcs if s not in sources)
        try:
            conds = [c.parse() for c in r.detection.parsed_condition]
        except SigmaError as exc:
            lowerer.problems.append(f"rule {r.title!r}: {exc}")
            continue
        parts = [lowerer.lower(c) for c in conds]
        if all(p is not None for p in parts):
            predicates.append(Or(*parts))

    correlation = None
    if corr:
        c = corr[0]
        ctype = c.type.name.lower()
        if ctype not in ("event_count", "value_count"):
            lowerer.problems.append(f"correlation type {ctype} is not supported (event_count, value_count)")
        op = c.condition.op.name.lower()
        value_field = c.condition.fieldref
        for g in [*(c.group_by or []), *([value_field] if value_field else [])]:
            lowerer.field_ok(g)
        if ctype == "value_count" and not value_field:
            lowerer.problems.append("value_count correlation needs condition.field")
        correlation = Correlation(type=ctype, group_by=list(c.group_by or []), timespan_s=int(c.timespan.seconds),
                                  op=op, threshold=float(c.condition.count), value_field=value_field)

    if lowerer.problems:
        raise CompileError(lowerer.problems)
    predicate = Or(*predicates)
    tags = sorted({str(t) for r in [head, *bases] for t in (getattr(r, "tags", None) or [])})
    techniques, tactics = _attack_tags(tags)
    used = sorted({lit.field for lit, _ in literals(predicate)} |
                  set(correlation.group_by if correlation else []) |
                  ({correlation.value_field} if correlation and correlation.value_field else set()))
    canonical = json.dumps(list(yaml.safe_load_all(yaml_text)), sort_keys=True, default=str)
    return CompiledRule(
        rule_id=_rule_id(head), title=head.title or "", level=str(head.level.name).lower() if head.level else None,
        description=" ".join(str(head.description or "").split()), tags=tags, techniques=techniques,
        tactics=tactics, sources=sources, predicate=predicate, fields=used,
        version_hash=_hash(canonical + COMPILER_VERSION), yaml_text=yaml_text, correlation=correlation,
        base_rules=[_rule_id(b) for b in bases] if corr else [], origin=origin)


# --------------------------------------------------------------------------- SQL rendering
def q(s: str) -> str:
    return "'" + str(s).replace("'", "''") + "'"


def _glob_to_like(pattern: str) -> str:
    out, i = [], 0
    while i < len(pattern):
        ch = pattern[i]
        if ch == "\\" and i + 1 < len(pattern):
            nxt = pattern[i + 1]
            out.append({"%": "\\%", "_": "\\_", "\\": "\\\\"}.get(nxt, nxt))
            i += 2
            continue
        out.append({"*": "%", "?": "_", "%": "\\%", "_": "\\_"}.get(ch, ch))
        i += 1
    return "".join(out)


def _scalar_sql(lit: Lit, x: str, typ: str) -> str:
    """Predicate over one scalar value expression `x` of ECS type `typ`."""
    base = typ.removesuffix("[]")
    numeric = base in ("long", "float")
    if lit.op == "exists":
        return f"{x} IS NOT NULL"
    if lit.op == "null":
        return f"{x} IS NULL"
    if lit.op in ("gt", "gte", "lt", "lte"):
        sym = {"gt": ">", "gte": ">=", "lt": "<", "lte": "<="}[lit.op]
        col = x if numeric else f"TRY_CAST({x} AS DOUBLE)"
        return f"{col} {sym} {float(lit.value)!r}"
    if lit.op == "cidr":
        net = ipaddress.ip_network(lit.value, strict=False)
        lo, hi = int(net.network_address), int(net.broadcast_address)
        x = f"CAST({x} AS VARCHAR)"
        as_int = " + ".join(f"CAST(split_part({x}, '.', {i + 1}) AS BIGINT) * {256 ** (3 - i)}" for i in range(4))
        return (f"(CASE WHEN regexp_full_match({x}, '[0-9]+[.][0-9]+[.][0-9]+[.][0-9]+') "
                f"THEN ({as_int}) BETWEEN {lo} AND {hi} ELSE false END)")
    if lit.op == "re":
        flags = lit.flags
        return f"regexp_matches(CAST({x} AS VARCHAR), {q(lit.value)}{', ' + q(flags) if flags else ''})"
    if numeric and lit.op == "eq" and isinstance(lit.value, (int, float)) and not isinstance(lit.value, bool):
        return f"{x} = {lit.value!r}"
    if base == "boolean":
        return f"{x} = {str(bool(lit.value)).upper()}"
    v = str(lit.value)
    col = f"CAST({x} AS VARCHAR)"
    if not lit.cased:
        col, v = f"lower({col})", v.lower()
    if lit.op == "eq":
        return f"{col} = {q(v)}"
    if lit.op == "contains":
        return f"contains({col}, {q(v)})"
    if lit.op == "startswith":
        return f"prefix({col}, {q(v)})"
    if lit.op == "endswith":
        return f"suffix({col}, {q(v)})"
    if lit.op == "glob":
        return f"{col} LIKE {q(_glob_to_like(v))} ESCAPE '\\'"
    raise ValueError(f"cannot render operator {lit.op}")


def lit_sql(lit: Lit, column: str | None = None, typ: str | None = None) -> str:
    typ = typ or ecs.catalog().fields.get(lit.field, "keyword")
    col = column or f'"{lit.field}"'
    if typ.endswith("[]"):
        if lit.op == "exists":
            return f"coalesce(len({col}) > 0, false)"
        if lit.op == "null":
            return f"coalesce(len({col}) = 0, true)"
        return f"coalesce(len(list_filter({col}, x -> {_scalar_sql(lit, 'x', typ)})) > 0, false)"
    if lit.op == "null":
        return f"({col} IS NULL)"
    return f"coalesce({_scalar_sql(lit, col, typ)}, false)"


def to_sql(e: Expr, render=lit_sql) -> str:
    if isinstance(e, Lit):
        return render(e)
    if e.kind == "not":
        return f"(NOT {to_sql(e.items[0], render)})"
    return "(" + f" {e.kind.upper()} ".join(to_sql(i, render) for i in e.items) + ")"
