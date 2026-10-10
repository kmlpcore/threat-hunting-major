"""LLM providers for behavioural pattern enrichment (plan.md section 3.9, step 3).

    LLM_PROVIDER=groq      Groq's OpenAI-compatible API (GROQ_API_KEY), model from LLM_MODEL
    LLM_PROVIDER=openai|vllm|ollama   any OpenAI-compatible endpoint (LLM_BASE_URL, LLM_API_KEY)
    LLM_PROVIDER=offline   deterministic local heuristic: nothing leaves the host
    (unset)                enrichment disabled

Groq only runs inference; it stores nothing. Results are validated and stored in our own
Iceberg TI tables. The output is advisory (plan.md non-goals): it never becomes a detection
verdict without validation.
"""
from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass
from typing import Protocol

import httpx

from engine.common.config import REPO_ROOT, Settings
from engine.ti.bundler import egress_policy

log = logging.getLogger(__name__)
OUTPUT_SCHEMA = json.loads((REPO_ROOT / "schemas" / "llm" / "pattern_output.schema.json").read_text())

SYSTEM_PROMPT = """You are a threat-intelligence analyst. You receive one behaviour bundle: pseudonymised
evidence (rule hits and derived artefacts) about one entity in one time window. Identify the
attacker behaviour patterns it shows and map each to MITRE ATT&CK Enterprise.

Rules:
- Use only ATT&CK Enterprise technique IDs (Txxxx or Txxxx.yyy) and tactic short names
  (e.g. credential-access, lateral-movement).
- Every pattern must cite the evidence ids (e1, a2, ...) that support it. Do not invent evidence.
- Confidence is 0-100: how sure you are the pattern is malicious activity, given only this evidence.
- If the evidence looks benign, return {"patterns": []}.
- Answer with a single JSON object that matches this JSON Schema, and nothing else:
""" + json.dumps(OUTPUT_SCHEMA)


@dataclass
class LLMResult:
    content: dict
    provider: str
    model: str
    prompt_tokens: int = 0
    completion_tokens: int = 0


class LLMProvider(Protocol):
    name: str
    model: str

    def complete(self, payload: dict) -> LLMResult: ...


class OpenAICompatibleProvider:
    """Chat-completions client with JSON output, rate limiting and retry with backoff."""

    def __init__(self, name: str, base_url: str, model: str, api_key: str | None, timeout_s: float = 60,
                 max_retries: int = 4, requests_per_minute: int = 20, temperature: float = 0,
                 transport: httpx.BaseTransport | None = None):
        self.name, self.model = name, model
        self.client = httpx.Client(base_url=base_url.rstrip("/"), timeout=timeout_s, transport=transport,
                                   headers={"Authorization": f"Bearer {api_key}"} if api_key else {})
        self.max_retries, self.temperature = max_retries, temperature
        self.min_interval = 60.0 / max(1, requests_per_minute)
        self._last = 0.0

    def complete(self, payload: dict) -> LLMResult:
        body = {"model": self.model, "temperature": self.temperature,
                "response_format": {"type": "json_object"},
                "messages": [{"role": "system", "content": SYSTEM_PROMPT},
                             {"role": "user", "content": json.dumps(payload, default=str)}]}
        delay = 2.0
        for attempt in range(1, self.max_retries + 1):
            wait = self._last + self.min_interval - time.monotonic()
            if wait > 0:
                time.sleep(wait)
            self._last = time.monotonic()
            try:
                r = self.client.post("/chat/completions", json=body)
            except httpx.HTTPError as exc:
                if attempt == self.max_retries:
                    raise
                log.warning("llm request failed (%s), retrying in %.0fs", exc, delay)
                time.sleep(delay)
                delay *= 2
                continue
            if r.status_code in (429, 500, 502, 503, 504) and attempt < self.max_retries:
                retry_after = float(r.headers.get("retry-after", delay))
                log.warning("llm %s returned %d, retrying in %.0fs", self.name, r.status_code, retry_after)
                time.sleep(min(retry_after, 60))
                delay *= 2
                continue
            r.raise_for_status()
            data = r.json()
            text = data["choices"][0]["message"]["content"]
            usage = data.get("usage") or {}
            return LLMResult(json.loads(text), self.name, self.model, usage.get("prompt_tokens", 0),
                             usage.get("completion_tokens", 0))
        raise RuntimeError("unreachable")


# --------------------------------------------------------------------------- offline heuristic
KEYWORDS = [  # (predicate over a redacted evidence item, techniques, title fragment)
    (lambda e: _cmd(e).get("base64_like") or "-enc" in _cmd(e).get("flags", []), ["T1059.001", "T1027"],
     "encoded PowerShell"),
    (lambda e: "downloadstring" in _cmd(e).get("mentions", []) or _cmd(e).get("has_url"), ["T1105"],
     "payload download"),
    (lambda e: _proc(e, "parent") in ("winword.exe", "excel.exe", "powerpnt.exe", "outlook.exe"),
     ["T1566.001", "T1204.002"], "malicious Office document"),
    (lambda e: _proc(e) == "certutil.exe", ["T1105"], "certutil download"),
    (lambda e: _proc(e) == "mshta.exe", ["T1218.005"], "mshta proxy execution"),
    (lambda e: _proc(e) == "rundll32.exe", ["T1218.011"], "rundll32 proxy execution"),
    (lambda e: _proc(e) == "bitsadmin.exe", ["T1197"], "BITS job"),
    (lambda e: "psexesvc.exe" in (_proc(e), _proc(e, "parent")), ["T1569.002", "T1021.002"], "PsExec execution"),
    (lambda e: "whoami" in _cmd(e).get("mentions", []) or "net group" in _cmd(e).get("mentions", []),
     ["T1033", "T1087.002"], "account discovery"),
    (lambda e: "stratum" in _cmd(e).get("mentions", []) or _proc(e) == "xmrig.exe", ["T1496"], "cryptomining"),
    (lambda e: str(e.get("fields", {}).get("event.code")) in ("4728", "4732"), ["T1098"],
     "privileged group change"),
]


def _fields(e: dict) -> dict:
    return e.get("fields") or e.get("row") or {}


def _cmd(e: dict) -> dict:
    c = _fields(e).get("process.command_line")
    return c if isinstance(c, dict) else {}


def _proc(e: dict, which: str = "") -> str:
    f = _fields(e)
    key = "process.parent.name" if which == "parent" else "process.name"
    alt = "parent_name" if which == "parent" else "process_name"
    return str(f.get(key) or f.get(alt) or "").lower()


class OfflineProvider:
    """Deterministic stand-in for an LLM: maps redacted evidence to ATT&CK with keyword rules
    and the techniques of the rules that fired. Lets the whole TI pipeline run air-gapped."""
    name = "offline"
    model = "heuristic-v1"

    def complete(self, payload: dict) -> LLMResult:
        techniques: dict[str, list[str]] = {}
        titles: list[str] = []
        for e in payload["evidence"]:
            for t in e.get("rule_techniques", []) or []:
                techniques.setdefault(t, []).append(e["id"])
            for pred, techs, title in KEYWORDS:
                try:
                    hit = pred(e)
                except Exception:  # noqa: BLE001
                    hit = False
                if hit:
                    for t in techs:
                        techniques.setdefault(t, []).append(e["id"])
                    if title not in titles:
                        titles.append(title)
            if e.get("kind") == "rule_hit" and e.get("rule") and not titles:
                titles.append(e["rule"])
        if not techniques:
            return LLMResult({"patterns": []}, self.name, self.model)
        hits = [e for e in payload["evidence"] if e.get("kind") == "rule_hit"]
        evidence = sorted({i for ids in techniques.values() for i in ids}, key=lambda x: (x[0], int(x[1:])))
        confidence = min(95, 55 + 10 * len({e.get("rule") for e in hits}))
        title = " + ".join(titles[:4]) or "suspicious activity"
        return LLMResult({"patterns": [{
            "title": title[:1].upper() + title[1:],
            "narrative": f"{len(hits)} rule hit(s) on {payload['entity']['type']} {payload['entity']['id']} "
                         f"between {payload['window']['start']} and {payload['window']['end']}: "
                         + "; ".join(sorted({str(e.get('rule')) for e in hits})),
            "tactics": [], "techniques": sorted(techniques), "kill_chain_phase": None,
            "severity": "high" if confidence >= 75 else "medium", "confidence": confidence,
            "evidence_ids": evidence}]}, self.name, self.model)


def make_provider(settings: Settings) -> LLMProvider | None:
    name = (settings.llm_provider or "").lower()
    if not name:
        return None
    if name == "offline":
        return OfflineProvider()
    pol = egress_policy()["provider"]
    model = settings.llm_model or pol.get("model")
    if not model:
        raise ValueError("LLM_MODEL is not set (the model name is configuration, never hardcoded)")
    base = settings.llm_base_url or pol["base_urls"].get(name)
    if not base:
        raise ValueError(f"no base URL for LLM provider {name!r}: set LLM_BASE_URL")
    if name == "groq" and not settings.llm_api_key:
        raise ValueError("GROQ_API_KEY is not set")
    return OpenAICompatibleProvider(name, base, model, settings.llm_api_key, pol["timeout_s"], pol["max_retries"],
                                    pol["requests_per_minute"], pol["temperature"])
