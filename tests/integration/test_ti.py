"""M6 exit criteria: no identifiers leak in egress logs; invalid ATT&CK IDs are rejected;
ti.strategic shows the planted scenario tactics."""
import json
import sys
import uuid
from datetime import datetime, timezone

import httpx
import pytest
from sqlalchemy import select

from benchmarks.fidelity import corpus, submit_corpus
from engine.cli import LocalClient
from engine.common.db import assets, identities, ip_leases, llm_egress, rule_runs
from engine.cqrs.commands import EnrichBehavior, ReviewPattern
from engine.ti import tables as T
from engine.ti.llm_provider import LLMResult, OpenAICompatibleProvider, make_provider
from engine.ti.validator import validate

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="PyIceberg local IO needs POSIX paths")
START = datetime(2026, 9, 7, tzinfo=timezone.utc)
END = datetime(2026, 9, 13, tzinfo=timezone.utc)


@pytest.fixture(scope="module")
def client(pipeline):
    c = LocalClient.__new__(LocalClient)
    c.rt = pipeline
    return c


@pytest.fixture(scope="module")
def runs(pipeline, client):
    out = submit_corpus(client, START, END, corpus())
    pipeline.drain(pipeline=True)                     # observations -> rollups
    return out


@pytest.fixture
def offline(pipeline):
    real = pipeline.settings
    pipeline.settings = real.with_overrides(llm_provider="offline")
    yield pipeline
    pipeline.settings = real


def test_rule_hits_become_operational_observations_and_strategic_tactics(pipeline, runs):
    op, _ = T.read_all(pipeline.settings, T.OPERATIONAL)
    rule_rows = [r for r in op if r["origin"] == "rule"]
    assert rule_rows and all(r["entity_pseudonym"] and r["status"] == "auto_validated" for r in rule_rows)
    techniques = {t for r in rule_rows for t in r["attack_techniques"]}
    assert {"T1110.003", "T1059.001", "T1021.002", "T1071.004", "T1496", "T1098"} <= techniques
    st, _ = T.read_all(pipeline.settings, T.STRATEGIC)
    tactics = {r["tactic"] for r in st if r["period_type"] == "month"}
    planted = {"credential-access", "execution", "lateral-movement", "command-and-control", "exfiltration",
               "impact", "persistence", "defense-evasion", "initial-access"}
    assert planted <= tactics, planted - tactics
    assert all(r["business_unit"] for r in st)


def test_offline_enrichment_records_validated_patterns_without_leaking_identifiers(pipeline, runs, client, offline):
    run = runs["win_encoded_powershell"]
    client.wait([client.submit(EnrichBehavior(run_id=run["run_id"]))])
    op, _ = T.read_all(pipeline.settings, T.OPERATIONAL)
    llm = [r for r in op if r["origin"] == "llm" and r["rule_run_id"] == run["run_id"]]
    assert llm and all(r["llm_provider"] == "offline" and r["prompt_version"] for r in llm)
    assert all("T1059.001" in r["attack_techniques"] for r in llm)
    assert all(ref.startswith(("hit:", "art:")) for r in llm for ref in r["evidence_refs"])

    with pipeline.engine.connect() as conn:
        sent = [r.payload for r in conn.execute(select(llm_egress))]
        users = {r.name for r in conn.execute(select(identities.c.name).where(identities.c.kind != "builtin"))}
        hosts = {r.host_name for r in conn.execute(select(assets.c.host_name))}
        ips = {r.ip for r in conn.execute(select(ip_leases.c.ip))} | \
            {r.static_ip for r in conn.execute(select(assets.c.static_ip)) if r.static_ip}
    assert sent
    labels = json.loads((pipeline.settings.ground_truth_dir / "p" / "labels.json").read_text())
    users |= {u for lab in labels for u in lab["users"]} - {"system"}
    hosts |= {h for lab in labels for h in lab["hosts"]}
    text = json.dumps(sent).lower()
    leaked = [x for x in users | hosts | ips if x and f'"{x.lower()}"' in text or (x and f" {x.lower()} " in text)]
    assert not leaked, leaked[:10]
    import re
    assert not re.search(r"\b(10|192\.168)\.\d+\.\d+\.\d+\b", text)

    # identical bundle -> not re-sent
    before = len(sent)
    client.wait([client.submit(EnrichBehavior(run_id=run["run_id"], nonce="again"))])
    with pipeline.engine.connect() as conn:
        assert len(conn.execute(select(llm_egress)).all()) == before


def test_invalid_attack_ids_and_unknown_evidence_are_rejected():
    out = validate({"patterns": [
        {"title": "ok-ish", "narrative": "", "techniques": ["T9999", "T1059.001"], "confidence": 80,
         "evidence_ids": ["e1"]},
        {"title": "made up", "narrative": "", "techniques": ["T0000"], "confidence": 90, "evidence_ids": ["e1"]},
        {"title": "no evidence", "narrative": "", "techniques": ["T1105"], "confidence": 90,
         "evidence_ids": ["e42"]},
        {"title": "low confidence", "narrative": "", "techniques": ["T1105"], "confidence": 40,
         "evidence_ids": ["e1"]},
    ]}, {"e1", "e2"})
    assert [p["title"] for p in out.accepted] == ["ok-ish", "low confidence"]
    assert out.accepted[0]["techniques"] == ["T1059.001"] and "T9999" in out.dropped_techniques
    assert out.accepted[0]["status"] == "auto_validated" and out.accepted[1]["status"] == "proposed"
    assert len(out.rejected) == 2


def test_handler_drops_hallucinated_techniques(pipeline, runs, client, offline, monkeypatch):
    class Liar:
        name, model = "liar", "test"

        def complete(self, payload):
            ids = [e["id"] for e in payload["evidence"]]
            return LLMResult({"patterns": [
                {"title": "Hallucinated", "narrative": "", "techniques": ["T9999"], "confidence": 99,
                 "evidence_ids": ids[:1]},
                {"title": "Brute force burst", "narrative": "", "techniques": ["T1110.001", "T1110.999"],
                 "confidence": 90, "evidence_ids": ids[:1]}]}, "liar", "test")
    monkeypatch.setattr("engine.ti.llm_provider.make_provider", lambda s: Liar())
    run = runs["win_brute_force"]
    client.wait([client.submit(EnrichBehavior(run_id=run["run_id"], nonce=str(uuid.uuid4())))])
    op, _ = T.read_all(pipeline.settings, T.OPERATIONAL)
    liar = [r for r in op if r["llm_provider"] == "liar"]
    assert liar and {r["title"] for r in liar} == {"Brute force burst"}
    assert all(r["attack_techniques"] == ["T1110.001"] for r in liar)


def test_review_moves_status_and_rejected_rows_leave_strategic(pipeline, runs, client):
    op, _ = T.read_all(pipeline.settings, T.OPERATIONAL)
    target = next(r for r in op if r["origin"] == "rule" and "T1562.008" not in r["attack_techniques"]
                  and r["pattern_id"].endswith(runs["win_miner_commandline"]["rule_id"]))
    client.wait([client.submit(ReviewPattern(target_id=target["pattern_id"], verdict="rejected", reviewer="analyst1"))])
    pipeline.drain(pipeline=True)
    op, _ = T.read_all(pipeline.settings, T.OPERATIONAL)
    assert all(r["status"] == "rejected" and r["reviewed_by"] == "analyst1"
               for r in op if r["pattern_id"] == target["pattern_id"])
    st, _ = T.read_all(pipeline.settings, T.STRATEGIC)
    assert not any(target["title"] in r["top_patterns"] for r in st)
    client.wait([client.submit(ReviewPattern(target_id=target["pattern_id"], verdict="validated", reviewer="analyst1"))])
    pipeline.drain(pipeline=True)


def test_openai_compatible_provider_request_and_retry():
    calls = []

    def handler(request: httpx.Request):
        calls.append(json.loads(request.content))
        if len(calls) == 1:
            return httpx.Response(429, headers={"retry-after": "0"})
        return httpx.Response(200, json={"choices": [{"message": {"content": json.dumps({"patterns": []})}}],
                                         "usage": {"prompt_tokens": 11, "completion_tokens": 3}})
    p = OpenAICompatibleProvider("groq", "https://api.groq.com/openai/v1", "configured-model", "k",
                                 requests_per_minute=6000, transport=httpx.MockTransport(handler))
    res = p.complete({"entity": {}, "window": {}, "evidence": []})
    assert res.content == {"patterns": []} and res.prompt_tokens == 11 and len(calls) == 2
    assert calls[1]["model"] == "configured-model" and calls[1]["response_format"] == {"type": "json_object"}


def test_provider_configuration_is_required(pl_settings):
    assert make_provider(pl_settings.with_overrides(llm_provider=None)) is None
    with pytest.raises(ValueError, match="LLM_MODEL"):
        make_provider(pl_settings.with_overrides(llm_provider="groq", llm_model=None, llm_api_key="x"))
    with pytest.raises(ValueError, match="GROQ_API_KEY"):
        make_provider(pl_settings.with_overrides(llm_provider="groq", llm_model="m", llm_api_key=None))


def test_ti_query_endpoints(pipeline, runs):
    from fastapi.testclient import TestClient
    from engine.api.query_api import create_app
    api = TestClient(create_app(pipeline))
    s = api.get("/ti/summary").json()
    assert s["operational"]["rows"] > 0 and s["strategic"]["rows"] > 0
    strat = api.get("/ti/strategic?period=month&compare=yoy").json()
    assert strat["comparison"] and strat["snapshot_id"]
    assert api.get("/ti/patterns").json()["count"] > 0
    with pipeline.engine.connect() as conn:
        assert conn.execute(select(rule_runs)).first() is not None
