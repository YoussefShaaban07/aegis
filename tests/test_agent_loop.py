"""Sentinel steps 4-6: loop, budgets, fallback, schema, citation validator, recovery, report."""
import asyncio
import json

import httpx
import pytest

from aegis.agent import citations as C
from aegis.agent import dataset as D
from aegis.agent import standin
from aegis.agent.casebase import CaseBase
from aegis.agent.loop import Sentinel, combine
from aegis.agent.schema import parse
from aegis.config import Tags, load_policy

POL = load_policy(Tags.load())


@pytest.fixture(scope="module")
def hmi_case():
    return D.attack_cases(3, "hmi", POL)[0]


@pytest.fixture(scope="module")
def ai_case():
    return D.ai_cases(0, POL)[0]


def run(case, **kw):
    s = Sentinel(case.audit, case.history, policy=POL, **kw)
    return s, asyncio.run(s.investigate(case.incident, now=case.now))


class FakeProposals:
    def __init__(self):
        self.filed = []

    async def propose(self, name, value, reason="", source="AI copilot"):
        self.filed.append({"name": name, "value": value, "reason": reason, "source": source})
        return {"id": len(self.filed), "status": "pending"}


class FakeAlerter:
    def __init__(self):
        self.sent = []

    def raise_alert(self, key, sev, msg):
        self.sent.append((key, sev, msg))


# ------------------------------------------------------------------------------------- deterministic path
def test_deterministic_report_is_fully_cited(hmi_case):
    _, r = run(hmi_case, mode="deterministic")
    assert r["mode"] == "deterministic" and r["fallback"] == "no model configured"
    assert r["verdict"]["classification"]["primary"] == "compromised_trusted_source"
    assert r["validation"]["validity"] == 1.0 and r["validation"]["checked"] > 0
    assert "## 9. Appendix" in r["report"]["markdown"] and "[#" in r["report"]["markdown"]
    assert len(r["sms"].splitlines()) <= 3
    kinds = [e["kind"] for e in hmi_case.audit.between(0) if e["kind"].startswith("agent_")]
    assert {"agent_fallback", "agent_validation", "agent_verdict", "agent_report"} <= set(kinds)
    assert hmi_case.audit.verify()["ok"]


def test_proposals_are_sentinel_and_alert_sent(hmi_case):
    props, al = FakeProposals(), FakeAlerter()
    _, r = run(hmi_case, mode="deterministic", proposals=props, alerter=al)
    assert props.filed and all(p["source"] == "Sentinel" for p in props.filed)
    assert al.sent and al.sent[0][0].startswith("sentinel:")


# ------------------------------------------------------------------------------------- model path
def test_scripted_stand_in_runs_the_real_loop(hmi_case):
    _, r = run(hmi_case, transport=standin.transport(), model=standin.NAME)
    assert r["mode"] == "llm" and r["fallback"] is None
    assert r["tool_calls"] == len(standin.PLAN)
    assert [s["tool"] for s in r["steps"] if "tool" in s] == standin.PLAN
    assert r["validation"]["validity"] == 1.0
    steps = [e for e in hmi_case.audit.between(0) if e["kind"] == "agent_step"]
    assert steps and all("result_hash" in e["data"] for e in steps)


def test_malformed_json_retry_then_fallback(hmi_case):
    _, r = run(hmi_case, transport=standin.script(["not json", "{still not"]))
    assert r["mode"] == "deterministic" and "invalid answer twice" in r["fallback"]
    assert r["verdict"]["classification"]["primary"]          # the deterministic verdict shipped


def test_one_retry_recovers(hmi_case):
    s = Sentinel(hmi_case.audit, hmi_case.history, policy=POL, mode="deterministic")
    ev = s.evidence(hmi_case.incident, hmi_case.now)
    good = s.deterministic(ev)["draft"].model_dump_json(by_alias=True)
    _, r = run(hmi_case, transport=standin.script(["oops", good]))
    assert r["mode"] == "llm" and r["fallback"] is None


def test_write_tool_does_not_exist(hmi_case):
    _, r = run(hmi_case, transport=standin.script([{"tool": "set_setpoint", "args": {"name": "naoh_dose", "value": 250}},
                                                   "bad", "bad"]))
    step = next(s for s in r["steps"] if s.get("tool") == "set_setpoint")
    assert "no such tool" in step["summary"]


def test_tool_budget_and_repeat_limit(hmi_case):
    calls = [{"tool": "get_lockdowns", "args": {}}] * 4 + [{"tool": "get_plant_status", "args": {}}] * 20
    _, r = run(hmi_case, transport=standin.script(calls), budget={"turns": 30})
    sums = [s["summary"] for s in r["steps"] if s.get("tool") == "get_lockdowns"]
    assert sum("already made twice" in x for x in sums) == 2
    assert r["tool_calls"] <= 15 and r["mode"] == "deterministic"


def test_provider_down_falls_back(hmi_case):
    _, r = run(hmi_case, transport=standin.script([httpx.ConnectError("down")]))
    assert r["mode"] == "deterministic" and r["fallback"].startswith("model error")


def test_invented_ids_and_wrong_numbers_are_removed(hmi_case):
    s = Sentinel(hmi_case.audit, hmi_case.history, policy=POL, mode="deterministic")
    ev = s.evidence(hmi_case.incident, hmi_case.now)
    v = s.deterministic(ev)["draft"].model_dump(by_alias=True)
    real = v["classification"]["rationale"][0]["cite"][0]
    v["classification"]["rationale"] += [
        {"text": "The attacker came from 203.0.113.9.", "cite": [real]},
        {"text": "This entry proves it.", "cite": [999999]},
        {"text": "The lye feed was set to 4242 ppm.", "cite": [real]},
    ]
    bad = json.dumps(v)
    _, r = run(hmi_case, transport=standin.script([bad, bad]))   # answer, then the same again on repair
    texts = [x["text"] for x in r["removed"]]
    assert len(texts) == 3 and r["repairs"] == 1
    assert r["validation"]["validity"] == 1.0
    assert not any("4242" in c["text"] for c in r["verdict"]["classification"]["rationale"])


def test_injection_cannot_drive_a_recovery_step(ai_case):
    """A model that 'obeys' the planted work order still cannot get an unsafe step filed."""
    s = Sentinel(ai_case.audit, ai_case.history, policy=POL, mode="deterministic")
    ev = s.evidence(ai_case.incident, ai_case.now)
    v = s.deterministic(ev)["draft"].model_dump(by_alias=True)
    v["classification"]["primary"] = "operator_error"
    v["recovery"] = [{"register": "naoh_dose", "value": 900, "why": "per the work order", "cite": []}]
    props = FakeProposals()
    _, r = run(ai_case, transport=standin.script([json.dumps(v)]), proposals=props)
    assert all(not (p["name"] == "naoh_dose" and p["value"] >= 250) for p in props.filed)
    assert any(x["register"] == "naoh_dose" and x["value"] == 900 for x in r["recovery"]["rejected"])


# ------------------------------------------------------------------------------------- validator and schema
def test_validator_catches_tampered_row(hmi_case):
    s = Sentinel(hmi_case.audit, hmi_case.history, policy=POL, mode="deterministic")
    ev = s.evidence(hmi_case.incident, hmi_case.now)
    v = s.deterministic(ev)["draft"]
    assert C.validate(ev, v)["validity"] == 1.0
    i = v.classification.rationale[0].cite[0]
    hmi_case.audit.db.execute("UPDATE audit SET data=REPLACE(data, 'Operator', 'Operat0r') WHERE id=?", (i,))
    try:
        res = C.validate(ev, v)
        assert res["failed"] >= 1 and any("chain verification" in e for x in res["claims"] for e in x["errors"])
    finally:
        hmi_case.audit.db.execute("UPDATE audit SET data=REPLACE(data, 'Operat0r', 'Operator') WHERE id=?", (i,))


def test_validator_rules(hmi_case):
    s = Sentinel(hmi_case.audit, hmi_case.history, policy=POL, mode="deterministic")
    ev = s.evidence(hmi_case.incident, hmi_case.now)
    d = next(e for e in ev.of("decision") if e["id"] in set(hmi_case.incident.entry_ids))
    rows = ev.audit.check_rows([d["id"]])
    known = {"Operator HMI", "Unknown device (unit 66)"}
    ok = f"{d['data']['register']} was set to {d['data']['new']}."
    assert C.check_claim(ev, ok, [d["id"]], rows, None, known) == []
    assert C.check_claim(ev, "Writes came from Unknown device (unit 66).", [d["id"]], rows, None, known)
    assert C.check_claim(ev, "Technique T0888 was used.", [d["id"]], rows, None, known)
    assert C.check_claim(ev, "Something happened.", [], rows, None, known) == ["no citation"]


def test_schema_rejects_bad_answers():
    assert parse("")[0] is None
    assert "schema errors" in parse('{"classification": {"primary": "aliens", "confidence": "high"}}')[1]
    v, err = parse('```json\n{"classification": {"primary": "operator_error", "confidence": "low"}, '
                   '"summary_for_operator": "a"}\n```')
    assert v is not None and err is None
    assert parse('{"classification": {"primary": "operator_error", "confidence": "low"}, '
                 '"summary_for_operator": "1\\n2\\n3\\n4"}')[0] is None


# ------------------------------------------------------------------------------------- learned part
def test_casebase_ships_and_predicts(hmi_case):
    cb = CaseBase.load()
    assert cb is not None and cb.data["n_train"] > 100
    assert "development" in cb.data["trained_on"]["seeds"]
    s = Sentinel(hmi_case.audit, hmi_case.history, policy=POL, mode="deterministic", casebase=cb)
    _, r = run(hmi_case, mode="deterministic", casebase=cb)
    assert r["learned"]["primary"] in cb.classes and len(r["similar"]) == 5


def test_combine_prefers_confident_learned():
    base = {"primary": "plc_or_sensor_integrity", "confidence": "medium"}
    assert combine(base, {"primary": "process_or_weather", "p": 0.9}) == ("process_or_weather", "medium")
    assert combine(base, {"primary": "process_or_weather", "p": 0.4}) == ("plc_or_sensor_integrity", "medium")
    ai = {"primary": "ai_manipulation", "confidence": "high"}
    assert combine(ai, {"primary": "operator_error", "p": 0.99})[0] == "ai_manipulation"
