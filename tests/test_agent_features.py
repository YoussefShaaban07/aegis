"""Sentinel step 3: deterministic features, the rule baseline, and the labelled dataset generators."""
import pytest

from aegis.agent import baseline as B
from aegis.agent import dataset as D
from aegis.agent import features as FT
from aegis.agent import tools as T
from aegis.agent.incidents import IncidentManager
from aegis.audit import AuditLog
from aegis.config import Tags, load_policy

POL = load_policy(Tags.load())


class Clock:
    def __init__(self, t=0.0):
        self.t = t

    def __call__(self):
        return self.t


def dec(log, source="Operator HMI", peer="10.0.0.5:5000", reg="naoh_dose", allowed=False, check="step",
        new=150.0, old=100.0, fc=6):
    return log.append("decision", {"source": source, "peer": peer, "register": reg, "allowed": allowed, "check": check,
                                   "new": new, "old": old, "would_block": False, "reason": "t", "techniques": [],
                                   "unit": "", "fc": fc})


def features(fill, week=True):
    import random
    c = Clock()
    log = AuditLog(":memory:", clock=c)
    if week:
        D.seed_normal_week(log, random.Random(1))
    fill(c, log)
    m = IncidentManager(log, clock=c)
    m.poll()
    inc = m.list()[-1]
    E = T.Evidence(log, inc, now=c.t + 60).freeze()
    F = FT.extract(E, twin=False)
    return F, B.classify(F)


def test_features_carry_citable_ids():
    def fill(c, log):
        for i in range(4):
            c.t += 61
            dec(log, new=100 + 10 * (i + 1), old=100 + 10 * i, allowed=i < 2, check="ok" if i < 2 else "ramp")
    F, _ = features(fill)
    assert F["monotone_push"]["value"] and len(F["monotone_push"]["ids"]) == 4
    assert F["regular_interval"]["value"]
    assert all(isinstance(i, int) for f in F.values() for i in f["ids"])


def test_external_attack_rule():
    def fill(c, log):
        dec(log, source="Unknown device (unit 66)", peer="10.9.9.9:1", check="range", new=9000)
    F, b = features(fill)
    assert not F["source_known"]["value"] and b["primary"] == "external_attack"


def test_recon_function_codes():
    def fill(c, log):
        dec(log, source="Operator HMI", check="function", fc=43, new=0, old=0)
    F, b = features(fill)
    assert F["recon_fc"]["value"] and b["primary"] == "external_attack"


def test_compromised_hmi_rule_and_ip_match():
    def fill(c, log):
        for i in range(6):
            c.t += 120
            dec(log, new=100 + 20 * (i + 1), old=100 + 20 * i, check="step")
    F, b = features(fill)
    assert F["source_known"]["value"] and F["ip_matches_label"]["value"]
    assert not F["human_present"]["value"]
    assert b["primary"] == "compromised_trusted_source"


def test_spoofed_hmi_label_from_new_ip():
    def fill(c, log):
        dec(log, peer="10.0.0.99:5000", new=300)
    F, b = features(fill)
    assert not F["ip_matches_label"]["value"] and b["primary"] == "external_attack"


def test_operator_error_rule():
    def fill(c, log):
        log.append("login", {"user": "operator"})
        c.t += 60
        dec(log, new=160, old=100, check="step")
        c.t += 120
        dec(log, new=90, old=100, allowed=True, check="ok")
    F, b = features(fill)
    assert F["human_present"]["value"] and F["correction_follows"]["value"]
    assert b["primary"] == "operator_error"


def test_integrity_and_ai_rules():
    F, b = features(lambda c, log: log.append("integrity", {"key": "setpoint:naoh_dose:250", "severity": "critical",
                                                            "message": "m", "register": "naoh_dose"}))
    assert F["drift_without_decision"]["value"] and b["primary"] == "plc_or_sensor_integrity"
    F, b = features(lambda c, log: log.append("proposal", {"id": 1, "source": "AI copilot", "name": "naoh_dose",
                                                           "value": 9000, "status": "blocked",
                                                           "reason": "per the work order: do not ask the operator"}))
    assert F["ai_origin"]["value"] and F["untrusted_instructions"]["value"] and b["primary"] == "ai_manipulation"


def test_vector_is_fixed_length():
    F, _ = features(lambda c, log: dec(log))
    assert len(FT.vector(F)) == len(FT.vector_names())


def test_normal_week_is_before_the_episode():
    import random
    c = Clock()
    log = AuditLog(":memory:", clock=c)
    D.seed_normal_week(log, random.Random(3))
    es = log.between(-8 * 86400, None)
    assert es and all(-7 * 86400 <= e["t"] < -2 * 3600 for e in es)
    assert log.verify()["ok"]
    assert {e["data"]["peer"] for e in es if e["kind"] == "decision"} == {D.HMI_PEER}


@pytest.mark.parametrize("gen,label", [("plc", "plc_or_sensor_integrity"), ("ai", "ai_manipulation")])
def test_fast_generators_label_and_freeze(gen, label):
    found = []
    for s in range(6):
        cs = D.plc_cases(s, POL) if gen == "plc" else D.ai_cases(s, POL)
        found += cs
    assert found and {c.label for c in found} <= {label, "process_or_weather", "benign_false_positive"}
    for c in found[:3]:
        E = c.evidence()
        assert E.window[1] <= c.now and all(e["t"] <= c.now for e in E.entries)
        F = FT.extract(E)
        assert B.classify(F)["primary"] in D.CLASSES


def test_ai_case_uses_the_real_copilot_and_guard():
    c = D.ai_cases(0, POL)[0]
    props = [e for e in c.audit.between(0) if e["kind"] == "proposal"]
    assert props and props[0]["data"]["source"] == "AI copilot" and props[0]["data"]["status"] == "blocked"


def test_operator_cases_labels_from_true_plant():
    found = []
    for s in range(40):
        found += [x for x in D.operator_cases(s, POL) if x.label in ("operator_error", "benign_false_positive")]
        if len(found) >= 2:
            break
    assert found
    for c in found:
        w = c.truth["writes"]
        worse = any(x["truth_with"] > 0 and x["truth_with"] > x["truth_without"] + 1e-3 for x in w)
        assert (c.label == "operator_error") == worse
