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


def test_true_plant_snapshots_do_not_change_episodes():
    """The evaluation hands the TRUE plant to the observer (to replay fixes); episodes must be unchanged."""
    import random as _r
    from aegis import evaluate as ev
    from aegis.audit import AuditLog
    plain = ev.attack_episode(5, True, POL)
    clock = ev.Clock()
    log = AuditLog(":memory:", clock=clock)
    obs = D.Episode(log, clock, _r.Random(0))
    assert ev.attack_episode(5, True, POL, audit=log, clock=clock, observer=obs) == plain
    assert obs.snaps and obs.plant_at(obs.snaps[3][0]) is obs.snaps[3][1]
    assert obs.plant_at(-1) is None
    # snapshots are independent copies: changing one doesn't touch another
    a, b = obs.snaps[1][1], obs.snaps[2][1]
    a.set("naoh_dose", 7)
    assert b.setpoint("naoh_dose") != 7 or a is not b


def test_typo_and_retry_features_and_rule():
    """An operator types 1000 instead of 100, is blocked, re-sends 100 a minute later and stops."""
    def fill(c, log):
        log.append("login", {"user": "operator"})
        c.t += 60
        dec(log, new=1000, old=90, check="range")
        c.t += 60
        dec(log, new=100, old=90, allowed=True, check="ok")
    F, b = features(fill)
    assert F["retry_after_block"]["value"] and F["typo_like"]["value"]
    assert b["primary"] == "operator_error"


def test_persistent_pusher_is_not_a_retry():
    def fill(c, log):
        for i in range(5):
            c.t += 60
            dec(log, new=200 + 10 * i, old=100, check="range")
    F, _ = features(fill)
    assert not F["retry_after_block"]["value"]


def test_typo_generator_labels_from_true_plant():
    found = []
    for s in range(6):
        found += D.typo_cases(s, POL)
    assert found and {c.label for c in found} <= {"operator_error", "benign_false_positive"}
    assert all(c.meta["strategy"] == "typo" for c in found)


def test_ablation_runs_and_removes_the_group(tmp_path):
    import json as _j
    from aegis.agent import ablate as A
    rows = []
    for s in range(3):
        for c in D.plc_cases(s, POL) + D.ai_cases(s, POL) + D.typo_cases(s, POL):
            rows.append({"cid": c.cid, "label": c.label, "F": {k: v["value"] for k, v in FT.extract(c.evidence()).items()}})
    p = tmp_path / "rows.json"
    p.write_text(_j.dumps(rows, default=str))
    A.main(["--train", str(p), "--test", str(p), "--out", str(tmp_path / "abl")])
    res = _j.loads((tmp_path / "abl.json").read_text())
    assert "all signals" in res and len(res) == 1 + len(A.GROUPS)
    dropped = A._drop(A._load(str(p)), set(A.GROUPS["human presence"]))
    assert all("human_present" not in r["F"] for r in dropped)


def test_generator_chunks_do_not_overlap():
    """Regression: train.generate on seeds 0-19 and 20-39 shared operator seeds 20-119 (300 duplicate rows)."""
    import aegis.agent.train as TR
    calls = []
    orig = D.operator_cases
    try:
        D.operator_cases = lambda x, *a, **k: calls.append(x) or []
        for gen in ("attack_cases", "plc_cases", "ai_cases", "oneshot_cases", "typo_cases"):
            setattr(D, "_orig_" + gen, getattr(D, gen))
            setattr(D, gen, lambda *a, **k: [])
        TR.generate(range(0, 3))
        first = list(calls)
        calls.clear()
        TR.generate(range(3, 6))
        assert first == list(range(0, 18)) and not set(first) & set(calls)
    finally:
        D.operator_cases = orig
        for gen in ("attack_cases", "plc_cases", "ai_cases", "oneshot_cases", "typo_cases"):
            setattr(D, gen, getattr(D, "_orig_" + gen))
    assert len(TR.dedupe([{"cid": "a"}, {"cid": "a"}, {"cid": "b"}])) == 2
