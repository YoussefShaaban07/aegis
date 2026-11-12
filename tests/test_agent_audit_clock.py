"""Sentinel step 0: evaluation episodes can leave a hash-chained, simulated-time audit log,
and attaching one never changes an episode's outcome."""
from aegis import evaluate as ev
from aegis.audit import AuditLog
from aegis.config import Tags, load_policy


def test_audit_clock_used_and_chain_verifies():
    t = [100.0]
    log = AuditLog(":memory:", clock=lambda: t[0])
    a = log.append("x", {"n": 1})
    t[0] = 160.5
    b = log.append("x", {"n": 2})
    assert (a["t"], b["t"]) == (100.0, 160.5)
    assert log.verify()["ok"]
    assert [e["id"] for e in log.between(150, 200)] == [b["id"]]


def test_default_clock_is_wall_time():
    import time
    e = AuditLog(":memory:").append("x", {})
    assert abs(e["t"] - time.time()) < 5


def test_episode_identical_with_audit_and_logs_decisions(monkeypatch):
    pol = load_policy(Tags.load())
    for attacker in ("unknown", "hmi"):
        monkeypatch.setattr(ev, "ATTACKER", attacker)
        plain = ev.attack_episode(0, True, pol)
        clock = ev.Clock()
        log = AuditLog(":memory:", clock=clock)
        logged = ev.attack_episode(0, True, pol, audit=log, clock=clock)
        assert plain == logged
        assert log.verify()["ok"]
        dec = log.between(0, kinds=("decision",))
        assert dec, attacker
        # timestamps are simulated seconds inside the episode, not wall time
        assert all(0 <= e["t"] <= (8 * 60 + 360) * 60 for e in dec)
        assert all(e["data"]["t"] == e["t"] for e in dec)


def test_operator_episode_identical_with_audit():
    pol = load_policy(Tags.load())
    plain = ev.operator_episode(1, True, pol)
    clock = ev.Clock()
    log = AuditLog(":memory:", clock=clock)
    assert ev.operator_episode(1, True, pol, audit=log, clock=clock) == plain
    assert all(e["data"]["source"] == "Operator HMI" for e in log.between(0, kinds=("decision",)))
