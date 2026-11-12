"""Sentinel step 1: triggers, coalescing, lifecycle and budget of the incident store."""
import pytest

from aegis import evaluate as ev
from aegis.agent import incidents as I
from aegis.agent.incidents import IncidentManager
from aegis.audit import AuditLog
from aegis.config import Tags, load_policy


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def env():
    c = Clock()
    log = AuditLog(":memory:", clock=c)
    return c, log, IncidentManager(log, clock=c)


class FakeAlerter:
    def __init__(self):
        self.alerts = []

    def raise_alert(self, key, sev, msg):
        self.alerts.append((key, sev, msg))


def dec(log, source="Unknown device (unit 66)", peer="10.9.9.9:4444", reg="naoh_dose", allowed=False,
        check="range", new=500.0, old=100.0, would_block=False):
    return log.append("decision", {"source": source, "peer": peer, "register": reg, "allowed": allowed,
                                   "check": check, "new": new, "old": old, "would_block": would_block,
                                   "reason": "test", "techniques": [], "unit": "", "fc": 6})


def test_flood_is_one_incident(env):
    c, log, m = env
    for _ in range(30):
        dec(log)
        c.t += 1
    m.poll()
    assert len(m.incidents) == 1
    inc = m.list()[0]
    assert len(inc.trigger_ids) == 30 and inc.state == I.COLLECTING
    assert inc.ips == {"10.9.9.9"} and inc.registers == {"naoh_dose"}


def test_unrelated_events_are_separate(env):
    c, log, m = env
    dec(log)
    c.t += 60
    dec(log, source="Other (unit 9)", peer="10.7.7.7:1", reg="chlorine_dose")
    m.poll()
    assert len(m.incidents) == 2


def test_shared_ip_joins_even_with_new_label(env):
    """A spoofed label from the same machine is the same activity."""
    c, log, m = env
    dec(log)
    c.t += 60
    dec(log, source="Operator HMI", peer="10.9.9.9:5000", reg="chlorine_dose")
    m.poll()
    assert len(m.incidents) == 1
    assert m.list()[0].sources == {"Unknown device (unit 66)", "Operator HMI"}


def test_join_window_and_quiet_close(env):
    c, log, m = env
    dec(log)
    c.t += 16 * 60                       # beyond the 15-min join window: new incident
    dec(log)
    assert m.poll(now=c.t) == []        # nothing quiet for 30 min yet
    assert len(m.incidents) == 2
    started = m.poll(now=c.t + 14 * 60 + 1)   # first one is now 30 min quiet
    assert [i.id for i in started] == [1]
    assert m.get(1).state == I.INVESTIGATING and m.get(2).state == I.COLLECTING


def test_allowed_writes_join_but_never_open(env):
    c, log, m = env
    dec(log, allowed=True, check="ok")
    m.poll()
    assert m.incidents == {}
    dec(log)
    c.t += 30
    dec(log, allowed=True, check="ok", new=120)
    m.poll()
    inc = m.list()[0]
    assert len(inc.entry_ids) == 2 and len(inc.trigger_ids) == 1


def test_lockdown_is_urgent(env):
    c, log, m = env
    dec(log)
    log.append("lockdown", {"source": "Unknown device (unit 66)", "blocks": 6, "last_register": "naoh_dose"})
    started = m.poll(now=c.t)            # no 30-min wait
    assert len(started) == 1 and started[0].kinds == {"decision": 1, "lockdown": 1}


def test_integrity_warning_vs_info(env):
    c, log, m = env
    log.append("integrity", {"key": "x", "severity": "info", "message": "m"})
    m.poll()
    assert m.incidents == {}
    log.append("integrity", {"key": "drift:naoh_dose", "severity": "critical", "message": "m", "register": "naoh_dose"})
    assert len(m.poll(now=c.t)) == 1


def test_forecast_warning_needs_recent_write(env):
    c, log, m = env
    log.append("forecast_warning", {"var": "ph", "direction": "above", "minutes": 90, "message": "m"})
    m.poll()
    assert m.incidents == {}              # weather: the operator's job, not an incident
    dec(log, allowed=True, check="ok", new=150)
    c.t += 20 * 60
    log.append("forecast_warning", {"var": "ph", "direction": "above", "minutes": 60, "message": "m"})
    m.poll()
    assert len(m.incidents) == 1
    c.t += 61 * 60                        # long after the write: weather again
    log.append("forecast_warning", {"var": "chlorine_residual", "direction": "below", "minutes": 60, "message": "m"})
    m.poll()
    assert len(m.incidents) == 1


def test_three_unusual_writes_open_with_all_three(env):
    c, log, m = env
    ids = []
    for _ in range(2):
        ids.append(dec(log, allowed=True, check="unusual", source="Operator HMI", peer="10.0.0.5:5000")["id"])
        c.t += 300
    m.poll()
    assert m.incidents == {}
    ids.append(dec(log, allowed=True, check="unusual", source="Operator HMI", peer="10.0.0.5:5000")["id"])
    m.poll()
    inc = m.list()[0]
    assert set(ids) <= set(inc.entry_ids)


def test_auth_failures(env):
    c, log, m = env
    for _ in range(2):
        log.append("auth_failure", {"action": "permit"})
        c.t += 60
    m.poll()
    assert m.incidents == {}
    log.append("auth_failure", {"action": "permit"})
    m.poll()
    assert len(m.list()[0].entry_ids) == 3


def test_reopen_within_two_hours_not_after(env):
    c, log, m = env
    dec(log)
    m.poll(now=c.t + 31 * 60)
    m.finish(1, I.REPORTED, now=c.t + 32 * 60)
    c.t += 90 * 60
    dec(log)                               # same source, < 2 h after report: reopen
    m.poll()
    assert len(m.incidents) == 1 and m.get(1).state == I.REOPENED and m.get(1).reopened == 1
    m.poll(now=c.t + 31 * 60)
    m.finish(1, I.CLOSED, now=c.t + 31 * 60)
    c.t += 4 * 3600
    dec(log)
    m.poll()
    assert len(m.incidents) == 2           # too late: a new incident


def test_agent_entries_ignored(env):
    c, log, m = env
    log.append("agent_step", {"tool": "get_decisions", "allowed": False})
    log.append("agent_verdict", {"classification": "external_attack"})
    m.poll()
    assert m.incidents == {}


def test_one_running_and_six_per_hour(env):
    c, log, m = env
    for k in range(8):                     # 8 unrelated incidents
        dec(log, source=f"src{k}", peer=f"10.1.1.{k}:1", reg=f"r{k}")
    started = m.poll(now=c.t + 31 * 60)
    assert len(started) == 1               # only one at a time
    now = c.t + 31 * 60
    total = 1
    for _ in range(10):
        m.finish(started[0].id, I.REPORTED, now=now)
        now += 60
        started = m.tick(now)
        if not started:
            break
        total += len(started)
    assert total == 6                      # hourly cap
    later = m.tick(now + 3600)
    assert len(later) == 1                 # the window rolls


def test_queue_overflow_falls_back_with_one_alert():
    c = Clock()
    log = AuditLog(":memory:", clock=c)
    al = FakeAlerter()
    m = IncidentManager(log, clock=c, alerter=al)
    for k in range(14):
        dec(log, source=f"src{k}", peer=f"10.1.1.{k}:1", reg=f"r{k}")
    m.poll(now=c.t + 31 * 60)
    states = [i.state for i in m.list()]
    assert states.count(I.FAILED_FALLBACK) == 3          # 14 - 1 running - 10 queued
    assert states.count(I.INVESTIGATING) == 1 and states.count(I.READY) == 10
    m.tick(c.t + 32 * 60)
    assert len(al.alerts) == 1
    assert any(e["kind"] == "agent_fallback" for e in log.between(0))


def test_every_open_is_audited(env):
    c, log, m = env
    dec(log)
    m.poll()
    opens = [e for e in log.between(0) if e["kind"] == "agent_incident_open"]
    assert len(opens) == 1 and opens[0]["data"]["incident"] == 1


@pytest.mark.parametrize("attacker", ["unknown", "hmi"])
def test_attack_episodes_open_exactly_one_incident(monkeypatch, attacker):
    monkeypatch.setattr(ev, "ATTACKER", attacker)
    pol = load_policy(Tags.load())
    for seed in range(4):
        clock = ev.Clock()
        log = AuditLog(":memory:", clock=clock)
        r = ev.attack_episode(seed, True, pol, audit=log, clock=clock)
        m = IncidentManager(log, clock=clock)
        m.poll()
        assert len(m.incidents) == (1 if r["blocked"] else 0), (attacker, seed, r)


def test_clean_operator_episode_opens_nothing():
    pol = load_policy(Tags.load())
    for seed in range(4):
        clock = ev.Clock()
        log = AuditLog(":memory:", clock=clock)
        r = ev.operator_episode(seed, True, pol, audit=log, clock=clock)
        m = IncidentManager(log, clock=clock)
        m.poll()
        blocked = any(not w["allowed"] for w in r["writes"])
        assert (len(m.incidents) > 0) == blocked
