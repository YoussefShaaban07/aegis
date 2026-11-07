"""Slow-ramp + flood protection, config validation, audit chain, alerts, gateway reads."""
import asyncio
import copy
import sqlite3

import httpx
import pytest

from aegis import modbus
from aegis.alerts import Alerter
from aegis.audit import AuditLog
from aegis.config import PolicyError, Tags, load_policy, validate_policy
from aegis.guard import Guard, read_plc_state
from aegis.plant import HOLDING, Plant, to_raw

TAGS = Tags.load()


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def guard_for(plant, **kw):
    return Guard(None, plant.snapshot, **kw)


def apply(g, plant, reg, value, source="Unknown device (unit 9)"):
    d = g.check(reg, value, plant.snapshot(), source, "p")
    if d.allowed:
        g._commit(d)
        plant.set(reg, value)
    return d


# ---------------- slow ramp ----------------
def test_slow_ramp_blocked():
    """Each step is legal (<= max_step 0.5), but the attacker can't walk chlorine up fast."""
    plant, clk = Plant(), Clock()
    g = guard_for(plant, clock=clk)
    assert apply(g, plant, "chlorine_dose", 1.9).allowed      # +0.4
    clk.t += 5
    d = apply(g, plant, "chlorine_dose", 2.3)                 # +0.4 again: net +0.8 > 0.6/min
    assert not d.allowed and d.check == "ramp"
    assert plant.setpoint("chlorine_dose") == 1.9


def test_ramp_window_slides():
    plant, clk = Plant(), Clock()
    g = guard_for(plant, clock=clk)
    assert apply(g, plant, "chlorine_dose", 1.9).allowed
    clk.t += 61                                               # a minute later, budget resets
    assert apply(g, plant, "chlorine_dose", 2.3).allowed


def test_ramp_back_down_is_measured_from_window_start():
    plant, clk = Plant(), Clock()
    g = guard_for(plant, clock=clk)
    assert apply(g, plant, "naoh_dose", 150).allowed           # +50
    clk.t += 1
    assert apply(g, plant, "naoh_dose", 100).allowed           # back to 100: net 0 from baseline


# ---------------- flood ----------------
def test_flood_blocked():
    plant, clk = Plant(), Clock()
    g = guard_for(plant, clock=clk)
    src = "Unknown device (unit 66)"
    results = []
    for i in range(25):
        clk.t += 0.5
        results.append(apply(g, plant, "intake_pump", 1, source=src))
    assert results[0].allowed and results[-1].check == "flood"
    # a different source (the operator) is unaffected
    assert apply(g, plant, "intake_pump", 1, source="Operator HMI").allowed


# ---------------- config ----------------
def test_shipped_policy_valid():
    p = load_policy(TAGS)
    assert p["limits"]["naoh_dose"]["max"] == 250 and p["prediction"]["enabled"]


@pytest.mark.parametrize("mutate,msg", [
    (lambda p: p["limits"]["naoh_dose"].update(min=500), "above max"),
    (lambda p: p["limits"].update(bogus={"min": 0, "max": 1}), "not a writable tag"),
    (lambda p: p["limits"]["naoh_dose"].update(max_step=-5), "positive"),
    (lambda p: p.update(max_writes_per_min_per_source=0), "positive integer"),
])
def test_bad_policy_rejected(mutate, msg):
    p = copy.deepcopy(load_policy(TAGS))
    mutate(p)
    with pytest.raises(PolicyError, match=msg):
        validate_policy(p, TAGS)


def test_policy_change_takes_effect_and_is_audited():
    plant, audit = Plant(), AuditLog(":memory:")
    g = guard_for(plant, audit=audit)
    p = copy.deepcopy(g.policy)
    p["limits"]["naoh_dose"]["max"] = 120
    g.set_policy(p, by="test-engineer")
    assert not g.check("naoh_dose", 140, plant.snapshot(), "Operator HMI", "p").allowed
    assert audit.recent(1)[0]["kind"] == "policy_change"


def test_interlock_from_config():
    plant = Plant(); plant.state.tank_level = 93
    d = guard_for(plant).check("distribution_pump", 0, plant.snapshot(), "Operator HMI", "p")
    assert not d.allowed and d.check == "interlock"


# ---------------- audit ----------------
def test_audit_chain_detects_tampering(tmp_path):
    a = AuditLog(tmp_path / "a.db")
    for i in range(5):
        a.append("decision", {"i": i, "allowed": False})
    assert a.verify()["ok"]
    db = sqlite3.connect(tmp_path / "a.db")       # attacker edits a past record to hide a block
    db.execute("UPDATE audit SET data='{\"i\": 2, \"allowed\": true}' WHERE id=3"); db.commit()
    v = a.verify()
    assert not v["ok"] and v["broken_at"] == 3


def test_audit_detects_deletion(tmp_path):
    a = AuditLog(tmp_path / "a.db")
    for i in range(4):
        a.append("decision", {"i": i})
    db = sqlite3.connect(tmp_path / "a.db"); db.execute("DELETE FROM audit WHERE id=2"); db.commit()
    assert not a.verify()["ok"]


def test_audit_csv_export():
    a = AuditLog(":memory:")
    a.append("alert", {"m": "x"})
    assert "kind" in a.export_csv() and "alert" in a.export_csv()


def test_guard_writes_audit_entries():
    async def run():
        plant, audit = Plant(), AuditLog(":memory:")
        plc = await modbus.serve(plant.handle, "127.0.0.1", 0)
        up = await modbus.Client("127.0.0.1", plc.sockets[0].getsockname()[1]).connect()
        g = Guard(up, plant.snapshot, audit=audit)
        srv = await modbus.serve(g.handle, "127.0.0.1", 0)
        c = await modbus.Client("127.0.0.1", srv.sockets[0].getsockname()[1], unit=66).connect()
        with pytest.raises(modbus.ModbusError):
            await c.write(HOLDING["naoh_dose"], 11100)
        e = audit.recent(1, "decision")[0]["data"]
        assert e["allowed"] is False and e["check"] == "range"
        assert audit.verify()["ok"]
        plc.close(); srv.close()
    asyncio.run(run())


# ---------------- alerts ----------------
def test_alert_without_twilio_is_honest(monkeypatch):
    for k in ("TWILIO_ACCOUNT_SID", "TWILIO_AUTH_TOKEN", "TWILIO_FROM", "ALERT_TO"):
        monkeypatch.delenv(k, raising=False)
    al = Alerter(AuditLog(":memory:"))
    a = al.raise_alert("k", "critical", "lye blocked")
    assert "not configured" in a["delivery"]


def test_alert_throttled():
    al = Alerter()
    assert al.raise_alert("same", "warning", "x") is not None
    assert al.raise_alert("same", "warning", "x") is None


def test_twilio_sms_and_call(monkeypatch):
    for k, v in {"TWILIO_ACCOUNT_SID": "AC1", "TWILIO_AUTH_TOKEN": "t", "TWILIO_FROM": "+1601",
                 "ALERT_TO": "+1769"}.items():
        monkeypatch.setenv(k, v)
    sent = []

    def handler(req):
        sent.append((req.url.path, req.content.decode()))
        return httpx.Response(201, json={"sid": "x"})

    async def run():
        al = Alerter(transport=httpx.MockTransport(handler))
        a = al.raise_alert("k", "critical", "Blocked lye 11100 ppm")
        await asyncio.sleep(0.05)
        return a
    a = asyncio.run(run())
    paths = [p for p, _ in sent]
    assert any(p.endswith("/Messages.json") for p in paths) and any(p.endswith("/Calls.json") for p in paths)
    assert a["delivery"] == "SMS sent, call placed"


def test_guard_blocks_raise_alerts():
    plant, al = Plant(), Alerter()
    g = guard_for(plant, alerter=al)
    d = g.check("naoh_dose", 11100, plant.snapshot(), "Unknown device (unit 66)", "p")
    g._record(d)
    assert al.recent[0]["severity"] == "critical" and "11100" in al.recent[0]["message"]


def test_disabling_guard_alerts_and_audits():
    plant, audit = Plant(), AuditLog(":memory:")
    al = Alerter(audit)
    g = guard_for(plant, alerter=al, audit=audit)
    g.set_enabled(False, by="engineer")
    kinds = [e["kind"] for e in audit.recent(5)]
    assert al.recent[0]["key"] == "guard_mode" and "DISABLED" in al.recent[0]["message"]
    assert {"guard_mode", "alert"} <= set(kinds)


# ---------------- gateway mode ----------------
def test_read_plc_state_from_real_modbus():
    async def run():
        plant = Plant()
        plc = await modbus.serve(plant.handle, "127.0.0.1", 0)
        c = await modbus.Client("127.0.0.1", plc.sockets[0].getsockname()[1]).connect()
        s = await read_plc_state(c, TAGS)
        assert s["naoh_dose"] == 100 and s["chlorine_dose"] == 1.5 and abs(s["ph"] - 7.33) < 0.05
        assert s["intake_pump"] == 1 and s["raw_alkalinity"] == 77    # coils + input registers
        # guard with an async state reader (as used against a real/OpenPLC controller)
        g = Guard(c, lambda: read_plc_state(c, TAGS))
        d = await g.dry_run("naoh_dose", 11100, "AI copilot")
        assert not d.allowed
        plc.close()
    asyncio.run(run())
