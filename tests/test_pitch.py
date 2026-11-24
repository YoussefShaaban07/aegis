"""Every guided-demo step, run through the HTTP API the way the dashboard runs it, must reach its point.

The expo failure (handoff section 9): a pitch step waited on wall-clock time while a slow host ran the
simulation, and the presenter was left watching a counter. Steps now fast-forward with /api/sim/advance,
so they finish the same way on any host; this test fails if any step stops reaching its point.
"""
import time

from test_server import client  # noqa: F401  (fixture: demo server, signed in as engineer)

PIN = "2468"


def state(c):
    return c.get("/api/state").json()


def advance_until(c, cond, max_min, chunk=5):
    m = 0
    while m < max_min:
        if cond(state(c)):
            return m
        r = c.post("/api/sim/advance", json={"minutes": chunk})
        assert r.status_code == 200, r.text
        m += chunk
    assert cond(state(c)), f"not reached after {max_min} simulated minutes"
    return m


def test_advance_is_exact_and_bounded(client):     # noqa: F811
    client.post("/api/reset")
    t0 = state(client)["sim_t"]
    r = client.post("/api/sim/advance", json={"minutes": 30}).json()
    assert 30 * 60 <= r["sim_t"] - t0 < 31 * 60          # 30 simulated minutes (+ any background tick)
    assert client.post("/api/sim/advance", json={"minutes": 0}).status_code == 422
    assert client.post("/api/sim/advance", json={"minutes": 361}).status_code == 422


def test_pitch_step_1_oldsmar_without_aegis(client):     # noqa: F811
    client.post("/api/reset")
    assert client.post("/api/mode", json={"mode": "off", "pin": PIN}).status_code == 200
    client.post("/api/attack/lye")
    t = time.time()
    mins = advance_until(client, lambda s: s["plant"]["ph"] > 8.5, 180)
    assert mins <= 180 and time.time() - t < 20


def test_pitch_step_2_blocked_with_aegis(client):     # noqa: F811
    client.post("/api/reset")
    client.post("/api/mode", json={"mode": "enforce", "pin": PIN})
    a = client.post("/api/attack/lye").json()
    b = client.post("/api/attack/mask").json()
    assert "rejected" in a["result"] and "rejected" in b["result"], (a, b)
    snap = client.get("/api/state").json()["plant"]
    assert snap.get("naoh_dose", snap.get("setpoints", {}).get("naoh_dose", 0)) < 300, snap


def test_pitch_step_3_twin_blocks_routine_change_in_bloom(client):     # noqa: F811
    client.post("/api/reset")
    client.post("/api/scenario/bloom")
    advance_until(client, lambda s: len(s.get("forewarn") or []) > 0, 240)
    a = client.post("/api/operator/setpoint", json={"name": "naoh_dose", "value": 150}).json()
    b = client.post("/api/operator/setpoint", json={"name": "naoh_dose", "value": 0}).json()
    assert a["result"] == "blocked", a
    assert b["result"] != "blocked", b


def test_pitch_step_4_ai_copilot_poisoned_work_order(client):     # noqa: F811
    client.post("/api/reset")
    client.post("/api/mode", json={"mode": "enforce", "pin": PIN})
    client.post("/api/attack/plant-work-order")
    r = client.post("/api/copilot", json={"message": "Any open work orders I should handle?"})
    assert r.status_code == 200
    props = client.get("/api/state").json().get("proposals") or []
    assert not any(p.get("status") == "applied" and p.get("name") == "naoh_dose" and p.get("value", 0) > 250
                   for p in props)


def test_full_tour_step_lying_controller(client):     # noqa: F811
    client.post("/api/reset")
    client.post("/api/attack/plc-compromise", json={"freeze_sensors": False})
    advance_until(client, lambda s: not s["integrity"]["ok"], 360, chunk=10)
