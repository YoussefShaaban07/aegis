"""Catching a PLC that lies: setpoint drift, physics shadow, lab grab samples.
Also: no false alarms during normal operation, operator changes and weather."""
from aegis.audit import AuditLog
from aegis.integrity import IntegrityMonitor
from aegis.plant import Plant
from aegis.process import ProcessModel


def run(plant, mon, minutes, commanded, every=1, on_minute=None):
    for m in range(minutes):
        plant.step(1.0)                         # 1 simulated minute
        if on_minute:
            on_minute(m)
        if m % every == 0:
            mon.update(plant.snapshot(), plant.sim_time, commanded)


def fresh(seed=5):
    plant = Plant(noise=True, seed=seed)
    for _ in range(10):
        plant.step(1.0)
    mon = IntegrityMonitor(ProcessModel(), audit=AuditLog(":memory:"))
    commanded = dict(plant.setpoints())
    mon.update(plant.snapshot(), plant.sim_time, commanded)
    return plant, mon, commanded


def test_no_false_alarms_normal_day_with_operator_changes_and_weather():
    plant, mon, cmd = fresh()

    def operator(m):
        if m == 30:
            plant.set("naoh_dose", 140); cmd["naoh_dose"] = 140       # approved by the guard
        if m == 90:
            plant.set_scenario("storm")
        if m == 120:
            plant.set("chlorine_dose", 2.5); cmd["chlorine_dose"] = 2.5
        if m == 200:
            plant.set_scenario("bloom")
        if m == 230:
            plant.set("naoh_dose", 20); cmd["naoh_dose"] = 20
    run(plant, mon, 8 * 60, cmd, on_minute=operator)
    assert list(mon.events) == [], mon.events
    assert abs(mon.status["ph_err"]) < 0.3


def test_compromised_plc_hidden_setpoint_caught_by_physics():
    plant, mon, cmd = fresh()
    run(plant, mon, 30, cmd)
    plant.compromise_plc({"naoh_dose": 200})      # registers still say 100
    assert plant.snapshot()["naoh_dose"] == 100
    caught = {}

    def watch(m):
        if mon.events and "at" not in caught:
            caught["at"] = m
    run(plant, mon, 120, cmd, on_minute=watch)
    assert "at" in caught and caught["at"] < 100, caught     # ~80 min of plant time (baffled clearwell)
    ev = mon.events[0]
    assert ev["severity"] == "critical" and "chemistry predicts" in ev["message"]
    assert plant.truth()["ph"] > 8.0                          # the real water really was drifting


def test_visible_local_setpoint_change_caught_immediately():
    plant, mon, cmd = fresh()
    plant.set("naoh_dose", 180)                     # someone at the panel (or malware), not via Aegis
    mon.update(plant.snapshot(), plant.sim_time, cmd)
    assert mon.events and "without going through Aegis" in mon.events[0]["message"]


def test_full_replay_lie_needs_a_grab_sample():
    """Honest limit: dosing changed + setpoint hidden + sensors frozen -> physics can't see it."""
    plant, mon, cmd = fresh()
    plant.compromise_plc({"naoh_dose": 220}, freeze_sensors=True)
    run(plant, mon, 120, cmd)
    assert not any(e["key"].startswith("physics") for e in mon.events)   # consistent lie: invisible to physics
    t = plant.truth()
    res = mon.grab_sample(plant.snapshot(), ph=t["ph"], chlorine=t["chlorine_residual"])
    assert not res["ok"] and mon.events[0]["key"].startswith("grab")


def test_grab_sample_agrees_when_honest():
    plant, mon, cmd = fresh()
    run(plant, mon, 20, cmd)
    t = plant.truth()
    assert mon.grab_sample(plant.snapshot(), ph=t["ph"] + 0.05, chlorine=t["chlorine_residual"])["ok"]


def test_grab_sample_catches_replay_early():
    """An hour into a replay attack (dose still travelling through the baffles), the lab sample disagrees."""
    plant, mon, cmd = fresh()
    plant.compromise_plc({"naoh_dose": 220}, freeze_sensors=True)
    run(plant, mon, 60, cmd)
    t = plant.truth()
    assert t["ph"] - plant.snapshot()["ph"] > 0.2
    assert not mon.grab_sample(plant.snapshot(), ph=t["ph"])["ok"]
