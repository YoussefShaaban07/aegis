"""Chemistry, digital-twin predictions, and the attacks only the twin can stop."""
import asyncio

import pytest

from aegis import modbus
from aegis.attacks import patient_attack
from aegis.guard import Guard
from aegis.plant import Plant
from aegis.process import (alk_from_ph, ct_from_ph_alk, hocl_fraction, mgl_caco3_to_eq, ph_from_alk,
                           ProcessModel, Raw)
from aegis.twin import Twin


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


# ---------------- chemistry ----------------
@pytest.mark.parametrize("ph", [5.5, 6.5, 7.0, 7.8, 8.5, 9.5, 10.5])
def test_ph_alkalinity_inverse(ph):
    ct = 2e-3
    assert abs(ph_from_alk(alk_from_ph(ph, ct), ct) - ph) < 1e-6


def test_textbook_values():
    assert abs(hocl_fraction(7.54) - 0.5) < 1e-9
    assert hocl_fraction(9.0) < 0.04                      # lye overdose also guts disinfection
    # at pH = pK1, half the carbonate is HCO3-: alkalinity ~ CT/2
    ct = 1e-3
    assert abs(alk_from_ph(6.35, ct) / ct - 0.5) < 0.01
    # raw water 77 mg/L as CaCO3 at pH 6.9 -> CT a bit above alkalinity (some CO2 present)
    ct_raw = ct_from_ph_alk(6.9, mgl_caco3_to_eq(77))
    assert 1.2 < ct_raw / mgl_caco3_to_eq(77) < 1.4


def test_titration_curve_is_steep():
    m, sp = ProcessModel(), dict(intake_pump=1, distribution_pump=1, chlorine_dose=1.5, distribution_rate=500)
    ph = {d: m.ph(m.steady(Raw(), {**sp, "naoh_dose": d})) for d in (100, 150, 200)}
    assert 7.2 < ph[100] < 7.45
    assert (ph[200] - ph[150]) > 2 * (ph[150] - ph[100]) * 0.5    # the same +50 does more damage higher up
    assert ph[200] > 8.5


# ---------------- twin decisions ----------------
def snap(plant):
    return plant.snapshot()


def test_twin_blocks_change_that_passes_every_static_rule():
    plant, clk = Plant(noise=False), Clock()
    g = Guard(None, plant.snapshot, clock=clk, twin=Twin())
    d = g.check("naoh_dose", 150, snap(plant), "Unknown device (unit 79)", "10.0.0.9:5000")
    assert d.allowed            # 100 -> 150 is fine (pH ~7.8)
    g._commit(d); plant.set("naoh_dose", 150)
    for _ in range(120):
        plant.step(1.0)         # two simulated hours later
    clk.t += 61                 # the ramp window has passed: every static rule is satisfied
    d = g.check("naoh_dose", 200, snap(plant), "Unknown device (unit 79)", "10.0.0.9:5000")
    assert not d.allowed and d.check == "predict" and "pH" in d.reason
    assert d.forecast["with"][-1]["ph"] > 8.5 and d.forecast["without"][-1]["ph"] < 8.5


def test_algae_bloom_lye_increase_blocked_decrease_allowed():
    plant = Plant(noise=False)
    plant.set_scenario("bloom")
    for _ in range(40):
        plant.step(1.0)
    g = Guard(None, plant.snapshot, twin=Twin())
    up = g.check("naoh_dose", 140, snap(plant), "Operator HMI", "h:1")
    assert not up.allowed and up.check == "predict"
    down = g.check("naoh_dose", 50, snap(plant), "Operator HMI", "h:1")
    assert down.allowed and "corrective" in down.reason


def test_storm_chlorine_increase_is_corrective():
    plant = Plant(noise=False)
    plant.set_scenario("storm")
    for _ in range(90):
        plant.step(1.0)
    assert plant.chlorine < 0.75                    # demand jumped, residual sagging
    g = Guard(None, plant.snapshot, twin=Twin())
    nothing = g.twin.forecast(snap(plant))
    assert nothing[-1]["chlorine_residual"] < 0.2   # doing nothing -> no disinfectant left
    d = g.check("chlorine_dose", 2.0, snap(plant), "AI copilot", "h:1")
    assert d.allowed and "corrective" in d.reason


def test_twin_off_when_sensors_missing():
    g = Guard(None, dict, twin=Twin())
    d = g.check("naoh_dose", 120, {"naoh_dose": 100}, "x", "h:1")
    assert d.allowed and "unavailable" in d.reason


def test_combined_multi_register_write_evaluated_together():
    plant = Plant(noise=False)
    g = Guard(None, plant.snapshot, twin=Twin(), policy={
        "limits": {"naoh_dose": {"min": 0, "max": 250}, "chlorine_dose": {"min": 0, "max": 4}},
        "prediction": {"enabled": True, "horizon_min": 360}})
    # alone, 190 is borderline-unsafe; the twin must judge it with the other value in the same write
    d = g.check("naoh_dose", 200, snap(plant), "x", "h:1", together={"chlorine_dose": 1.5})
    assert not d.allowed


# ---------------- twin accuracy vs the (noisy, mismatched) simulator ----------------
def test_forecast_accuracy_against_simulator():
    """The plant has different 'true' parameters, drifting demand and sensor noise.
    Forecast pH and chlorine 30/60/120 minutes ahead after a lye step and compare."""
    plant = Plant(noise=True, seed=3)
    for _ in range(30):
        plant.step(1.0)
    plant.set("naoh_dose", 150)
    fc = Twin().forecast(plant.snapshot(), None, 120, every_min=30)
    actual = {}
    for minute in range(1, 121):
        plant.step(1.0)                      # speed 60: 1 real second = 1 simulated minute
        if minute in (30, 60, 120):
            actual[minute] = (plant.ph, plant.chlorine)
    for pt in fc:
        if pt["min"] in actual:
            ph, cl = actual[pt["min"]]
            assert abs(pt["ph"] - ph) < 0.15, (pt, ph)
            assert abs(pt["chlorine_residual"] - cl) < 0.15, (pt, cl)


# ---------------- end to end over Modbus ----------------
def test_patient_attacker_over_modbus():
    async def run():
        plant = Plant(noise=False)
        plc = await modbus.serve(plant.handle, "127.0.0.1", 0)
        clk = Clock()
        g = Guard(modbus.Client("127.0.0.1", plc.sockets[0].getsockname()[1]), plant.snapshot,
                  twin=Twin(), clock=clk)
        gsrv = await modbus.serve(g.handle, "127.0.0.1", 0)

        async def fast_forward_sleep(_):      # pretend 61 s and 2 simulated hours passed
            clk.t += 61
            for _ in range(120):
                plant.step(1.0)
        import aegis.attacks as A
        orig = A.asyncio.sleep
        A.asyncio.sleep = fast_forward_sleep
        try:
            out = await patient_attack(gsrv.sockets[0].getsockname()[1], lambda: plant.setpoint("naoh_dose"))
        finally:
            A.asyncio.sleep = orig
        assert out[0].endswith("accepted by PLC") and "rejected" in out[-1]
        assert plant.setpoint("naoh_dose") == 150 and g.log[0].check == "predict"
        plc.close(); gsrv.close()
    asyncio.run(run())


def test_corrective_change_may_exceed_step_limit_but_others_may_not():
    """Bloom: cutting lye 100 -> 0 is a 100 ppm step (limit 50) but fixes the trend: allowed.
    The same big step on a normal day isn't corrective: still blocked by the step rule."""
    plant = Plant(noise=False)
    plant.set_scenario("bloom")
    for _ in range(40):
        plant.step(1.0)
    g = Guard(None, plant.snapshot, twin=Twin())
    d = g.check("naoh_dose", 0, plant.snapshot(), "Operator HMI", "h:1")
    assert d.allowed and "CORRECTIVE OVERRIDE of the step limit" in d.reason
    normal = Plant(noise=False)
    g2 = Guard(None, normal.snapshot, twin=Twin())
    d2 = g2.check("naoh_dose", 0, normal.snapshot(), "Operator HMI", "h:1")
    assert not d2.allowed and d2.check == "step"


def test_permit_not_burned_by_rejected_write():
    plant = Plant(noise=False)
    g = Guard(None, plant.snapshot, twin=Twin())
    g.policy["limits"]["distribution_pump"]["permit_values"] = [0]
    plant.state.tank_level = 93                      # interlock will reject stopping distribution
    g.issue_permit("distribution_pump", 0)
    assert not g.check("distribution_pump", 0, plant.snapshot(), "Operator HMI", "h:1").allowed
    plant.state.tank_level = 60
    assert g.check("distribution_pump", 0, plant.snapshot(), "Operator HMI", "h:1").allowed   # permit still there


def test_blocked_operator_is_told_what_is_safe():
    plant = Plant(noise=False)
    g = Guard(None, plant.snapshot, twin=Twin())
    g.policy["limits"]["naoh_dose"].update(max_step=None, max_change_per_min=None)
    d = g.check("naoh_dose", 230, plant.snapshot(), "Operator HMI", "h:1")
    assert not d.allowed and "Largest change the twin accepts right now: naoh_dose = " in d.reason
    safe = float(d.reason.split("naoh_dose = ")[1].split()[0])
    assert 120 <= safe < 230
    assert g.check("naoh_dose", safe, plant.snapshot(), "Operator HMI", "h:1").allowed     # and it really is
    att = g.check("naoh_dose", 230, plant.snapshot(), "Unknown device (unit 66)", "9.9.9.9:1")
    assert "Largest change" not in att.reason                                             # attackers get no hint
