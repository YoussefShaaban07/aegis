"""Judge round 12: attacks on Aegis's own judgement (slowing the twin, poisoning calibration, fake lab values)."""
from aegis.guard import Guard
from aegis.plant import Plant
from aegis.twin import Twin, Verdict


def slow_guard(plant):
    g = Guard(None, plant.snapshot, twin=Twin())
    g._twin_eval = lambda *a, **k: Verdict(True, "prediction skipped: time budget exceeded", timed_out=True)
    return g


def test_twin_timeout_does_not_downgrade_the_guard_for_unnamed_writers():
    plant = Plant(noise=False)
    g = slow_guard(plant)
    d = g.check("naoh_dose", 140, plant.snapshot(), "Unknown host 9.9.9.9", "9.9.9.9:1")
    assert not d.allowed and d.check == "predict" and "time budget" in d.reason
    op = g.check("naoh_dose", 140, plant.snapshot(), "Operator HMI", "10.0.0.5:5000")
    assert op.allowed and "twin skipped" in op.reason          # named operator: static checks, alerted
    assert g.counts["twin_timeouts"] == 2


def test_calibration_cannot_be_walked_away_from_the_commissioned_values():
    """Each step under the 25% single-calibration limit, but the total drift is caught."""
    from aegis.calibrate import calibration_warnings
    base = {"naoh_feed_strength": 1.0}
    cur = dict(base)
    accepted = 0
    for _ in range(5):
        new = {"naoh_feed_strength": round(cur["naoh_feed_strength"] * 1.2, 4)}
        w = calibration_warnings(cur, new, True, base)
        if w:
            assert "commissioned" in w[0]
            break
        cur, accepted = new, accepted + 1
    assert accepted == 1                         # 1.0 -> 1.2 ok; 1.2 -> 1.44 is +44% from commissioning
    assert calibration_warnings({"naoh_feed_strength": 1.0}, {"naoh_feed_strength": 1.3}, True, base)   # one big jump
    assert "Integrity" in calibration_warnings(base, base, False, base)[0]


def test_fake_lab_alkalinity_cannot_blind_the_twin():
    from aegis.alerts import Alerter
    from aegis.labinputs import LabInputs
    plant = Plant(noise=False)
    for _ in range(60):
        plant.step(1.0)
    twin = Twin()
    st = plant.snapshot(); st.pop("raw_alkalinity")             # this plant titrates alkalinity by hand
    # why it matters: with a made-up high alkalinity the twin would wave through a caustic lye dose
    assert twin.evaluate({**st, "raw_alkalinity": 300}, "naoh_dose", 200).allowed
    assert not twin.evaluate({**st, "raw_alkalinity": 77}, "naoh_dose", 200).allowed
    clk = [0.0]
    al = Alerter(None, throttle_s=0, clock=lambda: clk[0])
    lab = LabInputs({"raw_alkalinity": {"max_age_h": 36}}, alerter=al, clock=lambda: clk[0])
    lab.enter("raw_alkalinity", 300, by="night shift")
    assert lab.fill(st, twin.model)["raw_alkalinity"] == 300   # plant not known to be steady yet: used for now
    for m in range(100):                                       # 100 steady minutes of polling
        clk[0] += 60
        lab.fill(st, twin.model)
    out = lab.fill(st, twin.model)
    assert "raw_alkalinity" not in out and al.recent[0]["key"] == "lab_implausible:raw_alkalinity"
    lab.enter("raw_alkalinity", 78, by="day shift")              # the real titration: used
    assert lab.fill(st, twin.model)["raw_alkalinity"] == 78
    lab.enter("raw_alkalinity", 300, by="engineer", confirm=True)  # an engineer can override, on the record
    assert lab.fill(st, twin.model)["raw_alkalinity"] == 300


def test_big_unverified_lab_jump_waits_until_it_can_be_checked():
    from aegis.labinputs import LabInputs
    clk = [0.0]
    lab = LabInputs({"raw_alkalinity": {}}, clock=lambda: clk[0])
    lab.enter("raw_alkalinity", 77, by="day shift")
    clk[0] += 3600
    lab.enter("raw_alkalinity", 300, by="night shift")       # not steady yet, can't be judged: keep the old one
    plant = Plant(noise=False)
    st = plant.snapshot(); st.pop("raw_alkalinity")
    assert lab.fill(st, Twin().model)["raw_alkalinity"] == 77
