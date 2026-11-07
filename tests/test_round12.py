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


# ---------------- round 13 ----------------
def test_gateway_console_lets_a_named_operator_ack_and_release(tmp_path):
    from fastapi.testclient import TestClient
    from aegis.alerts import Alerter
    from aegis.auth import Auth
    from aegis.console import build_console
    plant = Plant(noise=False)
    g = Guard(None, plant.snapshot, twin=Twin(), alerter=Alerter(None, throttle_s=0))
    g.last_state = plant.snapshot()
    g.holds["distribution_rate"] = {"value": 500, "until": g.clock() + 3600, "by": "x", "reason": "test"}
    g.alerter.raise_alert("forecast:tank_level:below", "warning", "Twin forecast: clearwell low")
    auth = Auth(tmp_path / "users.json", demo=False)
    assert not auth.users                                         # no demo accounts on a real install
    auth.add("maria", "correct horse battery", "operator")
    c = TestClient(build_console(g, auth))
    assert c.get("/api/state").status_code == 401
    assert c.post("/api/login", json={"username": "engineer", "password": "engineer"},
                  headers={"X-Aegis": "1"}).status_code == 401
    assert c.post("/api/login", json={"username": "maria", "password": "correct horse battery"},
                  headers={"X-Aegis": "1"}).status_code == 200
    s = c.get("/api/state").json()
    assert s["plant"]["ph"] == g.last_state["ph"] and s["holds"][0]["register"] == "distribution_rate"
    iid = s["incidents"][0]["id"]
    assert c.post(f"/api/incidents/{iid}/ack").status_code == 403          # CSRF header required
    assert c.post(f"/api/incidents/{iid}/ack", headers={"X-Aegis": "1"}).json()["acked_by"].startswith("maria")
    assert c.post("/api/hold/release", json={"name": "distribution_rate"}, headers={"X-Aegis": "1"}).json()["ok"]
    assert g.holds == {}
    assert c.get("/").status_code == 200 and "Acknowledge" in c.get("/operator").text


def test_twin_gets_more_careful_when_the_plant_stops_matching_it():
    """Stronger lye delivered (true feed x1.6). The integrity monitor notices; until it's resolved the twin uses
    a wide ensemble, so a lye increase the nominal model would allow (and that truly reaches pH ~9.2) is refused."""
    import copy
    from aegis.integrity import IntegrityMonitor
    plant = Plant(noise=False)
    plant.model.params["naoh_feed_strength"] *= 1.6
    g = Guard(None, plant.snapshot, twin=Twin())
    g.sync_commanded(plant.snapshot())
    mon = IntegrityMonitor(Twin().model)
    for _ in range(150):
        plant.step(1.0)
        mon.update(plant.snapshot(), plant.sim_time, g.commanded)
    assert not mon.status["ok"]
    assert g.check("naoh_dose", 140, plant.snapshot(), "Operator HMI", "h:1", dry_run=True).allowed   # nominal: fooled
    g.distrust = True
    d = g.check("naoh_dose", 140, plant.snapshot(), "Operator HMI", "h:1", dry_run=True)
    assert not d.allowed and d.check == "predict"
    assert g.check("naoh_dose", 60, plant.snapshot(), "Operator HMI", "h:1", dry_run=True).allowed   # cutting is fine
    truth = copy.deepcopy(plant); truth.set("naoh_dose", 140)
    assert max((truth.step(1.0), truth.ph)[1] for _ in range(360)) > 8.5          # and 140 really was unsafe


def test_history_rotation_keeps_the_disk_bounded(tmp_path):
    import time as _t
    from aegis.gateway import rotate_history
    h = tmp_path / "history.csv"
    for i in range(5):
        h.write_text("t\n1\n")
        rotate_history(str(h), keep=3)
        _t.sleep(1.05)
    files = sorted(p.name for p in tmp_path.iterdir())
    assert len(files) == 3 and all(f.startswith("history-") for f in files)
