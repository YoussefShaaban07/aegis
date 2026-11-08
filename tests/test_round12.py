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


# ---------------- round 14 ----------------
def test_twin_chemistry_for_other_alkalis_and_chlorine_only_plants():
    from aegis.config import load_process
    from aegis.process import ProcessModel, Raw
    sp = dict(intake_pump=1, distribution_pump=1, chlorine_dose=1.5, distribution_rate=500)

    def ph(alkali, dose):
        p = load_process(); p["alkali"] = alkali
        m = ProcessModel(p)
        return m.ph(m.steady(Raw(), {**sp, "naoh_dose": dose}))
    # same feed setpoint: lime (2 eq/mol, lighter per eq) raises pH a bit more than NaOH; soda ash adds
    # carbonate along with alkalinity, so it buffers and raises pH far less; bicarbonate barely at all
    assert ph("lime", 200) > ph("naoh", 200) > ph("soda_ash", 200) > ph("bicarbonate", 200)
    assert ph("soda_ash", 400) < 8.5 < ph("naoh", 400)
    # a chlorine-only plant has no alkali feed register at all: the twin still judges chlorine changes
    plant = Plant(noise=False)
    plant.set_scenario("storm", immediate=True)
    for _ in range(60):
        plant.step(1.0)
    st = plant.snapshot(); st.pop("naoh_dose")
    v = Twin().evaluate(st, "chlorine_dose", 0.8)
    assert not v.allowed and "chlorine" in v.reason


# ---------------- round 15 ----------------
def test_probing_source_is_locked_down_to_corrective_changes_only(tmp_path):
    from aegis.alerts import Alerter
    plant = Plant(noise=False)
    plant.set_scenario("bloom")
    for _ in range(40):
        plant.step(1.0)
    g = Guard(None, plant.snapshot, twin=Twin(), alerter=Alerter(None, throttle_s=0))
    src, peer = "Operator HMI", "10.0.0.5:5000"
    for i in range(5):                                    # 5 refusals: not yet
        assert not g.check("naoh_dose", 140 + i, plant.snapshot(), src, peer).allowed
    assert src not in g.lockdowns
    assert not g.check("naoh_dose", 146, plant.snapshot(), src, peer).allowed
    assert src in g.lockdowns and any(a["key"] == f"lockdown:{src}" for a in g.alerter.recent)
    # a small, otherwise-legal chlorine trim is now refused; cutting lye in a bloom (corrective) still works
    d = g.check("chlorine_dose", 1.6, plant.snapshot(), src, peer)
    assert not d.allowed and d.check == "lockdown"
    assert g.check("naoh_dose", 50, plant.snapshot(), src, peer).allowed
    # other sources are unaffected; a restart doesn't clear it; a person does
    assert g.check("chlorine_dose", 1.6, plant.snapshot(), "AI copilot", "h:2").check != "lockdown"
    g.save_state(tmp_path / "s.json")
    g2 = Guard(None, plant.snapshot, twin=Twin())
    g2.load_state(tmp_path / "s.json")
    assert src in g2.lockdowns
    assert g2.clear_lockdown(src, "maria (operator)") and src not in g2.lockdowns


def test_lockdown_does_not_trigger_in_monitor_mode_or_on_dry_runs():
    plant = Plant(noise=False)
    g = Guard(None, plant.snapshot, twin=Twin())
    for _ in range(10):
        g.check("naoh_dose", 11100, plant.snapshot(), "AI copilot", "h", dry_run=True)
    g.mode = "monitor"
    for _ in range(10):
        g.check("naoh_dose", 11100, plant.snapshot(), "Operator HMI", "h")
    assert g.lockdowns == {}


# ---------------- round 16 ----------------
def test_approval_needs_headroom_not_just_a_forecast_inside_the_limit():
    """Held-out episode 300078: chlorine cut to 0.69 mg/L dose, long-run residual ~0.24 against a 0.2 limit.
    The twin used to approve it; ordinary demand drift made the water unsafe 7 hours later."""
    plant = Plant(noise=False)
    g = Guard(None, plant.snapshot, twin=Twin())
    g.policy["limits"]["chlorine_dose"].update(max_step=None, max_change_per_min=None)
    d = g.check("chlorine_dose", 0.69, plant.snapshot(), "Operator HMI", "h:1", dry_run=True)
    assert not d.allowed and d.check == "predict"
    assert g.check("chlorine_dose", 1.3, plant.snapshot(), "Operator HMI", "h:1", dry_run=True).allowed
    g.policy["prediction"]["approval_margin"] = {}
    assert g.check("chlorine_dose", 0.69, plant.snapshot(), "Operator HMI", "h:1", dry_run=True).allowed   # old behaviour


# ---------------- round 17 ----------------
def test_one_host_cannot_take_every_connection_and_lock_out_the_hmi():
    import asyncio
    from aegis import modbus

    async def go():
        plant = Plant(noise=False)
        reserved = {"127.0.0.1"}                       # pretend the named HMI is this address
        srv = await modbus.serve(plant.handle, "127.0.0.1", 0, max_clients=4, per_ip=3, reserved=lambda: reserved)
        port = srv.sockets[0].getsockname()[1]
        lim = srv.limiter
        held = [await asyncio.open_connection("127.0.0.1", port) for _ in range(5)]
        await asyncio.sleep(0.05)
        assert lim.by_ip.get("127.0.0.1") == 3 and lim.refused == 2    # per-address cap
        reserved.clear()
        lim.total = 3                                                  # now the box is "full"
        extra = await asyncio.open_connection("127.0.0.1", port)
        await asyncio.sleep(0.05)
        assert lim.refused == 3
        for r, w in held + [extra]:
            w.close()
        srv.close()
    asyncio.run(go())


def test_cip_guard_limits_connections_per_address():
    from aegis.cip import CIPGuard
    g = Guard(None, Plant(noise=False).snapshot)
    p = CIPGuard(g, "127.0.0.1", 1)
    assert [p.limiter.admit(("10.0.0.9", i)) for i in range(3)] == ["10.0.0.9", "10.0.0.9", None]
    g.ip_sources = {"10.0.0.5": "Operator HMI"}
    for i in range(6):
        p.limiter.admit((f"10.1.0.{i}", 1))
    assert p.limiter.admit(("10.2.2.2", 1)) is None                     # full
    assert p.limiter.admit(("10.0.0.5", 1)) == "10.0.0.5"              # the named HMI still gets in
