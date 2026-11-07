"""End-to-end through the HTTP API (real Modbus servers started by the app)."""
import copy
import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_DB", str(tmp_path / "audit.db"))
    monkeypatch.setenv("AEGIS_PLC_PORT", "0")
    import importlib, json, shutil
    from aegis import config
    pol = tmp_path / "policy.json"; shutil.copy(config.POLICY_PATH, pol)
    from aegis import server
    importlib.reload(server)
    server.POLICY_PATH = pol
    server.PLC_PORT, server.GUARD_PORT = 15020 + (int(time.time() * 1000) % 300), 16020 + (int(time.time() * 1000) % 300)
    with TestClient(server.app) as c:
        c.server = server
        yield c


def test_pin_required(client):
    assert client.post("/api/guard", json={"enabled": False}).status_code == 403
    assert client.post("/api/guard", json={"enabled": False, "pin": "0000"}).status_code == 403
    assert client.post("/api/guard", json={"enabled": False, "pin": "2468"}).status_code == 200
    s = client.get("/api/state").json()
    assert s["guard_enabled"] is False and s["alerts"][0]["key"] == "guard_mode"


def test_lye_attack_blocked_and_logged(client):
    r = client.post("/api/attack/lye").json()
    assert "rejected" in r["result"]
    s = client.get("/api/state").json()
    assert s["plant"]["naoh_dose"] == 100 and s["log"][0]["check"] == "range"
    assert s["alerts"][0]["severity"] == "critical"
    a = client.get("/api/audit").json()
    assert a["verify"]["ok"] and any(e["kind"] == "decision" for e in a["entries"])
    assert "decision" in client.get("/api/audit/export.csv").text


def test_flood_endpoint(client):
    r = client.post("/api/attack/flood").json()["result"]
    assert "20 writes passed, 10 blocked" in r


def test_policy_edit_validation(client):
    pol = client.get("/api/state").json()["policy"]
    bad = copy.deepcopy(pol); bad["limits"]["naoh_dose"]["min"] = 999
    assert client.post("/api/policy", json={"policy": bad, "pin": "2468"}).status_code == 400
    good = copy.deepcopy(pol); good["limits"]["naoh_dose"]["max"] = 150
    assert client.post("/api/policy", json={"policy": good, "pin": "2468"}).status_code == 200
    assert client.post("/api/operator/setpoint", json={"name": "naoh_dose", "value": 160}).json()["result"] == "blocked"


def test_autonomy_setting(client):
    assert client.post("/api/settings", json={"autonomy": "direct"}).status_code == 403
    assert client.post("/api/settings", json={"autonomy": "direct", "pin": "2468"}).status_code == 200
    assert client.get("/api/state").json()["autonomy"] == "direct"


def test_mode_monitor_and_report(client):
    assert client.post("/api/mode", json={"mode": "monitor"}).status_code == 403
    assert client.post("/api/mode", json={"mode": "monitor", "pin": "2468"}).status_code == 200
    r = client.post("/api/attack/lye").json()["result"]
    assert "accepted" in r                                  # monitor mode lets it through...
    s = client.get("/api/state").json()
    assert s["log"][0]["would_block"] and s["counts"]["would_block"] == 1   # ...but records it
    client.post("/api/mode", json={"mode": "enforce", "pin": "2468"})
    for a in ("mask", "readwrite", "recon", "coil"):
        client.post(f"/api/attack/{a}")
    html = client.get("/api/report?minutes=5").text
    assert "Evidence integrity" in html and "T0888" in html and "VERIFIED" in html
    md = client.get("/api/report.md?minutes=5").text
    assert "| Unknown device (unit 67)" in md            # mask-write attacker appears by its label


def test_whatif_and_scenarios(client):
    r = client.post("/api/whatif", json={"name": "naoh_dose", "value": 220}).json()
    assert r["allowed"] is False and "pH" in r["reason"]
    assert client.post("/api/scenario/bloom").status_code == 200
    assert client.post("/api/scenario/volcano").status_code == 400
    s = client.get("/api/state").json()
    assert s["plant"]["scenario"] == "bloom" and s["forecast"] is not None


def test_learn_endpoint(client):
    r = client.get("/api/learn?simulated=true").json()
    assert "SIMULATED" in r["source"] and r["based_on"]["writes"] > 50
    assert any(c["field"] == "normal" for c in r["changes"])
    assert client.post("/api/policy", json={"policy": r["policy"], "pin": "2468"}).status_code == 200


def test_operator_change_blocked_by_twin(client):
    # 100 -> 150 is fine; jumping the setpoint so far that pH would leave 8.5 isn't, even within static limits
    pol = client.get("/api/state").json()["policy"]
    pol["limits"]["naoh_dose"].update(max_step=200, max_change_per_min=200)    # static rules wide open
    client.post("/api/policy", json={"policy": pol, "pin": "2468"})
    r = client.post("/api/operator/setpoint", json={"name": "naoh_dose", "value": 230}).json()
    assert r["result"] == "blocked" and "twin predicts" in r["reason"]
    assert client.post("/api/operator/setpoint", json={"name": "naoh_dose", "value": 130}).json()["result"] == "accepted"


def test_permit_flow(client):
    assert "rejected" in client.post("/api/attack/coil").json()["result"]
    r = client.post("/api/operator/setpoint", json={"name": "distribution_pump", "value": 0}).json()
    assert r["result"] == "blocked" and "permit" in r["reason"]
    assert client.post("/api/permit", json={"name": "distribution_pump", "value": 0}).status_code == 403
    assert client.post("/api/permit", json={"name": "naoh_dose", "value": 5, "pin": "2468"}).status_code == 400
    assert client.post("/api/permit", json={"name": "distribution_pump", "value": 0, "pin": "2468"}).status_code == 200
    r = client.post("/api/operator/setpoint", json={"name": "distribution_pump", "value": 0}).json()
    assert r["result"] == "accepted"


def test_compromise_grab_and_calibrate_endpoints(client):
    srv = client.server
    plant = srv.S["plant"]
    for _ in range(40):
        plant.step(1.0)
    r = client.post("/api/attack/plc-compromise", json={"freeze_sensors": True}).json()
    assert "No command passed through Aegis" in r["result"]
    for _ in range(90):
        plant.step(1.0)
    s = client.get("/api/state").json()
    assert s["plant"]["naoh_dose"] == 100 and s["truth"]["naoh_dose_actual"] == 200   # PLC hides it
    t = s["truth"]
    g = client.post("/api/grab", json={"ph": t["ph"], "chlorine": t["chlorine_residual"]}).json()
    assert g["ok"] is False                                                        # lab sample exposes the lie
    for _ in range(5):
        srv.S["integrity"].update(plant.snapshot(), plant.sim_time, srv.S["guard"].commanded)
    c = client.get("/api/calibrate").json()
    assert c["warnings"]                                   # integrity alarm active: don't learn the attack
    assert client.post("/api/calibrate/apply", json={}).status_code == 403
    r = client.post("/api/calibrate/apply", json={"pin": "2468"})
    assert r.status_code == 409 and "not applied" in r.json()["detail"]


def test_calibration_applies_on_clean_history(client):
    plant = client.server.S["plant"]
    for m in range(240):
        if m == 60:
            plant.set("naoh_dose", 130)
        plant.step(1.0)
    c = client.get("/api/calibrate").json()
    assert c["warnings"] == [] and c["after"]["ph_mae"] <= c["before"]["ph_mae"]
    assert client.post("/api/calibrate/apply", json={"pin": "2468"}).status_code == 200
