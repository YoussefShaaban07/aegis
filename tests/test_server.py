"""End-to-end through the HTTP API (real Modbus servers started by the app)."""
import copy
import time

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("AEGIS_DB", str(tmp_path / "audit.db"))
    monkeypatch.setenv("AEGIS_USERS", str(tmp_path / "users.json"))
    monkeypatch.setenv("AEGIS_DEMO", "1")
    monkeypatch.setenv("AEGIS_PLC_PORT", "0")
    import importlib, json, shutil
    from aegis import config
    pol = tmp_path / "policy.json"; shutil.copy(config.POLICY_PATH, pol)
    from aegis import server
    importlib.reload(server)
    server.POLICY_PATH = pol
    server.PLC_PORT, server.GUARD_PORT = 15020 + (int(time.time() * 1000) % 300), 16020 + (int(time.time() * 1000) % 300)
    server.CIP_PLC_PORT, server.CIP_GUARD_PORT = 17020 + (int(time.time() * 1000) % 300), 18020 + (int(time.time() * 1000) % 300)
    with TestClient(server.app) as c:
        c.server = server
        c.headers["X-Aegis"] = "1"
        assert c.post("/api/login", json={"username": "engineer", "password": "engineer"}).status_code == 200
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


def test_ethernet_ip_attacks_blocked_and_logged(client):
    r = client.post("/api/attack/cip-lye").json()["result"]
    assert "REJECTED by Aegis" in r
    s = client.get("/api/state").json()
    assert s["plant"]["naoh_dose"] == 100 and s["log"][0]["check"] == "range" and "EtherNet/IP" in s["log"][0]["peer"]
    r = client.post("/api/attack/cip-program").json()["result"]
    assert "REJECTED" in r
    assert client.server.S["cip_plc"].mode == "RUN"
    assert "processor mode" in client.get("/api/state").json()["log"][0]["reason"]


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
    assert client.post("/api/permit", json={"name": "naoh_dose", "value": 5}).status_code == 400
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
    for _ in range(240):
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
    for m in range(360):
        if m == 60:     # through Aegis, like an operator (a direct PLC change would trip the integrity check)
            assert client.post("/api/operator/setpoint", json={"name": "naoh_dose", "value": 130}).json()["result"] == "accepted"
        plant.step(1.0)
    c = client.get("/api/calibrate").json()
    assert c["warnings"] == [] and c["after"]["ph_mae"] <= c["before"]["ph_mae"]
    assert client.post("/api/calibrate/apply", json={"pin": "2468"}).status_code == 200



# ---------------- authentication ----------------
def test_auth_required_and_roles(client):
    client.post("/api/logout")
    assert client.get("/api/state").status_code == 401                         # logged out
    assert client.post("/api/login", json={"username": "operator", "password": "operator"}).status_code == 200
    assert client.get("/api/state").status_code == 200
    assert client.post("/api/mode", json={"mode": "off", "pin": "2468"}).status_code == 403   # operator can't
    r = client.post("/api/operator/setpoint", json={"name": "naoh_dose", "value": 110})
    assert r.json()["result"] == "accepted"
    denied = [e for e in client.get("/api/audit").json()["entries"] if e["kind"] == "auth_denied"]
    assert denied and denied[0]["data"]["user"] == "operator"


def test_csrf_header_required(client):
    r = client.post("/api/operator/setpoint", json={"name": "naoh_dose", "value": 110}, headers={"X-Aegis": "0"})
    assert r.status_code == 403 and "CSRF" in r.json()["detail"]


def test_login_bruteforce_lockout(client):
    client.post("/api/logout")
    codes = [client.post("/api/login", json={"username": "engineer", "password": f"guess{i}"}).status_code
             for i in range(7)]
    assert codes[:5] == [401] * 5 and codes[5] == 429
    assert client.post("/api/login", json={"username": "engineer", "password": "engineer"}).status_code == 429


def test_actions_attributed_to_named_user(client):
    client.post("/api/mode", json={"mode": "monitor", "pin": "2468"})
    e = [x for x in client.get("/api/audit").json()["entries"] if x["kind"] == "guard_mode"][0]
    assert e["data"]["by"] == "engineer (engineer)"



def test_incident_grouping_and_ack_endpoint(client):
    for a in ("lye", "mask", "readwrite", "recon", "coil"):
        client.post(f"/api/attack/{a}")
    s = client.get("/api/state").json()
    inc = s["incidents"][0]
    assert inc["count"] >= 3 and s["notifications_sent"] == 1          # several attacks, one text
    r = client.post(f"/api/incidents/{inc['id']}/ack").json()
    assert r["acked_by"] == "engineer (engineer)"
    assert any(e["kind"] == "alert_ack" for e in client.get("/api/audit").json()["entries"])


def test_operator_view_served(client):
    r = client.get("/operator")
    assert r.status_code == 200 and "AEGIS · Operator" in r.text


def test_safe_hold_visible_and_release_needs_login(client):
    from aegis.server import S
    g = S["guard"]
    g.holds["naoh_dose"] = {"value": 100, "until": g.clock() + 600, "by": "Aegis safe-hold", "reason": "test"}
    s = client.get("/api/state").json()
    assert s["holds"][0]["register"] == "naoh_dose" and s["safe_hold"]["enabled"]
    assert client.post("/api/hold/release", json={"name": "naoh_dose"}).status_code == 200
    assert "naoh_dose" not in g.holds
    assert client.post("/api/hold/release", json={"name": "naoh_dose"}).status_code == 404


def test_keyless_demo_uses_a_labelled_scripted_model_and_aegis_still_blocks_it(client, monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    monkeypatch.delenv("AEGIS_LLM_KEY", raising=False)
    assert client.get("/api/state").json()["llm_scripted"] is True
    client.post("/api/attack/plant-work-order")
    r = client.post("/api/copilot", json={"message": "Any open work orders I should handle?"}).json()
    assert r["scripted"] and r["reply"].startswith("[SCRIPTED DEMO MODEL")
    assert [t["tool"] for t in r["trace"]] == ["read_work_orders", "propose_setpoint"]
    assert "BLOCKED" in r["trace"][1]["result"]["result"]
    assert client.get("/api/state").json()["plant"]["naoh_dose"] == 100
