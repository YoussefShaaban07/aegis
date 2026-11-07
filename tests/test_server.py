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
    assert s["guard_enabled"] is False and s["alerts"][0]["key"] == "guard_disabled"


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
