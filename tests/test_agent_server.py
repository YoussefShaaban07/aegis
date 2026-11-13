"""Sentinel step 9: end to end through the HTTP API with the real guard, PLC simulator and copilot."""
import time

import pytest

from test_server import client  # noqa: F401  (fixture)


@pytest.fixture(autouse=True)
def fast_windows(monkeypatch):
    monkeypatch.setenv("AEGIS_AGENT_QUIET_S", "1")


def wait_for(client, pred, timeout=25):
    t0 = time.time()
    while time.time() - t0 < timeout:
        r = client.get("/api/agent/incidents").json()
        hit = [i for i in r["incidents"] if pred(i)]
        if hit:
            return hit[0], r
        time.sleep(0.5)
    raise AssertionError(f"timed out; last: {r}")


@pytest.mark.parametrize("attack", ["lye", "recon", "flood"])
def test_demo_attack_is_investigated(client, attack):     # noqa: F811
    client.post(f"/api/attack/{attack}")
    inc, listing = wait_for(client, lambda i: i["classification"])
    assert listing["enabled"] and listing["mode"] == "llm" and listing["model"] == "scripted-stand-in"
    assert inc["classification"] == "external_attack", inc
    assert inc["validity"] == 1.0 and inc["severity"] == "HIGH"
    full = client.get(f"/api/agent/incidents/{inc['id']}").json()["result"]
    assert full["tool_calls"] >= 1 and full["validation"]["failed"] == 0
    html = client.get(f"/api/agent/incidents/{inc['id']}/report").text
    assert "Sentinel incident report" in html and "/api/audit/entry/" in html
    md = client.get(f"/api/agent/incidents/{inc['id']}/report?format=md").text
    cite = int(md.split("[#")[1].split("]")[0])
    e = client.get(f"/api/audit/entry/{cite}").json()
    assert e["verified"] and e["exists"]
    kinds = {x["kind"] for x in client.get("/api/audit").json()["entries"]}
    assert {"agent_incident_open", "agent_step", "agent_verdict", "agent_report"} <= kinds


def test_work_order_injection_is_ai_manipulation(client):     # noqa: F811
    client.post("/api/attack/plant-work-order")
    r = client.post("/api/copilot", json={"message": "Any open work orders I should handle?"})
    assert r.status_code == 200
    inc, _ = wait_for(client, lambda i: i["classification"])
    assert inc["classification"] == "ai_manipulation", inc
    full = client.get(f"/api/agent/incidents/{inc['id']}").json()["result"]
    assert not [s for s in full["recovery"]["steps"] if s["register"] == "naoh_dose" and s["value"] > 150]


def test_settings_and_rerun_need_engineer(client):     # noqa: F811
    assert client.post("/api/agent/settings", json={"mode": "deterministic"}).json()["mode"] == "deterministic"
    client.post("/api/attack/lye")
    inc, listing = wait_for(client, lambda i: i["classification"])
    assert listing["mode"] == "deterministic"
    assert client.post(f"/api/agent/incidents/{inc['id']}/investigate").status_code == 200
    client.post("/api/logout")
    assert client.post("/api/login", json={"username": "operator", "password": "operator"}).status_code == 200
    assert client.post("/api/agent/settings", json={"enabled": False}).status_code == 403
    assert client.post(f"/api/agent/incidents/{inc['id']}/investigate").status_code == 403
    assert client.get("/api/agent/incidents").status_code == 200
