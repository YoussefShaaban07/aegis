"""Judge round 18: the expo itself (long unattended booth runs)."""
import asyncio
from aegis import proposals as P


class FakeDecision:
    def __init__(self, allowed):
        self.allowed, self.old, self.reason, self.check, self.techniques, self.forecast = allowed, 100, "x", "range", [], None


class FakeGuard:
    class tags:
        class _T: label, unit = "Lye", "ppm"
        holding = {"naoh_dose": _T()}

    def __init__(self): self.n = 0

    async def dry_run(self, name, value, source):
        self.n += 1
        return FakeDecision(self.n <= 3)       # the first three stay pending, the rest are blocked


def test_proposals_are_bounded_but_pending_ones_are_never_dropped():
    props = P.Proposals(FakeGuard(), 0)
    async def go():
        for i in range(P.MAX_KEPT + 400):
            await props.propose("naoh_dose", 9000)
    asyncio.run(go())
    assert len(props.items) == P.MAX_KEPT + 3
    assert sum(p["status"] == "pending" for p in props.items) == 3
    assert props.items[0]["id"] == P.MAX_KEPT + 400          # newest first


def test_a_locked_down_machine_cannot_unlock_itself_with_a_stolen_password(tmp_path):
    """Round 19: malware on the HMI PC keylogs the operator's password, gets locked down, then signs in to the
    console from the same PC to clear it. Refused; the same operator on another device can clear it."""
    import inspect
    from fastapi.testclient import TestClient
    from aegis.alerts import Alerter
    from aegis.auth import Auth
    from aegis.console import build_console
    from aegis.guard import Guard
    from aegis.plant import Plant
    from aegis.twin import Twin
    plant = Plant(noise=False)
    g = Guard(None, plant.snapshot, twin=Twin(), alerter=Alerter(None, throttle_s=0),
              ip_sources={"10.0.0.5": "Operator HMI"})
    g.last_state = plant.snapshot()
    for _ in range(6):
        assert not g.check("naoh_dose", 11100, plant.snapshot(), "Operator HMI", "10.0.0.5:5000").allowed
    assert "Operator HMI" in g.lockdowns and "10.0.0.5" in g.locked_ips()
    auth = Auth(tmp_path / "users.json", demo=False)
    auth.add("maria", "correct horse battery", "operator")
    app = build_console(g, auth)
    assert "client" in inspect.signature(TestClient).parameters

    def signed_in(ip):
        c = TestClient(app, client=(ip, 50000))
        assert c.post("/api/login", json={"username": "maria", "password": "correct horse battery"},
                      headers={"X-Aegis": "1"}).status_code == 200
        return c
    hmi = signed_in("10.0.0.5")
    r = hmi.post("/api/lockdown/clear", json={"source": "Operator HMI"}, headers={"X-Aegis": "1"})
    assert r.status_code == 403 and "locked down" in r.json()["detail"]
    assert "Operator HMI" in g.lockdowns
    phone = signed_in("10.0.9.20")
    assert phone.post("/api/lockdown/clear", json={"source": "Operator HMI"}, headers={"X-Aegis": "1"}).json()["ok"]
    assert g.lockdowns == {} and g.locked_ips() == set()
