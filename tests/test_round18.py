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


def test_allow_once_ticket_lets_one_value_past_a_wrong_block_and_nothing_else():
    """Round 25: the twin is sometimes wrong. An operator can let ONE value on ONE setpoint through, once."""
    import pytest
    from aegis.alerts import Alerter
    from aegis.guard import Guard
    from aegis.plant import Plant
    from aegis.twin import Twin
    plant = Plant(noise=False)
    now = [1000.0]
    g = Guard(None, plant.snapshot, twin=Twin(), alerter=Alerter(None, throttle_s=0), clock=lambda: now[0])
    g.policy["limits"]["naoh_dose"].update(max_step=None, max_change_per_min=None)
    st = plant.snapshot()
    blocked = g.check("naoh_dose", 230, st, "Operator HMI", "10.0.0.5:1")
    assert not blocked.allowed and blocked.check == "predict"

    with pytest.raises(ValueError):
        g.allow_once("naoh_dose", 11100, "maria")                      # hard limits can't be ticketed
    g.allow_once("naoh_dose", 230, "maria", minutes=90)
    assert g.tickets["naoh_dose"]["until"] == now[0] + 30 * 60         # capped at 30 min
    assert any("allowed naoh_dose = 230 once" in i["title"] for i in g.alerter.incidents)

    assert not g.check("naoh_dose", 240, st, "Operator HMI", "10.0.0.5:1").allowed      # other value: no
    assert not g.check("naoh_dose", 230, st, "Unknown host 9.9.9.9", "9.9.9.9:1").allowed  # stranger: no
    assert g.check("naoh_dose", 230, st, "Operator HMI", "10.0.0.5:1", dry_run=True).allowed   # dry run: not used up
    d = g.check("naoh_dose", 230, st, "Operator HMI", "10.0.0.5:1")
    assert d.allowed and d.reason.startswith("ALLOWED ONCE by maria")
    assert not g.check("naoh_dose", 230, st, "Operator HMI", "10.0.0.5:1").allowed       # only once

    g.allow_once("naoh_dose", 230, "maria", minutes=5)
    now[0] += 6 * 60
    assert not g.check("naoh_dose", 230, st, "Operator HMI", "10.0.0.5:1").allowed       # expired
    assert "naoh_dose" not in g.tickets


def test_servers_start_under_uvloop():
    """Round 28: a fresh install on Linux/macOS gets uvloop with uvicorn; its Server objects don't take new
    attributes, and `srv.limiter = ...` crashed the dashboard at startup. Windows has no uvloop."""
    import pytest
    uvloop = pytest.importorskip("uvloop")
    from aegis import modbus

    async def go():
        async def handler(req, peer):
            return modbus.response_pdu(req, [7] * (req.count or 1))
        srv = await modbus.serve(handler, "127.0.0.1", 0, per_ip=2)
        port = srv.sockets[0].getsockname()[1]
        assert modbus.limiter_of(srv) is not None
        c = modbus.Client("127.0.0.1", port)
        assert await c.read_holding(0, 2) == [7, 7]
        await c.close(); srv.close()
    uvloop.run(go())
