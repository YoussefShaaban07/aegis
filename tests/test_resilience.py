"""Being inline must not make the plant fragile: errors, load, restarts, health."""
import asyncio
import subprocess
import sys
import time

import pytest

from aegis import modbus
from aegis.audit import AuditLog
from aegis.guard import Guard
from aegis.plant import TAGS, Plant
from aegis.twin import Twin

NAOH = TAGS.holding["naoh_dose"].address


def test_internal_error_rejects_that_write_and_keeps_serving():
    async def run():
        plant = Plant(noise=False)
        plc = await modbus.serve(plant.handle, "127.0.0.1", 0)
        calls = {"n": 0}

        def flaky_state():
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("sensor read glitch")
            return plant.snapshot()
        g = Guard(modbus.Client("127.0.0.1", plc.sockets[0].getsockname()[1]), flaky_state, twin=Twin())
        srv = await modbus.serve(g.handle, "127.0.0.1", 0)
        c = await modbus.Client("127.0.0.1", srv.sockets[0].getsockname()[1]).connect()
        with pytest.raises(modbus.ModbusError) as e:
            await c.write(NAOH, 105)                       # fails closed, not open
        assert e.value.code == modbus.DEVICE_FAILURE and plant.setpoint("naoh_dose") == 100
        await c.write(NAOH, 105)                           # next request works normally
        assert plant.setpoint("naoh_dose") == 105
        await c.close(); plc.close(); srv.close()
    asyncio.run(run())


def test_soak_many_concurrent_hmis():
    """20 clients hammer reads and safe writes concurrently for 3 s: no errors, no lost requests."""
    async def run():
        plant = Plant(noise=False)
        plc = await modbus.serve(plant.handle, "127.0.0.1", 0)
        g = Guard(modbus.Client("127.0.0.1", plc.sockets[0].getsockname()[1]), plant.snapshot)
        g.policy["max_writes_per_min_per_source"] = 10 ** 9
        g.policy["limits"]["naoh_dose"]["max_change_per_min"] = None
        g.policy["max_reads_per_sec_per_ip"] = None       # concurrency test, not a rate-limit test
        g.policy["max_reversals_per_10min"] = None        # (its 100<->105 writes would trip the cycling check)
        srv = await modbus.serve(g.handle, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        stop = time.time() + 3
        counts = {"ok": 0, "err": 0}

        async def hmi(i):
            c = await modbus.Client("127.0.0.1", port, unit=1).connect()
            k = 0
            while time.time() < stop:
                try:
                    if k % 5 == 0:
                        await c.write(NAOH, 100 + (k % 2) * 5)
                    else:
                        await c.read_input(0, 8)
                    counts["ok"] += 1
                except Exception:
                    counts["err"] += 1
                k += 1
            await c.close()
        await asyncio.gather(*(hmi(i) for i in range(20)))
        assert counts["err"] == 0 and counts["ok"] > 2000, counts
        plc.close(); srv.close()
    asyncio.run(run())


def test_supervisor_restarts_after_crash(monkeypatch):
    from aegis import supervisor
    calls = []
    monkeypatch.setattr(subprocess, "call", lambda cmd: calls.append(cmd) or 1)   # gateway "crashes" each time
    code = supervisor.run(["--plc-host", "x"], max_restarts=3, sleep=lambda s: None)
    assert code == 1 and len(calls) == 4 and calls[0][1:3] == ["-m", "aegis.gateway"]


def test_gateway_health_endpoint():
    from aegis.gateway import build, health_server

    async def run():
        plant = Plant(noise=False)
        plc = await modbus.serve(plant.handle, "127.0.0.1", 0)
        guard, audit, twin = build("127.0.0.1", plc.sockets[0].getsockname()[1], audit=AuditLog(":memory:"),
                                   printer=lambda *_: None)
        hs = await health_server(guard, audit, 0)
        port = hs.sockets[0].getsockname()[1]
        r, w = await asyncio.open_connection("127.0.0.1", port)
        w.write(b"GET /health HTTP/1.1\r\n\r\n"); await w.drain()
        body = (await r.read()).decode()
        assert "200 OK" in body and '"status": "ok"' in body
        plc.close()
        r, w = await asyncio.open_connection("127.0.0.1", port)
        guard.upstream.writer = None; guard.upstream.port = 1      # PLC gone
        w.write(b"GET /health HTTP/1.1\r\n\r\n"); await w.drain()
        assert "503" in (await r.read()).decode()
        hs.close()
    asyncio.run(run())


def test_slow_twin_falls_back_and_never_freezes_reads():
    """Emulate slow hardware: each twin model run takes 0.4 s. Reads from another HMI must keep flowing
    while a write is being decided, and the write must fall back to static checks within its budget."""
    from aegis.twin import Twin

    class SlowTwin(Twin):
        def forecast(self, *a, **k):
            time.sleep(0.4)
            return super().forecast(*a, **k)

    async def run():
        plant = Plant(noise=False)
        plc = await modbus.serve(plant.handle, "127.0.0.1", 0)
        g = Guard(modbus.Client("127.0.0.1", plc.sockets[0].getsockname()[1]), plant.snapshot, twin=SlowTwin())
        g.policy["prediction"]["budget_ms"] = 300
        srv = await modbus.serve(g.handle, "127.0.0.1", 0)
        port = srv.sockets[0].getsockname()[1]
        w = await modbus.Client("127.0.0.1", port, unit=1).connect()
        r = await modbus.Client("127.0.0.1", port, unit=1).connect()
        read_times = []

        async def reader():
            for _ in range(15):
                t = time.perf_counter(); await r.read_input(0, 8); read_times.append(time.perf_counter() - t)
                await asyncio.sleep(0.02)
        t0 = time.perf_counter()
        await asyncio.gather(w.write(NAOH, 110), reader())
        assert plant.setpoint("naoh_dose") == 110                      # static checks passed it
        assert "twin skipped" in g.log[0].reason and g.counts["twin_timeouts"] == 1
        assert time.perf_counter() - t0 < 2.0                          # budget respected (0.3 s + one model run)
        assert max(read_times) < 0.25                                   # reads never waited on the twin
        await w.close(); await r.close(); plc.close(); srv.close()
    asyncio.run(run())


def test_on_timeout_block_policy():
    from aegis.twin import Twin

    class SlowTwin(Twin):
        def forecast(self, *a, **k):
            time.sleep(0.3)
            return super().forecast(*a, **k)
    plant = Plant(noise=False)
    g = Guard(None, plant.snapshot, twin=SlowTwin())
    g.policy["prediction"].update(budget_ms=100, on_timeout="block")
    d = g.check("naoh_dose", 110, plant.snapshot(), "Operator HMI", "h:1")
    assert not d.allowed and "time budget" in d.reason



def test_restart_does_not_reset_ramp_window(tmp_path):
    """Crash-and-restart must not hand an attacker a fresh ramp window."""
    plant = Plant(noise=False)
    g = Guard(None, plant.snapshot)
    d = g.check("chlorine_dose", 1.9, plant.snapshot(), "x", "h:1"); g._commit(d); plant.set("chlorine_dose", 1.9)
    g.save_state(tmp_path / "s.json")
    g2 = Guard(None, plant.snapshot)                       # the restarted process
    assert g2.load_state(tmp_path / "s.json")
    d2 = g2.check("chlorine_dose", 2.3, plant.snapshot(), "x", "h:1")
    assert not d2.allowed and d2.check == "ramp"
    g3 = Guard(None, plant.snapshot)                       # without the saved state it would have passed
    assert g3.check("chlorine_dose", 2.3, plant.snapshot(), "x", "h:1").allowed
