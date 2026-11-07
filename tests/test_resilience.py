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
