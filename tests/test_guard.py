import asyncio

import pytest
from pymodbus.client import AsyncModbusTcpClient

from aegis import modbus
from aegis.guard import Guard
from aegis.plant import HOLDING, Plant, to_raw


@pytest.fixture
def anyio_backend():
    return "asyncio"


async def start(plant_port=0, guard_port=0, enabled=True):
    plant = Plant()
    plc = await modbus.serve(plant.handle, "127.0.0.1", 0)
    plc_port = plc.sockets[0].getsockname()[1]
    up = await modbus.Client("127.0.0.1", plc_port).connect()
    guard = Guard(up, plant.snapshot, enabled=enabled)
    gsrv = await modbus.serve(guard.handle, "127.0.0.1", 0)
    gport = gsrv.sockets[0].getsockname()[1]
    return plant, guard, plc, gsrv, plc_port, gport


def test_codec_roundtrip():
    req = modbus.Request(7, 1, modbus.WRITE_MULTIPLE, 2, 2, [150, 100])
    raw = modbus.build_request(req)
    tid, unit = int.from_bytes(raw[0:2], "big"), raw[6]
    parsed = modbus.parse_request(tid, unit, raw[7:])
    assert parsed.values == [150, 100] and parsed.address == 2


def test_pymodbus_interop():
    """A standard third-party Modbus client can read/write our PLC."""
    async def run():
        plant, guard, plc, gsrv, plc_port, gport = await start()
        c = AsyncModbusTcpClient("127.0.0.1", port=plc_port)
        await c.connect()
        r = await c.read_holding_registers(HOLDING["naoh_dose"], count=1)
        assert r.registers == [100]
        r = await c.read_input_registers(0, count=5)
        assert len(r.registers) == 5
        await c.write_register(HOLDING["naoh_dose"], 120)
        assert plant.setpoint("naoh_dose") == 120
        c.close(); plc.close(); gsrv.close()
    asyncio.run(run())


def test_oldsmar_style_attack_blocked():
    async def run():
        plant, guard, plc, gsrv, _, gport = await start()
        attacker = await modbus.Client("127.0.0.1", gport, unit=9).connect()
        with pytest.raises(modbus.ModbusError) as e:
            await attacker.write(HOLDING["naoh_dose"], 11100)
        assert e.value.code == modbus.ILLEGAL_VALUE
        assert plant.setpoint("naoh_dose") == 100        # PLC untouched
        d = guard.log[0]
        assert not d.allowed and "Unknown device" in d.source and "outside safe range" in d.reason
        plc.close(); gsrv.close()
    asyncio.run(run())


def test_same_attack_without_guard_reaches_plc():
    async def run():
        plant, guard, plc, gsrv, _, gport = await start(enabled=False)
        attacker = await modbus.Client("127.0.0.1", gport, unit=9).connect()
        await attacker.write(HOLDING["naoh_dose"], 11100)
        assert plant.setpoint("naoh_dose") == 11100
        plc.close(); gsrv.close()
    asyncio.run(run())


def test_ai_copilot_bound_by_same_rules():
    async def run():
        plant, guard, plc, gsrv, _, gport = await start()
        ai = await modbus.Client("127.0.0.1", gport, unit=2).connect()
        await ai.write(HOLDING["chlorine_dose"], to_raw("chlorine_dose", 1.8))   # small, safe
        assert plant.setpoint("chlorine_dose") == 1.8
        with pytest.raises(modbus.ModbusError):
            await ai.write(HOLDING["chlorine_dose"], to_raw("chlorine_dose", 3.9))  # in range, too big a jump
        assert guard.log[0].source == "AI copilot" and guard.log[0].check == "step"
        plc.close(); gsrv.close()
    asyncio.run(run())


def test_multi_write_rejected_atomically():
    async def run():
        plant, guard, plc, gsrv, _, gport = await start()
        c = await modbus.Client("127.0.0.1", gport, unit=9).connect()
        with pytest.raises(modbus.ModbusError):   # chlorine ok, naoh evil -> nothing applied
            await c.write_many(HOLDING["chlorine_dose"], [to_raw("chlorine_dose", 1.6), 9000])
        assert plant.setpoint("chlorine_dose") == 1.5 and plant.setpoint("naoh_dose") == 100
        plc.close(); gsrv.close()
    asyncio.run(run())


def test_interlock():
    plant = Plant(); plant.state.tank_level = 93
    g = Guard(None, plant.snapshot)
    d = g.check("distribution_pump", 0, plant.snapshot(), "x", "p")
    assert not d.allowed and "interlock" in d.reason


def test_unknown_register_blocked():
    plant = Plant()
    d = Guard(None, plant.snapshot).check("register 7", 1, plant.snapshot(), "x", "p")
    assert not d.allowed and "allowlist" in d.reason


def test_physics_attack_raises_ph():
    plant = Plant()
    plant.set("naoh_dose", 11100)
    for _ in range(30):
        plant.step(1.0)
    assert plant.ph > 8.5 and "pH HIGH" in plant.alarms()


def test_physics_normal_stable():
    plant = Plant()
    for _ in range(120):
        plant.step(1.0)
    assert 7.1 < plant.ph < 7.6 and not plant.alarms()
