"""Interoperability with third-party Modbus software (pymodbus), on both sides:

    pymodbus client  ->  Aegis gateway (aegis.gateway.build)  ->  pymodbus server acting as the PLC

The "PLC" here is not our simulator, so this checks that the gateway works
with a Modbus implementation we didn't write. (Not a substitute for testing
on OpenPLC or real hardware; see README.)
"""
import asyncio
import warnings

from aegis import modbus
from aegis.audit import AuditLog
from aegis.gateway import build
from aegis.plant import TAGS

warnings.filterwarnings("ignore")


async def third_party_plc(port):
    from pymodbus.datastore import ModbusDeviceContext, ModbusSequentialDataBlock, ModbusServerContext
    from pymodbus.server import ModbusTcpServer
    # pymodbus 3.x data blocks are 1-based internally: block address 1 == Modbus register 0
    dev = ModbusDeviceContext(
        co=ModbusSequentialDataBlock(1, [1, 1] + [0] * 14),
        di=ModbusSequentialDataBlock(1, [0] * 16),
        hr=ModbusSequentialDataBlock(1, [150, 100, 500] + [0] * 13),
        # tank 60.0%, chlorine 0.92, pH 7.35, flow 500, raw pH 6.90, raw alk 77, turbidity 1.0, alarms 0
        ir=ModbusSequentialDataBlock(1, [600, 92, 735, 500, 690, 77, 10, 0] + [0] * 8))
    srv = ModbusTcpServer(ModbusServerContext(devices=dev, single=True), address=("127.0.0.1", port))
    task = asyncio.create_task(srv.serve_forever())
    await asyncio.sleep(0.3)
    return srv, task, dev


def test_gateway_between_pymodbus_client_and_pymodbus_plc():
    from pymodbus.client import AsyncModbusTcpClient

    async def run():
        plc_port = 16500 + (id(run) % 300)
        srv, task, dev = await third_party_plc(plc_port)
        lines = []
        guard, audit, twin = build("127.0.0.1", plc_port, audit=AuditLog(":memory:"), printer=lines.append)
        assert twin is not None                                    # all sensor tags present -> twin on
        gsrv = await modbus.serve(guard.handle, "127.0.0.1", 0)
        gport = gsrv.sockets[0].getsockname()[1]

        c = AsyncModbusTcpClient("127.0.0.1", port=gport)
        await c.connect()
        naoh = TAGS.holding["naoh_dose"].address
        assert not (await c.write_register(naoh, 120)).isError()               # normal trim: allowed
        assert (await c.write_register(naoh, 11100)).isError()                 # Oldsmar: blocked
        assert (await c.mask_write_register(address=naoh, and_mask=0, or_mask=9000)).isError()   # FC 22 bypass
        assert (await c.write_coil(TAGS.holding["distribution_pump"].address, False)).isError()  # needs permit
        r = await c.read_holding_registers(0, count=3)
        assert r.registers == [150, 120, 500]                                  # PLC holds only the safe write
        assert (await c.read_input_registers(0, count=8)).registers[2] == 735   # reads pass through
        c.close()

        assert sum(l.split()[1] == "BLOCK" for l in lines) == 3 and any("ALLOW" in l for l in lines)
        assert audit.verify()["ok"]
        gsrv.close(); await srv.shutdown(); task.cancel()
    asyncio.run(run())


def test_gateway_twin_uses_live_plc_sensors():
    async def run():
        plc_port = 16900 + (id(run) % 90)
        srv, task, dev = await third_party_plc(plc_port)
        guard, audit, twin = build("127.0.0.1", plc_port, audit=AuditLog(":memory:"), printer=lambda *_: None)
        guard.policy["limits"]["naoh_dose"].update(max_step=None, max_change_per_min=None)   # only the twin left
        d = await guard.dry_run("naoh_dose", 230, "Operator HMI")
        assert not d.allowed and d.check == "predict"     # computed from pH 7.35 / raw water read off the PLC
        assert (await guard.dry_run("naoh_dose", 110, "Operator HMI")).allowed
        await srv.shutdown(); task.cancel()
    asyncio.run(run())


def test_gateway_integrity_loop_spots_change_made_behind_its_back():
    """Someone changes the lye setpoint directly on the (third-party) PLC, not through Aegis."""
    from aegis.gateway import integrity_loop

    async def run():
        plc_port = 17100 + (id(run) % 90)
        srv, task, dev = await third_party_plc(plc_port)
        lines = []
        guard, audit, twin = build("127.0.0.1", plc_port, audit=AuditLog(":memory:"), printer=lines.append)
        loop = asyncio.create_task(integrity_loop(guard, twin, poll_s=0.1, printer=lines.append))
        await asyncio.sleep(0.4)                              # first polls: learns approved values
        direct = await modbus.Client("127.0.0.1", plc_port).connect()   # straight to the PLC, skipping Aegis
        await direct.write(TAGS.holding["naoh_dose"].address, 180)
        await direct.close()
        await asyncio.sleep(0.5)
        assert any("INTEGRITY CRITICAL" in l and "naoh_dose = 180" in l for l in lines), lines
        loop.cancel(); await srv.shutdown(); task.cancel()
    asyncio.run(run())
