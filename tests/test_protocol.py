"""Protocol-level hardening: every write function code, bypass attempts,
malformed frames, connection abuse, PLC outages, monitor mode."""
import asyncio
import random
import struct

import pytest

from aegis import modbus
from aegis.alerts import Alerter
from aegis.attacks import (coil_attack, flood_attack, lye_attack, mask_attack, readwrite_attack,
                           recon_attack)
from aegis.audit import AuditLog
from aegis.guard import Guard
from aegis.plant import TAGS, Plant
from aegis.twin import Twin

NAOH = TAGS.holding["naoh_dose"].address
CL = TAGS.holding["chlorine_dose"].address


async def rig(mode="enforce", twin=True):
    plant = Plant(noise=False)
    plc = await modbus.serve(plant.handle, "127.0.0.1", 0)
    pport = plc.sockets[0].getsockname()[1]
    audit = AuditLog(":memory:")
    alerter = Alerter(audit)
    guard = Guard(modbus.Client("127.0.0.1", pport), plant.snapshot, audit=audit, alerter=alerter,
                  twin=Twin() if twin else None, mode=mode)
    gsrv = await modbus.serve(guard.handle, "127.0.0.1", 0)
    return plant, guard, plc, gsrv, gsrv.sockets[0].getsockname()[1], pport


def close(*servers):
    for s in servers:
        s.close()


# ---------------- codec ----------------
def test_parser_never_crashes_on_garbage():
    rng = random.Random(1)
    for _ in range(50_000):
        pdu = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 40)))
        try:
            modbus.parse_request(1, 1, pdu)
        except modbus.ModbusError:
            pass


def test_mask_write_math_matches_spec():
    # example from the Modbus Application Protocol spec v1.1b3, section 6.16
    assert modbus.mask_result(0x12, 0xF2, 0x25) == 0x17


def test_bits_roundtrip():
    bits = [1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 1]
    assert modbus.unpack_bits(modbus.pack_bits(bits), len(bits)) == bits


# ---------------- bypass attempts ----------------
def test_mask_write_bypass_blocked():
    async def run():
        plant, guard, plc, gsrv, gport, _ = await rig()
        r = await mask_attack(gport, 9000)
        assert "rejected" in r and plant.setpoint("naoh_dose") == 100
        assert guard.log[0].fc == 22 and guard.log[0].check == "range"
        close(plc, gsrv)
    asyncio.run(run())


def test_mask_write_legit_change_allowed():
    async def run():
        plant, guard, plc, gsrv, gport, _ = await rig()
        c = await modbus.Client("127.0.0.1", gport).connect()
        await c.mask_write(NAOH, 0x0000, 110)      # set exactly 110 ppm via mask write
        assert plant.setpoint("naoh_dose") == 110
        await c.close(); close(plc, gsrv)
    asyncio.run(run())


def test_read_write_multiple_bypass_blocked_and_legit_works():
    async def run():
        plant, guard, plc, gsrv, gport, _ = await rig()
        assert "rejected" in await readwrite_attack(gport, 9000)
        assert plant.setpoint("naoh_dose") == 100 and guard.log[0].fc == 23
        c = await modbus.Client("127.0.0.1", gport).connect()
        out = await c.read_write(CL, 1, NAOH, [120])
        assert plant.setpoint("naoh_dose") == 120 and out == [150]
        await c.close(); close(plc, gsrv)
    asyncio.run(run())


def test_coil_writes_checked():
    async def run():
        plant, guard, plc, gsrv, gport, _ = await rig()
        plant.state.tank_level = 93
        r = await coil_attack(gport)                   # stop distribution with a full tank
        assert "rejected" in r and plant.setpoint("distribution_pump") == 1
        assert guard.log[0].check == "interlock"
        plant.state.tank_level = 60
        r = await coil_attack(gport)                   # normal tank, but stopping the town's pump needs a permit
        assert "rejected" in r and guard.log[0].check == "permit"
        c = await modbus.Client("127.0.0.1", gport).connect()
        guard.issue_permit("distribution_pump", 0, by="test operator")
        await c.write_coils(TAGS.holding["intake_pump"].address, [1, 0])   # FC 15, with a permit
        assert plant.setpoint("distribution_pump") == 0
        await c.write_coil(TAGS.holding["distribution_pump"].address, 1)
        with pytest.raises(modbus.ModbusError):                             # permits are single-use
            await c.write_coils(TAGS.holding["intake_pump"].address, [1, 0])
        await c.close(); close(plc, gsrv)
    asyncio.run(run())


def test_recon_and_diagnostics_blocked_and_tagged():
    async def run():
        plant, guard, plc, gsrv, gport, _ = await rig()
        r = await recon_attack(gport)
        assert r.count("rejected") == 2
        techs = {t[0] for d in list(guard.log)[:2] for t in d.techniques}
        assert {"T0888", "T0814"} <= techs and guard.log[0].check == "function"
        close(plc, gsrv)
    asyncio.run(run())


def test_unit_id_rotation_does_not_beat_flood_limit():
    async def run():
        plant, guard, plc, gsrv, gport, _ = await rig()
        ok, blocked = await flood_attack(gport, 30)
        # 10 different unit IDs -> per-label counts stay at 3, but the per-IP count catches it
        assert ok == 20 and blocked == 10
        close(plc, gsrv)
    asyncio.run(run())


# ---------------- robustness ----------------
def test_server_survives_malformed_frames():
    async def run():
        plant, guard, plc, gsrv, gport, _ = await rig()
        rng = random.Random(2)
        for _ in range(200):
            r, w = await asyncio.open_connection("127.0.0.1", gport)
            body = bytes(rng.randrange(256) for _ in range(rng.randrange(1, 30)))
            w.write(struct.pack(">HHHB", 1, 0, len(body) + 1, 1) + body)
            await w.drain()
            try:
                await asyncio.wait_for(r.read(300), 0.2)
            except asyncio.TimeoutError:
                pass
            w.close()
        c = await modbus.Client("127.0.0.1", gport).connect()       # still serving normally
        assert (await c.read_holding(NAOH, 1)) == [100]
        await c.close(); close(plc, gsrv)
    asyncio.run(run())


def test_idle_connections_dropped_and_client_cap():
    async def run():
        srv = await modbus.serve(Plant(noise=False).handle, "127.0.0.1", 0, idle_timeout=0.3, max_clients=2)
        port = srv.sockets[0].getsockname()[1]
        a = await modbus.Client("127.0.0.1", port).connect()
        b = await modbus.Client("127.0.0.1", port).connect()
        await a.read_holding(0, 1); await b.read_holding(0, 1)
        c = await modbus.Client("127.0.0.1", port, timeout=0.5).connect()
        with pytest.raises(ConnectionError):
            await c.read_holding(0, 1)                                # third client refused
        await asyncio.sleep(0.5)                                      # a and b idle out
        with pytest.raises(ConnectionError):
            await a.read_holding(0, 1)
        assert (await a.read_holding(0, 1)) == [150]                  # auto-reconnect
        srv.close()
    asyncio.run(run())


def test_plc_down_fails_safe_with_alert():
    async def run():
        plant, guard, plc, gsrv, gport, _ = await rig()
        guard.upstream = modbus.Client("127.0.0.1", 1, timeout=0.3)   # nothing listens on port 1
        c = await modbus.Client("127.0.0.1", gport).connect()
        with pytest.raises(modbus.ModbusError) as e:
            await c.write(NAOH, 110)
        assert e.value.code == modbus.GATEWAY_TARGET_FAILED
        assert guard.alerter.recent[0]["key"] == "plc_unreachable"
        await c.close(); close(plc, gsrv)
    asyncio.run(run())


# ---------------- modes ----------------
def test_monitor_mode_logs_but_passes():
    async def run():
        plant, guard, plc, gsrv, gport, _ = await rig(mode="monitor")
        r = await lye_attack(gport, 11100)
        assert "accepted" in r and plant.setpoint("naoh_dose") == 11100
        d = guard.log[0]
        assert d.would_block and d.check == "range" and "MONITOR" in d.reason
        assert guard.alerter.recent[0]["severity"] == "warning"
        close(plc, gsrv)
    asyncio.run(run())


def test_mode_off_passes_everything():
    async def run():
        plant, guard, plc, gsrv, gport, _ = await rig(mode="off")
        assert "accepted" in await lye_attack(gport, 11100)
        assert guard.log[0].check == "disabled"
        close(plc, gsrv)
    asyncio.run(run())


# ---------------- third-party client ----------------
def test_pymodbus_client_all_write_codes_through_guard():
    from pymodbus.client import AsyncModbusTcpClient

    async def run():
        plant, guard, plc, gsrv, gport, _ = await rig()
        c = AsyncModbusTcpClient("127.0.0.1", port=gport)
        await c.connect()
        assert not (await c.write_register(NAOH, 110)).isError()
        assert (await c.write_register(NAOH, 11100)).isError()
        assert not (await c.write_coil(TAGS.holding["intake_pump"].address, True)).isError()
        assert (await c.mask_write_register(address=NAOH, and_mask=0, or_mask=9000)).isError()
        rr = await c.read_coils(0, count=2)
        assert rr.bits[:2] == [True, True]
        assert plant.setpoint("naoh_dose") == 110
        c.close(); close(plc, gsrv)
    asyncio.run(run())


def test_flood_from_trusted_host_with_rotating_ids_still_caught():
    """Even if the attacker shares the HMI's IP (e.g. the OS refuses 127.0.0.66), rotating unit IDs doesn't help."""
    async def run():
        plant, guard, plc, gsrv, gport, _ = await rig()
        guard.trusted_ips = {"127.0.0.1"}
        import aegis.attacks as A
        old = A.ATTACKER_IP
        A.ATTACKER_IP = None
        try:
            ok, blocked = await flood_attack(gport, 30)
        finally:
            A.ATTACKER_IP = old
        assert ok == 20 and blocked == 10
        c = await modbus.Client("127.0.0.1", gport, unit=1).connect()   # the HMI label itself is unaffected
        await c.write(NAOH, 105)
        await c.close(); close(plc, gsrv)
    asyncio.run(run())


def test_read_flood_throttled_and_logged_once():
    async def run():
        plant, guard, plc, gsrv, gport, _ = await rig()
        c = modbus.Client("127.0.0.1", gport, local_ip="127.0.0.66")
        busy = ok = 0
        for _ in range(120):                      # ~120 reads as fast as possible from one IP
            try:
                await c.read_input(0, 8); ok += 1
            except modbus.ModbusError as e:
                assert e.code == modbus.DEVICE_BUSY; busy += 1
        assert ok >= 50 and busy > 0 and guard.read_stats["throttled"] == busy
        assert sum(d.check == "read_flood" for d in guard.log) <= 3          # not one log line per read
        await c.close(); close(plc, gsrv)
    asyncio.run(run())


def test_read_coalescing_spares_the_plc():
    """20 HMIs polling the same registers: the PLC sees a fraction of the reads."""
    async def run():
        plant, guard, plc, gsrv, gport, _ = await rig()
        guard.policy["max_reads_per_sec_per_ip"] = None
        calls = {"n": 0}
        orig = plant.handle

        async def counting(req, peer):
            calls["n"] += 1
            return await orig(req, peer)
        plant.handle = counting                    # count what actually reaches the PLC
        plc.close()
        plc2 = await modbus.serve(plant.handle, "127.0.0.1", 0)
        guard.upstream = modbus.Client("127.0.0.1", plc2.sockets[0].getsockname()[1])

        async def hmi():
            c = await modbus.Client("127.0.0.1", gport).connect()
            for _ in range(10):
                await c.read_input(0, 8)
                await asyncio.sleep(0.01)
            await c.close()
        await asyncio.gather(*(hmi() for _ in range(20)))
        assert guard.read_stats["served"] == 200
        assert calls["n"] < 100, calls             # most answered from the 100 ms cache
        # a write invalidates the cache: the next read sees the new value
        c = await modbus.Client("127.0.0.1", gport).connect()
        await c.write(NAOH, 105)
        assert (await c.read_holding(NAOH, 1)) == [105]
        await c.close(); plc2.close(); gsrv.close()
    asyncio.run(run())
