"""Safety invariants under random traffic.

Not "the attacks we thought of": thousands of random Modbus requests (every function code,
random addresses and values, multi-register spans crossing tagged and untagged registers,
random unit IDs) through the guard, and after EVERY request:

  1. every tagged setpoint in the PLC is inside its hard min/max;
  2. no register or coil outside the write allowlist has changed;
  3. critical commands (pump stops) never happened without a permit.
"""
import asyncio
import os
import random
import struct

from aegis import modbus
from aegis.config import load_policy
from aegis.guard import Guard
from aegis.plant import TAGS, Plant
from aegis.twin import Twin

FCS = [1, 2, 3, 4, 5, 6, 8, 15, 16, 17, 22, 23, 43, 90]


def random_pdu(rng: random.Random, limits: dict) -> bytes:
    fc = rng.choice(FCS)
    addr = rng.choice([0, 1, 2, 3, 4, 7, 9, 15, rng.randrange(0, 70000) & 0xFFFF])
    def val():
        # mix plausible engineering values, hard-limit edges, and garbage
        return rng.choice([rng.randrange(0, 300), rng.randrange(0, 65536), 0, 1, 65535, 11100, 250, 251, 400, 401])
    if fc in (1, 2, 3, 4):
        return struct.pack(">BHH", fc, addr, rng.randrange(1, 10))
    if fc == 5:
        return struct.pack(">BHH", fc, addr, rng.choice([0, 0xFF00, 0x1234]))
    if fc == 6:
        return struct.pack(">BHH", fc, addr, val())
    if fc == 15:
        n = rng.randrange(1, 6)
        bits = [rng.randrange(2) for _ in range(n)]
        data = modbus.pack_bits(bits)
        return struct.pack(">BHHB", fc, addr, n, len(data)) + data
    if fc == 16:
        n = rng.randrange(1, 6)
        return struct.pack(f">BHHB{n}H", fc, addr, n, 2 * n, *[val() for _ in range(n)])
    if fc == 22:
        return struct.pack(">BHHH", fc, addr, rng.randrange(65536), rng.randrange(65536))
    if fc == 23:
        n = rng.randrange(1, 4)
        return struct.pack(f">BHHHHB{n}H", fc, rng.randrange(0, 5), rng.randrange(1, 4), addr, n, 2 * n,
                           *[val() for _ in range(n)])
    return bytes([fc]) + bytes(rng.randrange(256) for _ in range(rng.randrange(0, 8)))


def snapshot_regs(plant):
    return list(plant.hr), list(plant.coils)


def test_random_traffic_never_breaks_invariants():
    async def run():
        rng = random.Random(20261107)
        plant = Plant(noise=False)
        plc = await modbus.serve(plant.handle, "127.0.0.1", 0)
        g = Guard(modbus.Client("127.0.0.1", plc.sockets[0].getsockname()[1]), plant.snapshot, twin=Twin())
        g.policy["max_writes_per_min_per_source"] = 10 ** 9      # let traffic reach the deeper checks
        g.policy["max_reads_per_sec_per_ip"] = None
        limits = g.policy["limits"]
        writable = {(t.table, t.address): n for n, t in TAGS.holding.items() if n in limits}
        srv = await modbus.serve(g.handle, "127.0.0.1", 0)
        c = await modbus.Client("127.0.0.1", srv.sockets[0].getsockname()[1]).connect()
        hr0, co0 = snapshot_regs(plant)
        stats = {"sent": 0, "accepted": 0, "rejected": 0}
        for i in range(int(os.getenv("AEGIS_FUZZ_N", "3000"))):          # AEGIS_FUZZ_N=20000 for a long run
            pdu = random_pdu(rng, limits)
            unit = rng.choice([1, 1, 2, 66, 77, 200])
            try:
                await c.call_pdu(pdu, unit=unit)
                stats["accepted"] += 1
            except modbus.ModbusError:
                stats["rejected"] += 1
            except ConnectionError:
                c = await modbus.Client("127.0.0.1", srv.sockets[0].getsockname()[1]).connect()
            stats["sent"] += 1
            if i % 50 == 0:
                plant.step(1.0)
            # invariant 1: hard limits
            for name, lim in limits.items():
                v = plant.setpoint(name)
                assert lim["min"] <= v <= lim["max"], (i, name, v, pdu.hex())
            # invariant 2: nothing outside the allowlist changed
            hr, co = snapshot_regs(plant)
            for a, (x, y) in enumerate(zip(hr0, hr)):
                if ("holding", a) not in writable:
                    assert x == y, (i, "holding", a, pdu.hex())
            for a, (x, y) in enumerate(zip(co0, co)):
                if ("coil", a) not in writable:
                    assert x == y, (i, "coil", a, pdu.hex())
            # invariant 3: pumps never stopped (no permit was ever issued)
            assert plant.setpoint("intake_pump") == 1 and plant.setpoint("distribution_pump") == 1, (i, pdu.hex())
        print("invariant fuzz:", stats)
        assert stats["accepted"] > 300 and stats["rejected"] > 1000, stats   # the test exercised both paths
        await c.close(); plc.close(); srv.close()
    asyncio.run(run())
