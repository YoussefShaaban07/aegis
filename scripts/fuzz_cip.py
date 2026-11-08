"""Differential fuzzing of the EtherNet/IP guard (judge round 17).

Mutates dangerous PCCC writes (lye 11,100; stopping the distribution pump) and wraps them in random
transports. Every frame Aegis FORWARDS is then executed by the simulated MicroLogix, and any change to
the PLC must match a value Aegis judged and approved. Caveat: the simulator reuses Aegis's own decoder
for the innermost typed-write fields, so this proves the outer layers (encapsulation, CPF, unconnected
send, CIP paths) can't smuggle a write past; only a real PLC can prove the last bytes are read the same.

    python scripts/fuzz_cip.py [seed] [iterations]
"""
import asyncio, random, sys
sys.path.insert(0, '.')
from aegis.cip import CIPGuard, Frame, SEND_RR, SEND_UNIT, build_cpf, NULL_ADDR, UNCONN_DATA, CONN_ADDR, CONN_DATA, CIPRequest, MicroLogixSim
from aegis.guard import Guard
from aegis.plant import Plant
from aegis.config import Tags
tags = Tags.load()
rng = random.Random(int(sys.argv[1]) if len(sys.argv) > 1 else 2)
seeds = []
for fnc, params in [(0xAB, bytes([2,7,0x89,1,0]) + b"\xff\xff" + (11100).to_bytes(2,"little")),
                    (0xAA, bytes([2,7,0x89,1,0]) + (11100).to_bytes(2,"little")),
                    (0xA9, bytes([2,7,0x89,1]) + (11100).to_bytes(2,"little")),
                    (0xAB, bytes([2,3,0x85,0,0]) + b"\x02\x00\x00\x00")]:      # stop distribution pump
    seeds.append(CIPRequest(0x4B, b"\x20\x67\x24\x01", bytes([7,9,16,1,2,3,4,0x0F,0,1,0,fnc]) + params).encode())
bypass = []
async def run():
    for i in range(int(sys.argv[2]) if len(sys.argv) > 2 else 30000):
        plant = Plant(noise=False)
        g = Guard(None, plant.snapshot); g.policy["lockdown"]["enabled"] = False
        async def st(): return plant.snapshot()
        g._state = st
        p = CIPGuard(g, "127.0.0.1", 1, tags); sim = MicroLogixSim(plant, tags)
        b = bytearray(rng.choice(seeds))
        for _ in range(rng.randint(1, 3)):
            b[rng.randrange(len(b))] = rng.randrange(256)
        if rng.random() < 0.2:
            b = b[:rng.randrange(1, len(b))] + bytes(rng.randrange(256) for _ in range(rng.randrange(6)))
        msg = bytes(b)
        if rng.random() < 0.5:
            f = Frame(SEND_RR, 1, data=build_cpf([[NULL_ADDR, b""], [UNCONN_DATA, msg]]))
        else:
            f = Frame(SEND_UNIT, 1, data=build_cpf([[CONN_ADDR, b"\x01\x02\x03\x04"], [CONN_DATA, b"\x01\x00" + msg]]))
        before = (list(plant.hr), list(plant.coils))
        try:
            out = await p.inspect(f, "Unknown host 9.9.9.9", "9.9.9.9:1", {})
        except Exception:
            continue                       # refused by the connection loop
        if out is not None:
            continue                       # refused / answered by Aegis
        judged = p.stats["writes_judged"]
        try:
            sim.handle(f)
        except Exception:
            continue
        after = (list(plant.hr), list(plant.coils))
        if after != before and judged == 0:
            bypass.append(("unjudged", msg.hex()))
        elif after != before:
            approved = {d.register: d.new for d in g.log if d.allowed}
            for t in tags.all.values():
                if t.table == "holding" and after[0][t.address] != before[0][t.address]:
                    if t.name not in approved or abs(t.from_raw(after[0][t.address]) - approved[t.name]) > 1e-6:
                        bypass.append(("value mismatch", t.name, t.from_raw(after[0][t.address]), approved.get(t.name), msg.hex()))
                if t.table == "coil" and after[1][t.address] != before[1][t.address]:
                    if t.name not in approved or approved[t.name] != after[1][t.address]:
                        bypass.append(("coil mismatch", t.name, after[1][t.address], approved.get(t.name), msg.hex()))
def main():
    asyncio.run(run())
    return bypass


if __name__ == "__main__":
    main()
    print("PLC changes that differ from what Aegis judged:", len(bypass))
    for h in bypass[:5]:
        print("  ", h)
