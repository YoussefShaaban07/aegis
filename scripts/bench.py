"""Latency benchmark: how much time does Aegis add to each Modbus request?

    python scripts/bench.py            # 2000 writes + 2000 reads, direct vs through the guard

Runs the simulated PLC and the guard on localhost and times full request round
trips with our client. Prints p50 / p99 for: direct-to-PLC, through the guard
with static checks only, and through the guard with the digital twin on.
Numbers depend on the machine; run it on yours.
"""
import asyncio
import pathlib
import platform
import statistics
import sys
import time

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
from aegis import modbus  # noqa: E402
from aegis.guard import Guard  # noqa: E402
from aegis.plant import TAGS, Plant  # noqa: E402
from aegis.twin import Twin  # noqa: E402

N = 2000


def pct(xs, q):
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))]


async def timed(client, n, write):
    tag = TAGS.holding["naoh_dose"]
    out = []
    for i in range(n):
        t = time.perf_counter()
        if write:
            await client.write(tag.address, 100 + (i % 2) * 5)    # 100 <-> 105: always allowed
        else:
            await client.read_holding(0, 3)
        out.append((time.perf_counter() - t) * 1000)
    return out


async def main():
    plant = Plant(noise=False)
    plc = await modbus.serve(plant.handle, "127.0.0.1", 0)
    pport = plc.sockets[0].getsockname()[1]
    rows = []
    for label, twin in (("guard, static checks", None), ("guard + digital twin", Twin())):
        g = Guard(modbus.Client("127.0.0.1", pport), plant.snapshot, twin=twin)
        g.policy["max_writes_per_min_per_source"] = 10 ** 9
        g.policy["limits"]["naoh_dose"]["max_change_per_min"] = None
        g.policy["max_reversals_per_10min"] = None
        g.policy["max_reads_per_sec_per_ip"] = None
        g.policy["read_cache_ms"] = 0
        srv = await modbus.serve(g.handle, "127.0.0.1", 0)
        c = await modbus.Client("127.0.0.1", srv.sockets[0].getsockname()[1]).connect()
        rows.append((label + ": write", await timed(c, N, True)))
        rows.append((label + ": read", await timed(c, N, False)))
        await c.close(); srv.close()
    d = await modbus.Client("127.0.0.1", pport).connect()
    rows.insert(0, ("direct to PLC: read", await timed(d, N, False)))
    rows.insert(0, ("direct to PLC: write", await timed(d, N, True)))
    print(f"{platform.processor() or platform.machine()} · Python {platform.python_version()} · {N} requests each\n")
    print(f"{'path':38} {'p50 ms':>8} {'p99 ms':>8} {'mean ms':>8}")
    for label, xs in rows:
        print(f"{label:38} {pct(xs, .5):8.3f} {pct(xs, .99):8.3f} {statistics.fmean(xs):8.3f}")
    plc.close()


asyncio.run(main())
