"""Latency Aegis adds on the EtherNet/IP path, measured with pycomm3 (an independent client).

    python scripts/bench_cip.py [N]

Direct to the simulated MicroLogix, then through Aegis with static rules only, then with the twin.
Each write alternates between two allowed values so every one is judged and forwarded."""
import asyncio
import statistics
import sys
import threading
import time

sys.path.insert(0, ".")
from pycomm3 import SLCDriver  # noqa: E402

from aegis.cip import CIPGuard, MicroLogixSim  # noqa: E402
from aegis.config import Tags  # noqa: E402
from aegis.guard import Guard  # noqa: E402
from aegis.plant import Plant  # noqa: E402
from aegis.twin import Twin  # noqa: E402


def run(n=200):
    loop = asyncio.new_event_loop()
    plant, tags = Plant(noise=False), Tags.load()
    plc = loop.run_until_complete(MicroLogixSim(plant, tags).serve("127.0.0.1", 0))
    pport = plc.sockets[0].getsockname()[1]
    ports = {"direct": pport}
    for name, twin in (("aegis static", None), ("aegis + twin", Twin())):
        g = Guard(None, plant.snapshot, twin=twin)
        g.policy["max_writes_per_min_per_source"] = 10 ** 6
        g.policy["max_reversals_per_10min"] = None
        g.policy["max_large_reversals_per_hour"] = None
        srv = loop.run_until_complete(CIPGuard(g, "127.0.0.1", pport, tags).serve("127.0.0.1", 0))
        ports[name] = srv.sockets[0].getsockname()[1]
    threading.Thread(target=loop.run_forever, daemon=True).start()
    out = {}
    for name, port in ports.items():
        ts = []
        with SLCDriver(f"127.0.0.1:{port}") as c:
            for i in range(n):
                t0 = time.perf_counter()
                r = c.write(("N7:1", 100 if i % 2 else 105))
                ts.append((time.perf_counter() - t0) * 1000)
                assert r.error is None, (name, r.error)
        ts.sort()
        out[name] = (statistics.median(ts), ts[int(0.99 * (n - 1))])
        print(f"{name:14} write round trip: p50 {out[name][0]:.2f} ms, p99 {out[name][1]:.2f} ms")
    return out


if __name__ == "__main__":
    run(int(sys.argv[1]) if len(sys.argv) > 1 else 200)
