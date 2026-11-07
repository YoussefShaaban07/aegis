"""How long does one twin-checked write take on a weak box? Pin to one core, optionally with busy neighbours.

    taskset -c 0 python scripts/bench_lowpower.py [busy_procs]

The budget is policy.prediction.budget_ms (500 ms). A Raspberry Pi-class CPU is several times slower
per core than the cloud VM these numbers come from, so compare p99 x 5 against the budget."""
import multiprocessing as mp
import statistics
import sys
import time

sys.path.insert(0, ".")
from aegis.guard import Guard  # noqa: E402
from aegis.plant import Plant  # noqa: E402
from aegis.twin import Twin  # noqa: E402


def burn(_):
    while True:
        pass


if __name__ == "__main__":
    busy = int(sys.argv[1]) if len(sys.argv) > 1 else 0
    procs = [mp.Process(target=burn, args=(0,), daemon=True) for _ in range(busy)]
    for p in procs:
        p.start()
    plant = Plant(noise=False)
    g = Guard(None, plant.snapshot, twin=Twin())
    g.policy["max_writes_per_min_per_source"] = 10 ** 6
    g.policy["max_reversals_per_10min"] = None
    g.policy["max_large_reversals_per_hour"] = None
    ts = []
    for i in range(120):
        t0 = time.perf_counter()
        g.check("naoh_dose", 105 if i % 2 else 110, plant.snapshot(), "Operator HMI", "h:1", dry_run=True)
        ts.append((time.perf_counter() - t0) * 1000)
    ts.sort()
    print(f"busy neighbours {busy}: p50 {statistics.median(ts):.1f} ms, p99 {ts[int(.99 * 119)]:.1f} ms, "
          f"max {ts[-1]:.1f} ms; timeouts {g.counts.get('twin_timeouts', 0)}")
    for p in procs:
        p.terminate()
