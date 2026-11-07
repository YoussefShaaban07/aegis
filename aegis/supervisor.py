"""Keep the gateway running: restart it if it ever exits, with backoff.

    python -m aegis.supervisor -- --plc-host 192.168.1.50 --listen-port 502

Being inline between operators and the PLC means an Aegis crash would cut
operators off from the plant. Defence in depth:
  1. the guard catches its own errors per request (that write is rejected, the server keeps serving);
  2. this supervisor restarts the process within seconds if it dies anyway;
  3. the OS service manager restarts the supervisor (deploy/aegis.service for systemd;
     on Windows, run it as a service with NSSM or Task Scheduler "restart on failure");
  4. break-glass: a documented physical bypass (patch cable straight to the PLC switch
     port) so a plant is never more dependent on Aegis than on its own network.
"""
from __future__ import annotations

import subprocess
import sys
import time


def run(args: list[str], max_backoff: float = 30.0, max_restarts: int | None = None, sleep=time.sleep) -> int:
    restarts, backoff = 0, 1.0
    while True:
        started = time.time()
        print(f"[supervisor] starting gateway {' '.join(args)}", flush=True)
        code = subprocess.call([sys.executable, "-m", "aegis.gateway", *args])
        up = time.time() - started
        print(f"[supervisor] gateway exited with code {code} after {up:.0f} s", flush=True)
        restarts += 1
        if max_restarts is not None and restarts > max_restarts:
            return code
        backoff = 1.0 if up > 60 else min(max_backoff, backoff * 2)   # crash-looping -> back off
        sleep(backoff)


if __name__ == "__main__":
    a = sys.argv[1:]
    if a and a[0] == "--":
        a = a[1:]
    sys.exit(run(a))
