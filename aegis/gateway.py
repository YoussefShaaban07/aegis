"""Gateway mode: run only the guard, in front of a real PLC (or OpenPLC).

    python -m aegis.gateway --plc-host 192.168.1.50 --plc-port 502 --listen-port 502

Point the HMI / AI / everything else at this machine instead of the PLC, and
firewall the PLC so only this machine can reach it. Uses config/tags.json for
the register map and config/policy.json for the safety envelope.
"""
from __future__ import annotations

import argparse
import asyncio
import time

from dotenv import load_dotenv

from . import modbus
from .alerts import Alerter
from .audit import AuditLog
from .config import POLICY_PATH, Tags
from .guard import Guard, read_plc_state


async def run(plc_host: str, plc_port: int, listen_host: str, listen_port: int):
    tags = Tags.load()
    audit = AuditLog()
    alerter = Alerter(audit)
    upstream = await modbus.Client(plc_host, plc_port).connect()
    state_client = await modbus.Client(plc_host, plc_port).connect()
    guard = Guard(upstream, lambda: read_plc_state(state_client, tags), tags=tags,
                  audit=audit, alerter=alerter, policy_path=POLICY_PATH)
    orig = guard._record

    def record_and_print(d):
        orig(d)
        mark = "ALLOW" if d.allowed else "BLOCK"
        print(f"{time.strftime('%H:%M:%S')} {mark:5} {d.source:28} {d.register}={d.new:g} {d.unit}  {d.reason}",
              flush=True)

    guard._record = record_and_print
    srv = await modbus.serve(guard.handle, listen_host, listen_port)
    print(f"Aegis gateway: listening on {listen_host}:{listen_port} -> PLC {plc_host}:{plc_port}")
    print(f"Audit log: {audit.path}  ({audit.verify()['message']})")
    async with srv:
        await srv.serve_forever()


def main():
    load_dotenv()
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--plc-host", required=True)
    p.add_argument("--plc-port", type=int, default=502)
    p.add_argument("--listen-host", default="0.0.0.0")
    p.add_argument("--listen-port", type=int, default=5502)
    a = p.parse_args()
    asyncio.run(run(a.plc_host, a.plc_port, a.listen_host, a.listen_port))


if __name__ == "__main__":
    main()
