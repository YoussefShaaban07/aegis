"""Gateway mode: run only the guard, in front of a real PLC (or OpenPLC).

    python -m aegis.gateway --plc-host 192.168.1.50 --plc-port 502 --listen-port 502
    python -m aegis.gateway --plc-host 192.168.1.50 --mode monitor     # trial period: log only

Point the HMI / AI / everything else at this machine instead of the PLC, and
firewall the PLC so only this machine can reach it. Uses config/tags.json for
the register map, config/policy.json for the safety envelope and
config/process.json for the digital twin. The twin switches itself off if the
PLC doesn't expose the sensors it needs (pH, chlorine, level, raw-water pH,
alkalinity, turbidity); the static checks still run.

If the PLC is unreachable, writes fail safe (Modbus exception 0x0B) and an alert is raised.
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
from .guard import MODES, Guard, read_plc_state
from .twin import REQUIRED, Twin


def build(plc_host: str, plc_port: int, mode: str = "enforce", plc_unit: int = 1, audit=None, alerter=None,
          use_twin: bool = True, printer=print):
    tags = Tags.load()
    audit = audit or AuditLog()
    alerter = alerter or Alerter(audit)
    upstream = modbus.Client(plc_host, plc_port, unit=plc_unit)          # connects lazily, reconnects
    state_client = modbus.Client(plc_host, plc_port, unit=plc_unit)
    has_sensors = all(k in tags.all for k in REQUIRED)
    twin = Twin() if (use_twin and has_sensors) else None
    guard = Guard(upstream, lambda: read_plc_state(state_client, tags), tags=tags, audit=audit,
                  alerter=alerter, policy_path=POLICY_PATH, twin=twin, mode=mode)
    orig = guard._record

    def record_and_print(d):
        orig(d)
        mark = "WOULD" if d.would_block else ("ALLOW" if d.allowed else "BLOCK")
        tech = ",".join(t[0] for t in d.techniques)
        printer(f"{time.strftime('%H:%M:%S')} {mark:5} {d.source:28} {d.register}={d.new:g} {d.unit}  "
                f"[{d.check}{' ' + tech if tech else ''}] {d.reason}")

    guard._record = record_and_print
    return guard, audit, twin


async def run(plc_host, plc_port, listen_host, listen_port, mode, plc_unit, use_twin):
    guard, audit, twin = build(plc_host, plc_port, mode, plc_unit, use_twin=use_twin)
    srv = await modbus.serve(guard.handle, listen_host, listen_port)
    print(f"Aegis gateway [{mode}]: listening on {listen_host}:{listen_port} -> PLC {plc_host}:{plc_port} "
          f"(unit {plc_unit})")
    print(f"Digital twin: {'on' if twin else 'off (sensor tags missing or --no-twin)'}")
    print(f"Audit log: {audit.path}  ({audit.verify()['message']})")
    async with srv:
        await srv.serve_forever()


def main():
    load_dotenv()
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--plc-host", required=True)
    p.add_argument("--plc-port", type=int, default=502)
    p.add_argument("--plc-unit", type=int, default=1, help="Modbus unit/slave ID of the PLC")
    p.add_argument("--listen-host", default="0.0.0.0")
    p.add_argument("--listen-port", type=int, default=5502)
    p.add_argument("--mode", choices=MODES, default="enforce")
    p.add_argument("--no-twin", action="store_true", help="static checks only")
    a = p.parse_args()
    asyncio.run(run(a.plc_host, a.plc_port, a.listen_host, a.listen_port, a.mode, a.plc_unit, not a.no_twin))


if __name__ == "__main__":
    main()
