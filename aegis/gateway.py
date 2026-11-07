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
from .config import POLICY_PATH, Tags, verify_policy_file
from .guard import MODES, Guard, read_plc_state
from .forewarn import ForecastWatch
from .integrity import IntegrityMonitor
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


async def integrity_loop(guard, twin, poll_s: float = 10.0, printer=print, history_path: str | None = None):
    """Poll the PLC, check the process matches what Aegis approved, and record history for calibration."""
    mon = IntegrityMonitor(twin.model if twin else None, alerter=guard.alerter, audit=guard.audit)
    watch = ForecastWatch(guard.alerter, guard.audit)
    reader = modbus.Client(guard.upstream.host, guard.upstream.port, unit=guard.upstream.unit)
    seen = 0
    writer = None
    while True:
        try:
            st = await read_plc_state(reader, guard.tags)
            if history_path:
                import csv
                from pathlib import Path
                if writer is None:
                    Path(history_path).parent.mkdir(parents=True, exist_ok=True)
                    new = not Path(history_path).exists()
                    fh = open(history_path, "a", newline="")
                    writer = csv.DictWriter(fh, ["t"] + list(guard.tags.all))
                    if new:
                        writer.writeheader()
                writer.writerow({"t": round(time.time(), 1), **{k: st.get(k) for k in guard.tags.all}})
                fh.flush()
            guard.sync_commanded(st)
            mon.update(st, time.time(), guard.commanded)
            ok, msg = verify_policy_file(POLICY_PATH)
            if not ok:
                guard.alerter.raise_alert("policy_tamper", "critical", f"Policy file integrity check failed: {msg}")
            if history_path and guard.seen:            # discovery for `python -m aegis.onboard`
                import json
                from pathlib import Path
                Path(history_path).with_name("discovery.json").write_text(json.dumps(guard.seen, indent=1))
            if twin and twin.available(st):
                for w in watch.update(twin.forecast(st, None, 180, every_min=5), st).values():
                    if w.get("printed") is None:
                        printer(f"{time.strftime('%H:%M:%S')} EARLY WARNING: {w['message']}")
                        w["printed"] = True
            if len(mon.events) > seen:
                for ev in list(mon.events)[:len(mon.events) - seen]:
                    printer(f"{time.strftime('%H:%M:%S')} INTEGRITY {ev['severity'].upper()}: {ev['message']}")
                seen = len(mon.events)
        except Exception as e:     # PLC unreachable etc.; the guard already fails safe on writes
            printer(f"{time.strftime('%H:%M:%S')} integrity poll failed: {e}")
        await asyncio.sleep(poll_s)


async def health_server(guard, audit, port: int, host: str = "127.0.0.1"):
    """Minimal HTTP health endpoint for monitoring: GET /health -> JSON."""
    import json
    started = time.time()

    async def on(reader, writer):
        try:
            await asyncio.wait_for(reader.readline(), 5)
            ok = True
            try:
                await asyncio.wait_for(guard.upstream.read_holding(0, 1), 2)
            except Exception:
                ok = False
            body = json.dumps({"status": "ok" if ok else "plc_unreachable", "mode": guard.mode,
                               "uptime_s": round(time.time() - started), "counts": dict(guard.counts),
                               "latency": guard.latency(), "audit_ok": audit.verify()["ok"]}).encode()
            code = "200 OK" if ok else "503 Service Unavailable"
            writer.write(f"HTTP/1.1 {code}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\n"
                         f"Connection: close\r\n\r\n".encode() + body)
            await writer.drain()
        finally:
            writer.close()
    return await asyncio.start_server(on, host, port)


async def run(plc_host, plc_port, listen_host, listen_port, mode, plc_unit, use_twin, health_port=None):
    guard, audit, twin = build(plc_host, plc_port, mode, plc_unit, use_twin=use_twin)
    if health_port:
        await health_server(guard, audit, health_port)
        print(f"Health: http://127.0.0.1:{health_port}/health")
    asyncio.create_task(integrity_loop(guard, twin, history_path="data/history.csv"))
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
    p.add_argument("--health-port", type=int, default=None, help="serve GET /health on 127.0.0.1:PORT")
    a = p.parse_args()
    asyncio.run(run(a.plc_host, a.plc_port, a.listen_host, a.listen_port, a.mode, a.plc_unit, not a.no_twin,
                    a.health_port))


if __name__ == "__main__":
    main()
