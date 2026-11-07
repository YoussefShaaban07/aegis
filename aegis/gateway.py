"""Gateway mode: run only the guard, in front of a real PLC (or OpenPLC).

    python -m aegis.gateway --plc-host 192.168.1.50 --plc-port 502 --listen-port 502
    python -m aegis.gateway --plc-host 192.168.1.50 --mode monitor     # trial period: log only

Unit IDs are routed (Modbus TCP semantics): requests are forwarded to the same
unit ID, and only --plc-unit is allowed. Writers are named by IP with --sources.

Point the HMI / AI / everything else at this machine instead of the PLC, and
firewall the PLC so only this machine can reach it. Uses config/tags.json for
the register map, config/policy.json for the safety envelope and
config/process.json for the digital twin. The twin switches itself off if the
PLC doesn't expose the sensors it needs (pH, chlorine, level, raw-water pH,
alkalinity, turbidity); the static checks still run.

If the PLC is unreachable, writes fail safe (Modbus exception 0x0B) and an alert is raised.

Allen-Bradley MicroLogix / SLC over EtherNet/IP (what FactoryTalk / PanelView actually use):

    python -m aegis.gateway --protocol cip --plc-host 192.168.1.50 --listen-port 44818 \
        --sources "10.0.0.5=Operator HMI"

Same checks, same twin, same safe-hold; tags are addressed by their "pccc" data-file
address in tags.json (N7:1, B3:0/1). Mode changes, program download/upload and any
command Aegis doesn't recognise are refused. See aegis/cip.py for what is and isn't covered.
"""
from __future__ import annotations

import argparse
import asyncio
import time

from dotenv import load_dotenv

from . import modbus
from .cip import CIPGuard, PCCCClient
from .alerts import Alerter
from .audit import AuditLog
from .config import POLICY_PATH, Tags, verify_policy_file
from .guard import MODES, Guard, read_plc_state
from .forewarn import ForecastWatch
from .integrity import IntegrityMonitor
from .labinputs import LabInputs
from .safehold import SafeHold, execute as safehold_execute
from .twin import REQUIRED, Twin


def build(plc_host: str, plc_port: int, mode: str = "enforce", plc_unit: int = 1, audit=None, alerter=None,
          use_twin: bool = True, printer=print, unit_mode: str = "route", plc_units: set | None = None,
          ip_sources: dict | None = None, protocol: str = "modbus"):
    tags = Tags.load()
    audit = audit or AuditLog()
    alerter = alerter or Alerter(audit)
    if protocol == "cip":
        upstream = PCCCClient(plc_host, plc_port, tags)                   # safe-hold writes go through this
        state_client = PCCCClient(plc_host, plc_port, tags)
        reader_fn = lambda: state_client.read_state(tags)               # noqa: E731
    else:
        upstream = modbus.Client(plc_host, plc_port, unit=plc_unit)      # connects lazily, reconnects
        state_client = modbus.Client(plc_host, plc_port, unit=plc_unit)
        reader_fn = lambda: read_plc_state(state_client, tags)          # noqa: E731
    from .config import load_policy
    lab_cfg = load_policy(tags).get("lab_inputs") or {}
    lab = LabInputs(lab_cfg, "data/lab_inputs.json", audit=audit, alerter=alerter)
    plc_reader = reader_fn

    async def reader_fn():                      # PLC readings + fresh lab values for what the PLC lacks
        lab.reload()
        return lab.fill(await plc_reader())
    has_sensors = all(k in tags.all or k in lab_cfg for k in REQUIRED)
    twin = Twin() if (use_twin and has_sensors) else None
    guard = Guard(upstream, reader_fn, tags=tags, audit=audit,
                  alerter=alerter, policy_path=POLICY_PATH, twin=twin, mode=mode, unit_mode=unit_mode,
                  plc_units=plc_units or {plc_unit}, ip_sources=ip_sources)
    orig = guard._record

    def record_and_print(d):
        orig(d)
        mark = "WOULD" if d.would_block else ("ALLOW" if d.allowed else "BLOCK")
        tech = ",".join(t[0] for t in d.techniques)
        printer(f"{time.strftime('%H:%M:%S')} {mark:5} {d.source:28} {d.register}={d.new:g} {d.unit}  "
                f"[{d.check}{' ' + tech if tech else ''}] {d.reason}")

    guard._record = record_and_print
    guard.protocol = protocol
    guard.lab = lab
    return guard, audit, twin


async def poll_state(reader, tags) -> dict:
    if isinstance(reader, PCCCClient):
        return await reader.read_state(tags)
    return await read_plc_state(reader, tags)


def make_reader(guard):
    up = guard.upstream
    if isinstance(up, PCCCClient):
        return PCCCClient(up.host, up.port, guard.tags)
    return modbus.Client(up.host, up.port, unit=up.unit)


async def integrity_loop(guard, twin, poll_s: float = 10.0, printer=print, history_path: str | None = None):
    """Poll the PLC, check the process matches what Aegis approved, and record history for calibration."""
    mon = IntegrityMonitor(twin.model if twin else None, alerter=guard.alerter, audit=guard.audit)
    watch = ForecastWatch(guard.alerter, guard.audit)
    hold = SafeHold(guard)
    reader = make_reader(guard)
    seen = 0
    writer = None
    while True:
        try:
            st = await poll_state(reader, guard.tags)
            if getattr(guard, "lab", None):
                guard.lab.reload()
                st = guard.lab.fill(st)
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
            if twin:
                twin.observe(st, time.time())
                hold.cfg.update(guard.policy.get("safe_hold") or {})
                act = hold.update(st, time.time(), sensors_trusted=mon.status.get("ok", True))
                if act:            # write first; only a value the PLC accepted is recorded and held
                    if await safehold_execute(guard, act, guard.upstream.write_tag):
                        printer(f"{time.strftime('%H:%M:%S')} SAFE-HOLD: {guard.log[0].reason}")
                    else:
                        printer(f"{time.strftime('%H:%M:%S')} SAFE-HOLD FAILED: {act['failed']}")
            guard.flush_suppressed()
            if history_path:                    # an engineer logged in on this box releases a safe-hold with
                from pathlib import Path        #   echo distribution_rate > data/release_hold
                rel = Path(history_path).with_name("release_hold")
                if rel.exists():
                    for reg in rel.read_text().split():
                        if guard.release_hold(reg, "engineer (console on the Aegis box)"):
                            printer(f"{time.strftime('%H:%M:%S')} safe-hold on {reg} released from the console")
                    rel.unlink()
            if history_path:
                from pathlib import Path
                guard.save_state(Path(history_path).with_name("guard_state.json"))
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
                if isinstance(guard.upstream, PCCCClient):
                    await asyncio.wait_for(guard.upstream.read_state(guard.tags), 2)
                else:
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


async def run(plc_host, plc_port, listen_host, listen_port, mode, plc_unit, use_twin, health_port=None,
              ip_sources=None, protocol="modbus"):
    guard, audit, twin = build(plc_host, plc_port, mode, plc_unit, use_twin=use_twin, ip_sources=ip_sources,
                               protocol=protocol)
    if guard.load_state("data/guard_state.json"):
        print("Restored rate/ramp windows from before the restart")
    if health_port:
        await health_server(guard, audit, health_port)
        print(f"Health: http://127.0.0.1:{health_port}/health")
    asyncio.create_task(integrity_loop(guard, twin, history_path="data/history.csv"))
    if protocol == "cip":
        srv = await CIPGuard(guard, plc_host, plc_port).serve(listen_host, listen_port)
        print(f"Aegis gateway [{mode}, EtherNet/IP + PCCC]: listening on {listen_host}:{listen_port} -> "
              f"MicroLogix/SLC {plc_host}:{plc_port}")
    else:
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
    p.add_argument("--protocol", choices=["modbus", "cip"], default="modbus",
                   help="modbus (TCP 502) or cip (EtherNet/IP + PCCC to a MicroLogix / SLC, TCP 44818)")
    p.add_argument("--plc-port", type=int, default=None, help="default 502 (modbus) or 44818 (cip)")
    p.add_argument("--plc-unit", type=int, default=1, help="Modbus unit/slave ID of the PLC")
    p.add_argument("--listen-host", default="0.0.0.0")
    p.add_argument("--listen-port", type=int, default=5502)
    p.add_argument("--mode", choices=MODES, default="enforce")
    p.add_argument("--no-twin", action="store_true", help="static checks only")
    p.add_argument("--health-port", type=int, default=None, help="serve GET /health on 127.0.0.1:PORT")
    p.add_argument("--sources", default="", help='name writers by IP, e.g. "10.0.0.5=Operator HMI,10.0.0.9=AI copilot"')
    a = p.parse_args()
    srcs = dict(x.split("=", 1) for x in a.sources.split(",") if "=" in x)
    port = a.plc_port or (44818 if a.protocol == "cip" else 502)
    asyncio.run(run(a.plc_host, port, a.listen_host, a.listen_port, a.mode, a.plc_unit, not a.no_twin,
                    a.health_port, srcs, a.protocol))


if __name__ == "__main__":
    main()
