"""Bypass check: can this machine reach the PLC without going through Aegis?

Aegis only protects the commands that pass through it. A MicroLogix 1400
speaks Modbus TCP *and* EtherNet/IP at the same time, and many PLCs also run a
web server, programming ports or telnet. If any of those is reachable from the
plant network, an attacker can simply go around the guard.

Run this FROM ANY MACHINE OTHER THAN THE AEGIS BOX (an HMI PC, an engineering
laptop, a box on the office VLAN). After a correct install, every port should be
CLOSED or FILTERED. Anything OPEN is a way around Aegis and needs a firewall rule.

    python -m aegis.exposure 192.168.1.50
    python -m aegis.exposure 192.168.1.50 --json

It only opens and closes TCP connections (no data is sent), which is safe for
a running PLC. It does not try UDP (EtherNet/IP implicit I/O on 2222/udp, BACnet
47808/udp); check those in the firewall rules themselves.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import time

PORTS = {
    502: "Modbus TCP",
    44818: "EtherNet/IP / CIP (Rockwell MicroLogix, CompactLogix: programming and messaging)",
    102: "Siemens S7 / ISO-TSAP",
    20000: "DNP3",
    2404: "IEC 60870-5-104",
    4840: "OPC UA",
    1911: "Niagara Fox",
    80: "web server (PLC configuration pages)",
    443: "web server (HTTPS)",
    23: "telnet",
    21: "FTP (firmware / program upload on some PLCs)",
    22: "SSH",
    161: "SNMP (TCP; usually UDP)",
}


async def probe(host: str, port: int, timeout: float = 2.0) -> str:
    try:
        _, w = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except asyncio.TimeoutError:
        return "filtered"
    except ConnectionRefusedError:
        return "closed"
    except OSError as e:
        return f"unreachable ({e.strerror or e})"
    w.close()
    try:
        await w.wait_closed()
    except Exception:
        pass
    return "OPEN"


async def scan(host: str, ports: dict = PORTS, timeout: float = 2.0) -> dict:
    t0 = time.time()
    res = await asyncio.gather(*(probe(host, p, timeout) for p in ports))
    rows = [{"port": p, "service": ports[p], "state": s} for p, s in zip(ports, res)]
    open_ = [r for r in rows if r["state"] == "OPEN"]
    return {"host": host, "checked_at": time.strftime("%Y-%m-%d %H:%M:%S"), "seconds": round(time.time() - t0, 1),
            "ports": rows, "bypass_possible": bool(open_),
            "verdict": ("BYPASS POSSIBLE: " + ", ".join(f"{r['port']} ({r['service'].split(' (')[0]})" for r in open_)
                        + " reachable without Aegis. Firewall the PLC so only the Aegis box can reach it.")
            if open_ else "No bypass found over TCP from this machine (also check UDP rules and other VLANs)."}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("plc_host")
    ap.add_argument("--timeout", type=float, default=2.0)
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args(argv)
    r = asyncio.run(scan(a.plc_host, timeout=a.timeout))
    if a.json:
        print(json.dumps(r, indent=1))
    else:
        for row in r["ports"]:
            print(f"  {row['port']:>5}  {row['state']:12} {row['service']}")
        print(r["verdict"])
    return 1 if r["bypass_possible"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
