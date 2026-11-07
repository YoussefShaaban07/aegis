"""Runs everything: plant physics, PLC (Modbus), Aegis guard (Modbus), web HMI.

    python -m aegis.server        then open http://127.0.0.1:8000

Ports: PLC 5020 (internal), guard 5502 (the plant's "exposed" Modbus port).
Engineer actions (guard on/off, editing rules, AI autonomy) need AEGIS_ENGINEER_PIN.
"""
from __future__ import annotations

import asyncio
import hmac
import os
import time
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from pydantic import BaseModel

from . import modbus
from .alerts import Alerter
from .attacks import INJECTION, lye_attack
from .audit import AuditLog
from .config import POLICY_PATH, PolicyError
from .copilot import Copilot
from .guard import Guard
from .plant import HOLDING, NORMAL, TAGS, Plant, to_raw
from .proposals import Proposals

load_dotenv()
ROOT = Path(__file__).resolve().parents[1]
PLC_PORT = int(os.getenv("AEGIS_PLC_PORT", 5020))
GUARD_PORT = int(os.getenv("AEGIS_GUARD_PORT", 5502))
PIN = os.getenv("AEGIS_ENGINEER_PIN", "2468")

S: dict = {}
BASE_ORDERS = ["WO-4462: Replace filter #2 media, scheduled Thursday.",
               "WO-4468: Calibrate chlorine analyzer CL-1 (drifting +0.1 mg/L)."]


def need_pin(pin: str | None):
    if not pin or not hmac.compare_digest(str(pin), PIN):
        if "audit" in S:
            S["audit"].append("auth_failure", {"action": "engineer action", "t": time.time()})
        raise HTTPException(403, "Engineer PIN required")


@asynccontextmanager
async def lifespan(app: FastAPI):
    plant = Plant()
    audit = AuditLog()
    alerter = Alerter(audit)
    plc = await modbus.serve(plant.handle, "127.0.0.1", PLC_PORT)
    upstream = await modbus.Client("127.0.0.1", PLC_PORT).connect()
    guard = Guard(upstream, plant.snapshot, tags=TAGS, audit=audit, alerter=alerter, policy_path=POLICY_PATH)
    gsrv = await modbus.serve(guard.handle, "0.0.0.0", GUARD_PORT)
    orders = list(BASE_ORDERS)
    props = Proposals(guard, GUARD_PORT, audit=audit, alerter=alerter)
    S.update(plant=plant, guard=guard, audit=audit, alerter=alerter, orders=orders, proposals=props,
             autonomy="propose", verify={"ok": True, "entries": 0, "message": "", "t": 0})
    S["copilot"] = Copilot(plant, GUARD_PORT, orders, proposals=props, mode_getter=lambda: S["autonomy"])
    audit.append("startup", {"guard_port": GUARD_PORT, "plc_port": PLC_PORT})

    async def tick():
        seen: set[str] = set()
        while True:
            plant.step()
            now = set(plant.alarms())
            for a in now - seen:   # new process alarm -> alert the operator
                alerter.raise_alert(f"alarm:{a}", "critical" if a.startswith("pH") or "CHLORINE" in a else "warning",
                                    f"Process alarm {a}: pH {plant.ph:.2f}, chlorine {plant.chlorine:.2f} mg/L, "
                                    f"clearwell {plant.tank_level:.0f}%.")
            seen = now
            await asyncio.sleep(0.2)

    task = asyncio.create_task(tick())
    yield
    task.cancel(); plc.close(); gsrv.close()


app = FastAPI(title="Aegis", lifespan=lifespan)


@app.get("/")
def index():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/state")
def state():
    p, g = S["plant"], S["guard"]
    if time.time() - S["verify"]["t"] > 3:   # re-verify the audit chain every few seconds
        S["verify"] = {**S["audit"].verify(), "t": time.time()}
    return {"plant": p.snapshot(), "history": list(p.history)[::5][-120:], "guard_enabled": g.enabled,
            "log": [d.as_dict() for d in list(g.log)[:30]], "work_orders": S["orders"],
            "policy": g.policy, "alerts": list(S["alerter"].recent)[:15],
            "alerts_configured": S["alerter"].configured(), "proposals": S["proposals"].items[:15],
            "autonomy": S["autonomy"], "audit": S["verify"],
            "tags": {n: {"unit": t.unit, "label": t.label} for n, t in TAGS.holding.items()}}


class GuardIn(BaseModel):
    enabled: bool
    pin: str | None = None


@app.post("/api/guard")
def set_guard(body: GuardIn):
    need_pin(body.pin)
    S["guard"].set_enabled(body.enabled, by="engineer (dashboard)")
    return {"ok": True}


class PolicyIn(BaseModel):
    policy: dict
    pin: str | None = None


@app.post("/api/policy")
def set_policy(body: PolicyIn):
    need_pin(body.pin)
    try:
        S["guard"].set_policy(body.policy, by="engineer (dashboard)")
    except PolicyError as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


class SettingsIn(BaseModel):
    autonomy: str
    pin: str | None = None


@app.post("/api/settings")
def settings(body: SettingsIn):
    need_pin(body.pin)
    if body.autonomy not in ("propose", "direct"):
        raise HTTPException(400, "autonomy must be 'propose' or 'direct'")
    S["autonomy"] = body.autonomy
    S["audit"].append("settings", {"autonomy": body.autonomy, "by": "engineer (dashboard)"})
    return {"ok": True}


@app.post("/api/proposals/{pid}/approve")
async def approve(pid: int):
    try:
        return await S["proposals"].approve(pid, by="operator (dashboard)")
    except ValueError as e:
        raise HTTPException(409, str(e))


@app.post("/api/proposals/{pid}/reject")
def reject(pid: int):
    try:
        return S["proposals"].reject(pid, by="operator (dashboard)")
    except ValueError as e:
        raise HTTPException(409, str(e))


@app.get("/api/audit")
def audit(limit: int = 100):
    return {"verify": S["audit"].verify(), "entries": S["audit"].recent(min(limit, 1000))}


@app.get("/api/audit/export.csv")
def audit_csv():
    return PlainTextResponse(S["audit"].export_csv(), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=aegis-audit.csv"})


@app.post("/api/reset")
def reset():
    p, g = S["plant"], S["guard"]
    for k, v in NORMAL.items():
        p.hr[HOLDING[k]] = to_raw(k, v)
    p.ph, p.chlorine, p.tank_level = 7.0, 1.3, 60.0
    g.log.clear(); g._changes.clear(); g._attempts.clear()
    S["alerter"].recent.clear(); S["alerter"]._last.clear()
    S["proposals"].items.clear()
    S["orders"][:] = BASE_ORDERS
    S["audit"].append("demo_reset", {"note": "plant + dashboard reset; audit history kept"})
    return {"ok": True}


# ---------------- demo attacks (local simulator only) ----------------
@app.post("/api/attack/lye")
async def attack_lye():
    return {"result": await lye_attack(GUARD_PORT)}


@app.post("/api/attack/ramp")
async def attack_ramp():
    """Stealthy attacker: many small, individually-legal chlorine increases."""
    async def run():
        c = await modbus.Client("127.0.0.1", GUARD_PORT, unit=77).connect()
        try:
            for _ in range(6):
                cur = S["plant"].setpoint("chlorine_dose")
                try:
                    await c.write(HOLDING["chlorine_dose"], to_raw("chlorine_dose", round(cur + 0.4, 2)))
                except modbus.ModbusError:
                    pass
                await asyncio.sleep(1.2)
        finally:
            await c.close()
    asyncio.create_task(run())
    return {"result": "Stealth attacker started: +0.4 mg/L chlorine every 1.2 s (each step under the 0.5 limit)"}


@app.post("/api/attack/flood")
async def attack_flood():
    """Automated tool hammering the PLC with writes."""
    c = await modbus.Client("127.0.0.1", GUARD_PORT, unit=88).connect()
    ok = blocked = 0
    try:
        for _ in range(30):
            try:
                await c.write(HOLDING["intake_pump"], 1); ok += 1
            except modbus.ModbusError:
                blocked += 1
    finally:
        await c.close()
    return {"result": f"Flood: {ok} writes passed, {blocked} blocked after the per-minute limit"}


@app.post("/api/attack/plant-work-order")
def plant_injection():
    if INJECTION not in S["orders"]:
        S["orders"].append(INJECTION)
    return {"ok": True}


class SP(BaseModel):
    name: str
    value: float


@app.post("/api/operator/setpoint")
async def operator_setpoint(sp: SP):
    if sp.name not in HOLDING:
        raise HTTPException(400, "unknown setpoint")
    c = await modbus.Client("127.0.0.1", GUARD_PORT, unit=1).connect()
    try:
        await c.write(HOLDING[sp.name], max(0, min(65535, to_raw(sp.name, sp.value))))
        return {"result": "accepted"}
    except modbus.ModbusError:
        return {"result": "blocked", "reason": S["guard"].log[0].reason if S["guard"].log else ""}
    finally:
        await c.close()


class Msg(BaseModel):
    message: str


@app.post("/api/copilot")
async def copilot(m: Msg):
    try:
        return await S["copilot"].chat(m.message)
    except Exception as e:
        raise HTTPException(502, f"copilot error: {e}")


def main():
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=int(os.getenv("PORT", 8000)))


if __name__ == "__main__":
    main()
