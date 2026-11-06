"""Runs everything: plant physics, PLC (Modbus), Aegis guard (Modbus), web HMI.

    python -m aegis.server        then open http://127.0.0.1:8000

Ports: PLC 5020 (internal), guard 5502 (the plant's "exposed" Modbus port).
"""
from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from . import modbus
from .attacks import INJECTION, lye_attack
from .copilot import Copilot
from .guard import POLICY, Guard
from .plant import HOLDING, NORMAL, Plant, to_raw

load_dotenv()
ROOT = Path(__file__).resolve().parents[1]
PLC_PORT = int(os.getenv("AEGIS_PLC_PORT", 5020))
GUARD_PORT = int(os.getenv("AEGIS_GUARD_PORT", 5502))

STATE: dict = {}
BASE_ORDERS = ["WO-4462: Replace filter #2 media, scheduled Thursday.",
               "WO-4468: Calibrate chlorine analyzer CL-1 (drifting +0.1 mg/L)."]


@asynccontextmanager
async def lifespan(app: FastAPI):
    plant = Plant()
    plc = await modbus.serve(plant.handle, "127.0.0.1", PLC_PORT)
    upstream = await modbus.Client("127.0.0.1", PLC_PORT).connect()
    guard = Guard(upstream, plant.snapshot)
    gsrv = await modbus.serve(guard.handle, "0.0.0.0", GUARD_PORT)
    orders = list(BASE_ORDERS)

    async def tick():
        while True:
            plant.step()
            await asyncio.sleep(0.2)

    task = asyncio.create_task(tick())
    STATE.update(plant=plant, guard=guard, orders=orders,
                 copilot=Copilot(plant, GUARD_PORT, orders))
    yield
    task.cancel(); plc.close(); gsrv.close()


app = FastAPI(title="Aegis", lifespan=lifespan)


@app.get("/")
def index():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/state")
def state():
    p, g = STATE["plant"], STATE["guard"]
    hist = list(p.history)[::5][-120:]
    return {"plant": p.snapshot(), "history": hist, "guard_enabled": g.enabled,
            "log": [d.as_dict() for d in list(g.log)[:30]], "work_orders": STATE["orders"],
            "policy": {k: v.__dict__ for k, v in POLICY.items()}}


class Toggle(BaseModel):
    enabled: bool


@app.post("/api/guard")
def set_guard(t: Toggle):
    STATE["guard"].enabled = t.enabled
    return {"ok": True}


@app.post("/api/reset")
def reset():
    p = STATE["plant"]
    for k, v in NORMAL.items():
        p.hr[HOLDING[k]] = to_raw(k, v)
    p.ph, p.chlorine, p.tank_level = 7.0, 1.3, 60.0
    STATE["guard"].log.clear()
    STATE["orders"][:] = BASE_ORDERS
    return {"ok": True}


@app.post("/api/attack/lye")
async def attack_lye():
    return {"result": await lye_attack(GUARD_PORT)}


@app.post("/api/attack/plant-work-order")
def plant_injection():
    if INJECTION not in STATE["orders"]:
        STATE["orders"].append(INJECTION)
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
        return {"result": "blocked"}
    finally:
        await c.close()


class Msg(BaseModel):
    message: str


@app.post("/api/copilot")
async def copilot(m: Msg):
    try:
        return await STATE["copilot"].chat(m.message)
    except Exception as e:
        raise HTTPException(502, f"copilot error: {e}")


def main():
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=int(os.getenv("PORT", 8000)))


if __name__ == "__main__":
    main()
