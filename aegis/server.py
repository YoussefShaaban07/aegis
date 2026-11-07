"""Runs everything: plant physics, PLC (Modbus), Aegis guard (Modbus), web HMI.

    python -m aegis.server        then open http://127.0.0.1:8000

Ports: PLC 5020 (internal), guard 5502 (the plant's "exposed" Modbus port).
Engineer actions (guard mode, editing rules, AI autonomy) need AEGIS_ENGINEER_PIN.
"""
from __future__ import annotations

import asyncio
import hmac
import os
import time
from collections import deque
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from . import attacks, modbus
from .alerts import Alerter
from .attacks import INJECTION
from .audit import AuditLog
from .config import POLICY_PATH, PolicyError
from .copilot import Copilot
from .guard import MODES, Guard
from .learn import observations_from_audit, simulated_week, suggest
from .plant import HOLDING, SCENARIOS, TAGS, Plant
from .proposals import Proposals
from .report import build as build_report
from .twin import Twin

load_dotenv()
ROOT = Path(__file__).resolve().parents[1]
PLC_PORT = int(os.getenv("AEGIS_PLC_PORT", 5020))
GUARD_PORT = int(os.getenv("AEGIS_GUARD_PORT", 5502))
PIN = os.getenv("AEGIS_ENGINEER_PIN", "2468")
PLANT_NAME = os.getenv("AEGIS_PLANT_NAME", "Hattiesburg Water Treatment Plant #2 (simulated)")

S: dict = {}
BASE_ORDERS = ["WO-4462: Replace filter #2 media, scheduled Thursday.",
               "WO-4468: Calibrate chlorine analyzer CL-1 (drifting +0.1 mg/L)."]
HORIZONS = (10, 30, 60)   # simulated minutes ahead for the live accuracy score


def need_pin(pin: str | None, action: str = "engineer action"):
    if not pin or not hmac.compare_digest(str(pin), PIN):
        if "audit" in S:
            S["audit"].append("auth_failure", {"action": action, "t": time.time()})
        raise HTTPException(403, "Engineer PIN required")


class Accuracy:
    """Scores the twin against the simulator: forecast now, compare when due.

    A forecast assumes nobody touches the setpoints; if they change before the
    forecast comes due, that sample is skipped (it would measure the operator,
    not the model)."""

    def __init__(self):
        self.pending: list[dict] = []
        self.errors = {h: {"ph": deque(maxlen=200), "cl": deque(maxlen=200)} for h in HORIZONS}
        self.skipped = 0

    def predict(self, twin: Twin, plant: Plant):
        st = plant.snapshot()
        fc = twin.forecast(st, None, max(HORIZONS), every_min=10)
        sp = plant.setpoints()
        for pt in fc:
            if pt["min"] in HORIZONS:
                self.pending.append({"due": plant.sim_time + pt["min"] * 60, "h": pt["min"], "ph": pt["ph"],
                                     "cl": pt["chlorine_residual"], "sp": sp})

    def score(self, plant: Plant):
        now, keep = plant.sim_time, []
        for p in self.pending:
            if now < p["due"]:
                keep.append(p)
            elif p["sp"] != plant.setpoints():
                self.skipped += 1
            else:
                s = plant.sensors()
                self.errors[p["h"]]["ph"].append(abs(p["ph"] - s["ph"]))
                self.errors[p["h"]]["cl"].append(abs(p["cl"] - s["chlorine_residual"]))
        self.pending = keep

    def summary(self) -> dict:
        out = {}
        for h, e in self.errors.items():
            n = len(e["ph"])
            out[str(h)] = {"n": n, "ph_mae": round(sum(e["ph"]) / n, 3) if n else None,
                           "cl_mae": round(sum(e["cl"]) / n, 3) if n else None}
        return {"by_horizon_min": out, "skipped": self.skipped}


@asynccontextmanager
async def lifespan(app: FastAPI):
    plant = Plant()
    audit = AuditLog()
    alerter = Alerter(audit)
    twin = Twin()
    plc = await modbus.serve(plant.handle, "127.0.0.1", PLC_PORT)
    upstream = modbus.Client("127.0.0.1", PLC_PORT)
    guard = Guard(upstream, plant.snapshot, tags=TAGS, audit=audit, alerter=alerter, policy_path=POLICY_PATH,
                  twin=twin)
    guard.trusted_ips = {"127.0.0.1"}   # HMI + AI live here; demo attackers come from 127.0.0.66
    gsrv = await modbus.serve(guard.handle, "0.0.0.0", GUARD_PORT)
    orders = list(BASE_ORDERS)
    props = Proposals(guard, GUARD_PORT, audit=audit, alerter=alerter)
    S.update(plant=plant, guard=guard, audit=audit, alerter=alerter, orders=orders, proposals=props, twin=twin,
             autonomy="propose", verify={"ok": True, "entries": 0, "message": "", "t": 0},
             accuracy=Accuracy(), forecast=None, attack_log=deque(maxlen=30), patient=None)
    S["copilot"] = Copilot(plant, GUARD_PORT, orders, proposals=props, mode_getter=lambda: S["autonomy"], twin=twin)
    audit.append("startup", {"guard_port": GUARD_PORT, "plc_port": PLC_PORT, "plant": PLANT_NAME})

    async def tick():
        seen: set[str] = set()
        n = 0
        while True:
            try:
                plant.step()
                now = set(plant.alarms())
                for a in now - seen:   # new process alarm -> alert the operator
                    alerter.raise_alert(f"alarm:{a}", "critical" if a.startswith("pH") or "CHLORINE" in a else "warning",
                                        f"Process alarm {a}: pH {plant.ph:.2f}, chlorine {plant.chlorine:.2f} mg/L, "
                                        f"clearwell {plant.tank_level:.0f}%.")
                seen = now
                if n % 10 == 0:      # every 2 s: refresh the forecast shown on the trend chart
                    S["forecast"] = twin.forecast(plant.snapshot(), None, 360, every_min=10)
                if n % 25 == 0:      # every 5 s: new accuracy sample
                    S["accuracy"].predict(twin, plant)
                S["accuracy"].score(plant)
            except Exception as e:   # the sim loop must never die silently
                print("tick error:", e)
            n += 1
            await asyncio.sleep(0.2)

    task = asyncio.create_task(tick())
    yield
    task.cancel(); plc.close(); gsrv.close()
    if S.get("patient"):
        S["patient"].cancel()


app = FastAPI(title="Aegis", lifespan=lifespan)


@app.get("/")
def index():
    return FileResponse(ROOT / "static" / "index.html")


@app.get("/api/state")
def state():
    p, g = S["plant"], S["guard"]
    if time.time() - S["verify"]["t"] > 3:   # re-verify the audit chain every few seconds
        S["verify"] = {**S["audit"].verify(), "t": time.time()}
    hist = list(p.history)[::2][-240:]
    log = [d.as_dict(forecast=(i == 0 and d.check == "predict")) for i, d in enumerate(list(g.log)[:40])]
    return {"plant": p.snapshot(), "history": [{k: h[k] for k in ("sim_t", "ph", "chlorine_residual", "hocl_pct",
                                                                  "naoh_dose", "chlorine_dose")} for h in hist],
            "forecast": S["forecast"], "sim_t": p.sim_time, "speed": p.speed,
            "guard_mode": g.mode, "guard_enabled": g.enabled,
            "log": log, "work_orders": S["orders"], "policy": g.policy,
            "alerts": list(S["alerter"].recent)[:20], "alerts_configured": S["alerter"].configured(),
            "proposals": S["proposals"].items[:15], "autonomy": S["autonomy"], "audit": S["verify"],
            "latency": g.latency(), "counts": dict(g.counts), "accuracy": S["accuracy"].summary(),
            "attack_log": list(S["attack_log"]), "patient_running": bool(S["patient"] and not S["patient"].done()),
            "tags": {n: {"unit": t.unit, "label": t.label, "table": t.table} for n, t in TAGS.holding.items()},
            "llm": bool(os.getenv("GROQ_API_KEY") or os.getenv("AEGIS_LLM_KEY"))}


class ModeIn(BaseModel):
    mode: str
    pin: str | None = None


@app.post("/api/mode")
def set_mode(body: ModeIn):
    need_pin(body.pin, "change guard mode")
    if body.mode not in MODES:
        raise HTTPException(400, f"mode must be one of {MODES}")
    S["guard"].set_mode(body.mode, by="engineer (dashboard)")
    return {"ok": True}


class GuardIn(BaseModel):
    enabled: bool
    pin: str | None = None


@app.post("/api/guard")
def set_guard(body: GuardIn):
    need_pin(body.pin, "toggle guard")
    S["guard"].set_enabled(body.enabled, by="engineer (dashboard)")
    return {"ok": True}


class PolicyIn(BaseModel):
    policy: dict
    pin: str | None = None


@app.post("/api/policy")
def set_policy(body: PolicyIn):
    need_pin(body.pin, "edit safety rules")
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
    need_pin(body.pin, "change AI autonomy")
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


def _report(minutes: float):
    until = time.time()
    since = until - minutes * 60
    a = S["audit"]
    return build_report(a.between(since, until), a.verify(), a.head(), PLANT_NAME, since, until)


@app.get("/api/report", response_class=HTMLResponse)
def report_html(minutes: float = 60):
    return HTMLResponse(_report(minutes)["html"])


@app.get("/api/report.md")
def report_md(minutes: float = 60):
    return PlainTextResponse(_report(minutes)["markdown"], media_type="text/markdown",
                             headers={"Content-Disposition": "attachment; filename=aegis-incident-report.md"})


@app.get("/api/learn")
def learn(hours: float = 168, simulated: bool = False):
    if simulated:
        obs, label = simulated_week(start=time.time() - 7 * 86400), "SIMULATED week of operator activity (demo data)"
    else:
        obs = observations_from_audit(S["audit"].between(time.time() - hours * 3600, kinds=("decision",)))
        label = f"writes recorded in the audit log over the last {hours:g} h"
    return {**suggest(obs, S["guard"].policy), "source": label}


class WhatIf(BaseModel):
    name: str
    value: float
    hours: float = 6


@app.post("/api/whatif")
def whatif(w: WhatIf):
    if w.name not in HOLDING:
        raise HTTPException(400, "unknown setpoint")
    v = S["twin"].evaluate(S["plant"].snapshot(), w.name, w.value, max(1, min(12, w.hours)) * 60)
    return {"allowed": v.allowed, "reason": v.reason, "forecast": v.forecast}


@app.post("/api/scenario/{name}")
def scenario(name: str):
    if name not in SCENARIOS:
        raise HTTPException(400, f"scenario must be one of {list(SCENARIOS)}")
    S["plant"].set_scenario(name)
    S["audit"].append("scenario", {"scenario": name, "note": "simulator weather change"})
    return {"ok": True}


@app.post("/api/reset")
def reset():
    p, g = S["plant"], S["guard"]
    p.reset()
    g.log.clear(); g._changes.clear(); g._attempts.clear(); g.counts.clear()
    S["alerter"].recent.clear(); S["alerter"]._last.clear()
    S["proposals"].items.clear()
    S["orders"][:] = BASE_ORDERS
    S["attack_log"].clear()
    S["accuracy"].pending.clear()
    if S.get("patient"):
        S["patient"].cancel()
    S["audit"].append("demo_reset", {"note": "plant + dashboard reset; audit history kept"})
    return {"ok": True}


# ---------------- demo attacks (local simulator only, from 127.0.0.66) ----------------
def _alog(name: str, result: str):
    S["attack_log"].appendleft({"t": time.time(), "attack": name, "result": result})
    return {"result": result}


@app.post("/api/attack/lye")
async def attack_lye():
    return _alog("Oldsmar-style lye 11,100 ppm (FC 6)", await attacks.lye_attack(GUARD_PORT))


@app.post("/api/attack/mask")
async def attack_mask():
    return _alog("lye via Mask Write (FC 22)", await attacks.mask_attack(GUARD_PORT))


@app.post("/api/attack/readwrite")
async def attack_readwrite():
    return _alog("lye via Read/Write Multiple (FC 23)", await attacks.readwrite_attack(GUARD_PORT))


@app.post("/api/attack/coil")
async def attack_coil():
    return _alog("stop distribution pump (FC 5)", await attacks.coil_attack(GUARD_PORT))


@app.post("/api/attack/recon")
async def attack_recon():
    return _alog("recon + force listen-only (FC 43, FC 8)", await attacks.recon_attack(GUARD_PORT))


@app.post("/api/attack/ramp")
async def attack_ramp():
    async def run():
        out = await attacks.ramp_attack(GUARD_PORT, lambda: S["plant"].setpoint("chlorine_dose"))
        _alog("stealth chlorine ramp", "; ".join(out))
    asyncio.create_task(run())
    return _alog("stealth chlorine ramp", "started: +0.4 mg/L every 1.2 s (each step under the 0.5 limit)")


@app.post("/api/attack/flood")
async def attack_flood():
    ok, blocked = await attacks.flood_attack(GUARD_PORT)
    return _alog("flood, rotating unit IDs", f"Flood: {ok} writes passed, {blocked} blocked after the per-minute limit")


@app.post("/api/attack/patient")
async def attack_patient():
    if S.get("patient") and not S["patient"].done():
        return {"result": "already running"}

    async def run():
        await attacks.patient_attack(GUARD_PORT, lambda: S["plant"].setpoint("naoh_dose"),
                                     log=lambda line: _alog("patient attacker (+50 lye every 61 s)", line))
    S["patient"] = asyncio.create_task(run())
    return _alog("patient attacker (+50 lye every 61 s)",
                 "started: each step passes range, step and ramp rules; next step in 61 s")


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
        await c.write_tag(TAGS.holding[sp.name], sp.value)
        d = S["guard"].log[0] if S["guard"].log else None
        return {"result": "accepted", "reason": d.reason if d else ""}
    except modbus.ModbusError:
        return {"result": "blocked", "reason": S["guard"].log[0].reason if S["guard"].log else ""}
    finally:
        await c.close()


class PermitIn(BaseModel):
    name: str
    value: float
    minutes: float = 10
    pin: str | None = None


@app.post("/api/permit")
def permit(body: PermitIn):
    need_pin(body.pin, "issue command permit")
    try:
        return S["guard"].issue_permit(body.name, body.value, max(1, min(60, body.minutes)), by="operator (dashboard)")
    except ValueError as e:
        raise HTTPException(400, str(e))


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
    uvicorn.run(app, host=os.getenv("AEGIS_HOST", "127.0.0.1"), port=int(os.getenv("PORT", 8000)))


if __name__ == "__main__":
    main()
