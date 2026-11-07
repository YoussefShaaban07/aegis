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
from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse, HTMLResponse, PlainTextResponse
from pydantic import BaseModel

from . import attacks, modbus
from .alerts import Alerter
from .attacks import INJECTION
from .audit import AuditLog
from .auth import Auth, allowed
from .calibrate import fit as calibrate_fit
from .config import POLICY_PATH, PolicyError, verify_policy_file
from .copilot import Copilot
from .guard import MODES, Guard
from .forewarn import ForecastWatch
from .integrity import IntegrityMonitor
from .safehold import SafeHold
from .process import ProcessModel
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
DEMO = os.getenv("AEGIS_DEMO", "1") == "1"      # simulator controls + demo accounts
PLANT_NAME = os.getenv("AEGIS_PLANT_NAME", "Hattiesburg Water Treatment Plant #2 (simulated)")

S: dict = {}
BASE_ORDERS = ["WO-4462: Replace filter #2 media, scheduled Thursday.",
               "WO-4468: Calibrate chlorine analyzer CL-1 (drifting +0.1 mg/L)."]
HORIZONS = (10, 30, 60)   # simulated minutes ahead for the live accuracy score


COOKIE = "aegis_session"


def role(need: str, demo_only: bool = False):
    """Dependency: require a logged-in user with at least this role (and the CSRF header on writes)."""
    def dep(request: Request) -> dict:
        if request.method != "GET" and request.headers.get("x-aegis") != "1":
            raise HTTPException(403, "missing X-Aegis header (CSRF protection)")
        who = S["auth"].verify(request.cookies.get(COOKIE))
        if who is None:
            raise HTTPException(401, "please log in")
        if not allowed(who, need):
            S["audit"].append("auth_denied", {"user": who["user"], "role": who["role"], "needed": need,
                                              "path": request.url.path})
            raise HTTPException(403, f"needs the {need} role")
        if demo_only and not DEMO:
            raise HTTPException(404, "simulator controls are disabled (AEGIS_DEMO=0)")
        return who
    return dep


def _by(who: dict) -> str:
    return f"{who['user']} ({who['role']})"


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
    guard.sync_commanded(plant.snapshot())
    gsrv = await modbus.serve(guard.handle, "0.0.0.0", GUARD_PORT)
    orders = list(BASE_ORDERS)
    props = Proposals(guard, GUARD_PORT, audit=audit, alerter=alerter)
    S["auth"] = Auth(demo=DEMO)
    S.update(plant=plant, guard=guard, audit=audit, alerter=alerter, orders=orders, proposals=props, twin=twin,
             autonomy="propose", verify={"ok": True, "entries": 0, "message": "", "t": 0},
             accuracy=Accuracy(), forecast=None, attack_log=deque(maxlen=30), patient=None,
             integrity=IntegrityMonitor(ProcessModel(twin.model.params), alerter=alerter, audit=audit),
             forewarn=ForecastWatch(alerter, audit))
    S["safehold"] = SafeHold(guard)
    S["copilot"] = Copilot(plant, GUARD_PORT, orders, proposals=props, mode_getter=lambda: S["autonomy"], twin=twin,
                           context=lambda: {"guard_log": [d.as_dict() for d in list(S["guard"].log)[:30]],
                                            "integrity": {**S["integrity"].status,
                                                          "events": list(S["integrity"].events)[:5]},
                                            "forewarn": list(S["forewarn"].active.values())})
    S["copilot"].audit = audit
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
                    snap = plant.snapshot()
                    S["forecast"] = twin.forecast(snap, None, 360, every_min=10)
                    S["forewarn"].update(S["forecast"], snap)
                if n % 25 == 0:      # every 5 s: new accuracy sample, escalate unacknowledged incidents
                    S["accuracy"].predict(twin, plant)
                    alerter.tick()
                if n % 50 == 0:      # every 10 s: has someone edited the policy file behind Aegis's back?
                    guard.flush_suppressed()
                    ok, msg = verify_policy_file(POLICY_PATH)
                    S["policy_sig"] = {"ok": ok, "message": msg}
                    if not ok:
                        alerter.raise_alert("policy_tamper", "critical",
                                            f"Safety policy file on disk failed its integrity check: {msg}. Aegis "
                                            "keeps enforcing the last good policy it loaded.")
                S["accuracy"].score(plant)
                if n % 5 == 0:       # every simulated minute: is the process what the PLC claims?
                    snap = plant.snapshot()
                    S["integrity"].update(snap, plant.sim_time, guard.commanded)
                    twin.observe(snap, plant.sim_time)          # raw-water trend for forecasts
                    sh = S["safehold"]
                    sh.cfg.update({k: v for k, v in (guard.policy.get("safe_hold") or {}).items()})
                    act = sh.update(snap, plant.sim_time, sensors_trusted=S["integrity"].status.get("ok", True))
                    if act:                      # restore the earlier value through the PLC, then hold it
                        await upstream.write_tag(TAGS.holding[act["register"]], act["value"])
                        guard.apply_safe_hold(act)
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


@app.get("/operator")
def operator_view():
    """Phone-sized view for the on-call operator: is the water safe, what needs acknowledging."""
    return FileResponse(ROOT / "static" / "operator.html")


class LoginIn(BaseModel):
    username: str
    password: str


@app.post("/api/login")
def login(body: LoginIn, request: Request, response: Response):
    if request.headers.get("x-aegis") != "1":
        raise HTTPException(403, "missing X-Aegis header (CSRF protection)")
    ip = request.client.host if request.client else "?"
    token, msg = S["auth"].login(body.username, body.password, ip)
    S["audit"].append("login" if token else "login_failed", {"user": body.username, "ip": ip, "result": msg})
    if not token:
        raise HTTPException(429 if "too many" in msg else 401, msg)
    response.set_cookie(COOKIE, token, httponly=True, samesite="strict", max_age=8 * 3600,
                        secure=os.getenv("AEGIS_HTTPS") == "1")
    return S["auth"].verify(token) | {"demo": DEMO}


@app.post("/api/logout")
def logout(response: Response, who: dict = Depends(role("viewer"))):
    response.delete_cookie(COOKIE)
    S["audit"].append("logout", {"user": who["user"]})
    return {"ok": True}


@app.get("/api/me")
def me(who: dict = Depends(role("viewer"))):
    return who | {"demo": DEMO}


@app.get("/api/state")
def state(who: dict = Depends(role("viewer"))):
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
            "incidents": [i for i in S["alerter"].incidents if i["closed"] is None][:5],
            "notifications_sent": len(S["alerter"].notifications),
            "proposals": S["proposals"].items[:15], "autonomy": S["autonomy"], "audit": S["verify"],
            "latency": g.latency(), "counts": dict(g.counts), "policy_sig": S.get("policy_sig"), "accuracy": S["accuracy"].summary(),
            "integrity": {**S["integrity"].status, "events": list(S["integrity"].events)[:10]},
            "truth": p.truth() if p.compromise else None,
            "forewarn": list(S["forewarn"].active.values()),
            "holds": [{"register": r, **{k: v for k, v in h.items() if k != "until"},
                       "remaining_min": round((h["until"] - g.clock()) / 60)} for r, h in g.holds.items()],
            "safe_hold": {"enabled": S["safehold"].enabled, "standing_down": S["safehold"].standing_down,
                          "after_min": S["safehold"].cfg["after_min"], "actions": S["safehold"].actions[-5:]},
            "attack_log": list(S["attack_log"]), "patient_running": bool(S["patient"] and not S["patient"].done()),
            "tags": {n: {"unit": t.unit, "label": t.label, "table": t.table} for n, t in TAGS.holding.items()},
            "llm": bool(os.getenv("GROQ_API_KEY") or os.getenv("AEGIS_LLM_KEY"))}


class ModeIn(BaseModel):
    mode: str
    pin: str | None = None


@app.post("/api/mode")
def set_mode(body: ModeIn, who: dict = Depends(role("engineer"))):
    need_pin(body.pin, "change guard mode")
    if body.mode not in MODES:
        raise HTTPException(400, f"mode must be one of {MODES}")
    S["guard"].set_mode(body.mode, by=_by(who))
    return {"ok": True}


class GuardIn(BaseModel):
    enabled: bool
    pin: str | None = None


@app.post("/api/guard")
def set_guard(body: GuardIn, who: dict = Depends(role("engineer"))):
    need_pin(body.pin, "toggle guard")
    S["guard"].set_enabled(body.enabled, by=_by(who))
    return {"ok": True}


class PolicyIn(BaseModel):
    policy: dict
    pin: str | None = None


@app.post("/api/policy")
def set_policy(body: PolicyIn, who: dict = Depends(role("engineer"))):
    need_pin(body.pin, "edit safety rules")
    try:
        S["guard"].set_policy(body.policy, by=_by(who))
    except PolicyError as e:
        raise HTTPException(400, str(e))
    return {"ok": True}


class SettingsIn(BaseModel):
    autonomy: str
    pin: str | None = None


@app.post("/api/settings")
def settings(body: SettingsIn, who: dict = Depends(role("engineer"))):
    need_pin(body.pin, "change AI autonomy")
    if body.autonomy not in ("propose", "direct"):
        raise HTTPException(400, "autonomy must be 'propose' or 'direct'")
    S["autonomy"] = body.autonomy
    S["audit"].append("settings", {"autonomy": body.autonomy, "by": _by(who)})
    return {"ok": True}


@app.post("/api/proposals/{pid}/approve")
async def approve(pid: int, who: dict = Depends(role("operator"))):
    try:
        return await S["proposals"].approve(pid, by=_by(who))
    except ValueError as e:
        raise HTTPException(409, str(e))


@app.post("/api/proposals/{pid}/reject")
def reject(pid: int, who: dict = Depends(role("operator"))):
    try:
        return S["proposals"].reject(pid, by=_by(who))
    except ValueError as e:
        raise HTTPException(409, str(e))


@app.post("/api/incidents/{iid}/ack")
def ack_incident(iid: int, who: dict = Depends(role("operator"))):
    try:
        return S["alerter"].ack(iid, by=_by(who))
    except ValueError as e:
        raise HTTPException(404, str(e))


@app.get("/api/audit")
def audit(limit: int = 100, who: dict = Depends(role("viewer"))):
    return {"verify": S["audit"].verify(), "entries": S["audit"].recent(min(limit, 1000))}


@app.get("/api/audit/export.csv")
def audit_csv(who: dict = Depends(role("viewer"))):
    return PlainTextResponse(S["audit"].export_csv(), media_type="text/csv",
                             headers={"Content-Disposition": "attachment; filename=aegis-audit.csv"})


def _report(minutes: float):
    until = time.time()
    since = until - minutes * 60
    a = S["audit"]
    return build_report(a.between(since, until), a.verify(), a.head(), PLANT_NAME, since, until)


@app.get("/api/report", response_class=HTMLResponse)
def report_html(minutes: float = 60, who: dict = Depends(role("viewer"))):
    return HTMLResponse(_report(minutes)["html"])


@app.get("/api/report.md")
def report_md(minutes: float = 60, who: dict = Depends(role("viewer"))):
    return PlainTextResponse(_report(minutes)["markdown"], media_type="text/markdown",
                             headers={"Content-Disposition": "attachment; filename=aegis-incident-report.md"})


@app.get("/api/learn")
def learn(hours: float = 168, simulated: bool = False, who: dict = Depends(role("viewer"))):
    if simulated:
        obs, label = simulated_week(start=time.time() - 7 * 86400), "SIMULATED week of operator activity (demo data)"
    else:
        obs = observations_from_audit(S["audit"].between(time.time() - hours * 3600, kinds=("decision",)))
        label = f"writes recorded in the audit log over the last {hours:g} h"
    return {**suggest(obs, S["guard"].policy), "source": label}


@app.get("/api/calibrate")
def calibrate_preview(who: dict = Depends(role("engineer"))):
    """Fit the twin to the plant's recent history (doesn't change anything yet)."""
    hist = list(S["plant"].history)
    try:
        r = calibrate_fit(hist, S["twin"].model.params)
    except ValueError as e:
        raise HTTPException(400, str(e))
    cur = {k: S["twin"].model.params[k] for k in r["params"]}
    r["warnings"] = calibration_warnings(cur, r["params"], S["integrity"])
    S["calibration"] = r
    return {k: r[k] for k in ("params", "before", "after", "rows", "warnings")} | {"current": cur}


def calibration_warnings(cur: dict, new: dict, integrity) -> list[str]:
    """Calibrating on data recorded during an attack would teach the twin that the attack is normal."""
    w = []
    if integrity.events or not integrity.status.get("ok", True):
        w.append("Integrity alarms are active: the history may include an attack or a failed instrument. "
                 "Calibrating now could teach the twin that the attack is normal. Resolve the alarm first.")
    for k, v in new.items():
        if cur.get(k) and abs(v - cur[k]) / cur[k] > 0.25:
            w.append(f"{k} would change by {100 * (v - cur[k]) / cur[k]:+.0f}%. Physical plants don't drift that "
                     "fast; check the chemical feed and the instruments before accepting.")
    return w


class PinIn(BaseModel):
    pin: str | None = None


@app.post("/api/calibrate/apply")
def calibrate_apply(body: PinIn, who: dict = Depends(role("engineer"))):
    need_pin(body.pin, "apply twin calibration")
    r = S.get("calibration")
    if not r:
        raise HTTPException(409, "run a calibration first")
    if r.get("warnings"):
        raise HTTPException(409, "not applied: " + " ".join(r["warnings"]))
    old = {k: S["twin"].model.params[k] for k in r["params"]}
    S["twin"].model.params.update(r["params"])
    S["twin"].set_uncertainty(S["twin"].uncertainty)        # rebuild the ensemble around the new values
    S["integrity"].model.params.update(r["params"])
    S["audit"].append("twin_calibration", {"old": old, "new": r["params"], "before": r["before"],
                                           "after": r["after"], "by": _by(who)})
    return {"ok": True, "params": r["params"]}


class WhatIf(BaseModel):
    name: str
    value: float
    hours: float = 6


@app.post("/api/whatif")
def whatif(w: WhatIf, who: dict = Depends(role("operator"))):
    if w.name not in HOLDING:
        raise HTTPException(400, "unknown setpoint")
    v = S["twin"].evaluate(S["plant"].snapshot(), w.name, w.value, max(1, min(12, w.hours)) * 60)
    return {"allowed": v.allowed, "reason": v.reason, "forecast": v.forecast}


@app.post("/api/scenario/{name}")
def scenario(name: str, who: dict = Depends(role("operator", demo_only=True))):
    if name not in SCENARIOS:
        raise HTTPException(400, f"scenario must be one of {list(SCENARIOS)}")
    S["plant"].set_scenario(name)
    S["audit"].append("scenario", {"scenario": name, "note": "simulator weather change"})
    return {"ok": True}


@app.post("/api/reset")
def reset(who: dict = Depends(role("operator", demo_only=True))):
    p, g = S["plant"], S["guard"]
    p.reset()
    g.log.clear(); g._changes.clear(); g._attempts.clear(); g._dirs.clear(); g._big_dirs.clear(); g.counts.clear()
    S["alerter"].recent.clear(); S["alerter"]._last.clear(); S["alerter"].incidents.clear()
    S["proposals"].items.clear()
    S["orders"][:] = BASE_ORDERS
    S["attack_log"].clear()
    S["accuracy"].pending.clear()
    g.commanded.clear(); g.sync_commanded(p.snapshot()); g.permits.clear()
    S["integrity"] = IntegrityMonitor(ProcessModel(S["twin"].model.params), alerter=S["alerter"], audit=S["audit"])
    S["forewarn"] = ForecastWatch(S["alerter"], S["audit"])
    if S.get("patient"):
        S["patient"].cancel()
    S["audit"].append("demo_reset", {"note": "plant + dashboard reset; audit history kept", "by": _by(who)})
    return {"ok": True}


# ---------------- demo attacks (local simulator only, from 127.0.0.66) ----------------
def _alog(name: str, result: str):
    S["attack_log"].appendleft({"t": time.time(), "attack": name, "result": result})
    return {"result": result}


@app.post("/api/attack/lye")
async def attack_lye(who: dict = Depends(role("operator", demo_only=True))):
    return _alog("Oldsmar-style lye 11,100 ppm (FC 6)", await attacks.lye_attack(GUARD_PORT))


@app.post("/api/attack/mask")
async def attack_mask(who: dict = Depends(role("operator", demo_only=True))):
    return _alog("lye via Mask Write (FC 22)", await attacks.mask_attack(GUARD_PORT))


@app.post("/api/attack/readwrite")
async def attack_readwrite(who: dict = Depends(role("operator", demo_only=True))):
    return _alog("lye via Read/Write Multiple (FC 23)", await attacks.readwrite_attack(GUARD_PORT))


@app.post("/api/attack/coil")
async def attack_coil(who: dict = Depends(role("operator", demo_only=True))):
    return _alog("stop distribution pump (FC 5)", await attacks.coil_attack(GUARD_PORT))


@app.post("/api/attack/recon")
async def attack_recon(who: dict = Depends(role("operator", demo_only=True))):
    return _alog("recon + force listen-only (FC 43, FC 8)", await attacks.recon_attack(GUARD_PORT))


@app.post("/api/attack/ramp")
async def attack_ramp(who: dict = Depends(role("operator", demo_only=True))):
    async def run():
        out = await attacks.ramp_attack(GUARD_PORT, lambda: S["plant"].setpoint("chlorine_dose"))
        _alog("stealth chlorine ramp", "; ".join(out))
    asyncio.create_task(run())
    return _alog("stealth chlorine ramp", "started: +0.4 mg/L every 1.2 s (each step under the 0.5 limit)")


@app.post("/api/attack/flood")
async def attack_flood(who: dict = Depends(role("operator", demo_only=True))):
    ok, blocked = await attacks.flood_attack(GUARD_PORT)
    return _alog("flood, rotating unit IDs", f"Flood: {ok} writes passed, {blocked} blocked after the per-minute limit")


@app.post("/api/attack/patient")
async def attack_patient(who: dict = Depends(role("operator", demo_only=True))):
    if S.get("patient") and not S["patient"].done():
        return {"result": "already running"}

    async def run():
        await attacks.patient_attack(GUARD_PORT, lambda: S["plant"].setpoint("naoh_dose"),
                                     log=lambda line: _alog("patient attacker (+50 lye every 61 s)", line))
    S["patient"] = asyncio.create_task(run())
    return _alog("patient attacker (+50 lye every 61 s)",
                 "started: each step passes range, step and ramp rules; next step in 61 s")


class Compromise(BaseModel):
    freeze_sensors: bool = False


@app.post("/api/attack/plc-compromise")
def plc_compromise(body: Compromise, who: dict = Depends(role("operator", demo_only=True))):
    """Simulator only: malware inside the PLC doses lye 200 ppm while the registers keep saying 100."""
    S["plant"].compromise_plc({"naoh_dose": 200}, freeze_sensors=body.freeze_sensors)
    what = "and replays frozen normal pH/chlorine readings" if body.freeze_sensors else "(sensors left alone)"
    return _alog("compromised PLC (Stuxnet-style)", f"PLC now doses lye 200 ppm while reporting 100 {what}. "
                 "No command passed through Aegis.")


class Speed(BaseModel):
    speed: float


@app.post("/api/sim/speed")
def sim_speed(body: Speed, who: dict = Depends(role("operator", demo_only=True))):
    """Simulator only: fast-forward slow chemistry during a demo (1x-1200x)."""
    S["plant"].speed = max(1.0, min(1200.0, body.speed))
    return {"speed": S["plant"].speed}


class Grab(BaseModel):
    ph: float | None = None
    chlorine: float | None = None


@app.post("/api/grab")
def grab(g: Grab, who: dict = Depends(role("operator"))):
    return S["integrity"].grab_sample(S["plant"].snapshot(), g.ph, g.chlorine, by=_by(who))


@app.post("/api/attack/plant-work-order")
def plant_injection(who: dict = Depends(role("operator", demo_only=True))):
    if INJECTION not in S["orders"]:
        S["orders"].append(INJECTION)
    return {"ok": True}


class SP(BaseModel):
    name: str
    value: float


@app.post("/api/operator/setpoint")
async def operator_setpoint(sp: SP, who: dict = Depends(role("operator"))):
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
def permit(body: PermitIn, who: dict = Depends(role("operator"))):
    try:
        return S["guard"].issue_permit(body.name, body.value, max(1, min(60, body.minutes)), by=_by(who))
    except ValueError as e:
        raise HTTPException(400, str(e))


class HoldIn(BaseModel):
    name: str


@app.post("/api/hold/release")
def release_hold(body: HoldIn, who: dict = Depends(role("operator"))):
    """Releasing a safe-hold needs a login: a Modbus packet (or a hijacked HMI) can't do it."""
    if not S["guard"].release_hold(body.name, by=_by(who)):
        raise HTTPException(404, f"{body.name} is not held")
    return {"released": body.name}


class Msg(BaseModel):
    message: str


@app.post("/api/copilot")
async def copilot(m: Msg, who: dict = Depends(role("operator"))):
    try:
        return await S["copilot"].chat(m.message)
    except Exception as e:
        raise HTTPException(502, f"copilot error: {e}")


def main():
    import uvicorn
    print(f"Aegis dashboard: http://127.0.0.1:{os.getenv('PORT', 8000)}   operator view: /operator")
    print(f"Guarded Modbus port (attack it from another terminal or device): {GUARD_PORT} on all interfaces")
    uvicorn.run(app, host=os.getenv("AEGIS_HOST", "127.0.0.1"), port=int(os.getenv("PORT", 8000)))


if __name__ == "__main__":
    main()
