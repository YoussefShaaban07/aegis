"""Process integrity: catch a PLC that lies (or was changed behind Aegis's back).

The guard only sees commands that pass through it. A compromised PLC (the
Stuxnet pattern) can change its own dosing and report normal values. Three
independent checks, from weakest to strongest assumption:

1. Setpoint drift. Aegis knows every setpoint it allowed. If the PLC reports a
   setpoint Aegis never approved, something changed it locally (front-panel,
   engineering laptop, or malware). Catches attackers who don't hide the setpoint.

2. Physics shadow. A copy of the process model runs open-loop from a trusted
   anchor, driven by the setpoints Aegis approved and the raw-water sensors.
   If measured pH/chlorine drift away from what the chemistry allows (beyond
   model error), the dosing isn't what the PLC claims. Catches attackers who
   hide the setpoint but leave the real sensors alone.

3. Lab grab samples. Operators already take grab samples for compliance. Type
   the lab value in; if the PLC-reported reading disagrees, the sensor path is
   lying. The only check here that catches a full Stuxnet-style replay, because
   it's the only measurement that doesn't come through the PLC.

What it can't do: if the attacker fakes setpoints AND sensors consistently, and
nobody takes a grab sample, nothing that reads only from the PLC can tell.
"""
from __future__ import annotations

from collections import deque

from .process import ProcessModel, ProcessState, Raw

SETPOINTS = ("intake_pump", "distribution_pump", "chlorine_dose", "naoh_dose", "distribution_rate")


class IntegrityMonitor:
    def __init__(self, model: ProcessModel | None, ph_tol: float = 0.2, cl_tol: float = 0.25, persist: int = 3,
                 reanchor_s: float = 3600, alerter=None, audit=None, sp_tol: float = 1e-6):
        self.model = model
        self.ph_tol, self.cl_tol, self.persist, self.reanchor_s = ph_tol, cl_tol, persist, reanchor_s
        self.alerter, self.audit = alerter, audit
        self.sp_tol = sp_tol
        self.shadow: ProcessState | None = None
        self.anchor_t = None
        self.last_t = None
        self.strikes = 0
        self.status = {"ok": True, "message": "starting", "ph_err": None, "cl_err": None}
        self.events: deque = deque(maxlen=50)
        self._flagged: set[str] = set()

    # ---------------------------------------------------------------- helpers
    def _event(self, key: str, severity: str, message: str, data: dict):
        if key in self._flagged:
            return
        self._flagged.add(key)
        ev = {"key": key, "severity": severity, "message": message, **data}
        self.events.appendleft(ev)
        if self.audit:
            self.audit.append("integrity", ev)
        if self.alerter:
            self.alerter.raise_alert(f"integrity:{key}", severity, message)

    def _anchor(self, state: dict, t: float):
        raw = Raw(state["raw_ph"], state["raw_alkalinity"], state["raw_turbidity"])
        self.shadow = self.model.estimate(state, raw)
        self.anchor_t = t
        self.strikes = 0

    # ---------------------------------------------------------------- checks
    def check_setpoints(self, reported: dict, commanded: dict) -> list[str]:
        out = []
        for k in SETPOINTS:
            if k in commanded and k in reported and abs(float(reported[k]) - float(commanded[k])) > self.sp_tol:
                out.append(k)
                self._event(f"setpoint:{k}:{reported[k]}", "critical",
                            f"PLC reports {k} = {reported[k]:g} but the last value Aegis approved was "
                            f"{commanded[k]:g}. Something changed it without going through Aegis "
                            "(front panel, engineering laptop, or a compromised PLC).",
                            {"register": k, "reported": reported[k], "approved": commanded[k]})
        return out

    def update(self, state: dict, t: float, commanded: dict | None = None) -> dict:
        """Call periodically with the PLC-reported state and the time in seconds."""
        if commanded:
            self.check_setpoints(state, commanded)
        if self.model is None or any(state.get(k) is None for k in
                                     ("ph", "chlorine_residual", "raw_ph", "raw_alkalinity", "raw_turbidity")):
            self.status = {"ok": True, "message": "physics check unavailable (sensor tags missing)",
                           "ph_err": None, "cl_err": None}
            return self.status
        if self.shadow is None:
            self._anchor(state, t)
            self.last_t = t
            self.status = {"ok": True, "message": "anchored", "ph_err": 0.0, "cl_err": 0.0}
            return self.status
        dt = max(0.0, t - self.last_t)
        self.last_t = t
        sp = dict(commanded or {})
        for k in SETPOINTS:                 # use approved setpoints; fall back to reported ones
            sp.setdefault(k, state.get(k))
        raw = Raw(state["raw_ph"], state["raw_alkalinity"], state["raw_turbidity"])
        n = max(1, int(dt // 60))
        for _ in range(n):
            self.model.step(self.shadow, raw, sp, dt / n)
        self.shadow.tank_level = state.get("tank_level", self.shadow.tank_level)   # level is not chemistry
        ph_pred, cl_pred = self.model.ph(self.shadow), self.shadow.chlorine
        e_ph, e_cl = state["ph"] - ph_pred, state["chlorine_residual"] - cl_pred
        bad = abs(e_ph) > self.ph_tol or abs(e_cl) > self.cl_tol
        self.strikes = self.strikes + 1 if bad else 0
        if self.strikes >= self.persist:
            what = (f"pH is {state['ph']:.2f} but the chemistry predicts {ph_pred:.2f}" if abs(e_ph) > self.ph_tol else
                    f"chlorine is {state['chlorine_residual']:.2f} mg/L but the chemistry predicts {cl_pred:.2f}")
            self._event(f"physics:{int(self.anchor_t)}", "critical",
                        f"Process doesn't match the approved setpoints: {what}. The real dosing may differ from "
                        "what the PLC reports (or an instrument has failed). Take a grab sample.",
                        {"ph_measured": state["ph"], "ph_predicted": round(ph_pred, 3),
                         "cl_measured": state["chlorine_residual"], "cl_predicted": round(cl_pred, 3)})
            self.status = {"ok": False, "message": what, "ph_err": round(e_ph, 3), "cl_err": round(e_cl, 3)}
            return self.status
        self.status = {"ok": not bad, "message": "process consistent with approved setpoints" if not bad else
                       "deviation (watching)", "ph_err": round(e_ph, 3), "cl_err": round(e_cl, 3)}
        # Model error accumulates open-loop: re-anchor while things look consistent.
        if not bad and t - self.anchor_t > self.reanchor_s and abs(e_ph) < self.ph_tol / 2 and abs(e_cl) < self.cl_tol / 2:
            self._anchor(state, t)
        return self.status

    def grab_sample(self, state: dict, ph: float | None = None, chlorine: float | None = None,
                    ph_tol: float = 0.2, cl_tol: float = 0.2, by: str = "operator") -> dict:
        # lab pH meters are good to ~0.1 and DPD chlorine kits to ~0.1 mg/L; 0.2 leaves margin
        """Compare an independent lab measurement with what the PLC reports right now."""
        res = {"by": by, "lab_ph": ph, "lab_chlorine": chlorine, "plc_ph": state.get("ph"),
               "plc_chlorine": state.get("chlorine_residual"), "ok": True, "notes": []}
        if ph is not None and state.get("ph") is not None and abs(ph - state["ph"]) > ph_tol:
            res["ok"] = False
            res["notes"].append(f"lab pH {ph:.2f} vs PLC {state['ph']:.2f}")
        if chlorine is not None and state.get("chlorine_residual") is not None and \
                abs(chlorine - state["chlorine_residual"]) > cl_tol:
            res["ok"] = False
            res["notes"].append(f"lab chlorine {chlorine:.2f} vs PLC {state['chlorine_residual']:.2f} mg/L")
        if self.audit:
            self.audit.append("grab_sample", res)
        if not res["ok"]:
            self._event(f"grab:{len(self.events)}", "critical",
                        "Lab grab sample disagrees with the PLC: " + "; ".join(res["notes"]) +
                        ". The PLC's readings can't be trusted; check the plant by hand.", {"grab": res})
        return res
