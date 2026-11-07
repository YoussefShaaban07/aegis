"""Digital twin: predicts where a command will take the water *before* it's allowed.

Static limits ("lye 0-250 ppm, max 50 per command") can't know that today's
raw water is weakly buffered, or that an algae bloom already pushed raw pH to
8.3. The twin can: it estimates the clearwell's chemistry from the plant's own
sensors, then simulates the next few hours twice, once with the command and
once without, using the carbonate-chemistry model in aegis/process.py.

Decision rule (deterministic, no AI):
  * if the forecast WITH the command leaves a safe band (pH 6.5-8.5, chlorine
    0.2-4.0 mg/L by default; bands live in policy.json) and is worse than
    doing nothing -> block, with
    the predicted value and when it would happen;
  * a command that improves an already-bad forecast is allowed (corrective
    action must never be blocked by the safety system).
"""
from __future__ import annotations

from dataclasses import dataclass

from .config import load_process
from .process import ProcessModel, ProcessState, Raw, hocl_fraction

REQUIRED = ("ph", "chlorine_residual", "tank_level", "raw_ph", "raw_alkalinity", "raw_turbidity")
DEFAULT_LIMITS = {"ph": [6.5, 8.5], "chlorine_residual": [0.2, 4.0]}
LABELS = {"ph": ("pH", ""), "chlorine_residual": ("chlorine residual", " mg/L"), "tank_level": ("clearwell level", "%")}


@dataclass
class Verdict:
    allowed: bool
    reason: str
    worst_var: str | None = None
    worst_value: float | None = None
    minutes: float | None = None
    forecast: dict | None = None      # {"with": [...], "without": [...]} for the UI


class Twin:
    def __init__(self, params: dict | None = None, dt_s: float = 120.0):
        self.model = ProcessModel(params or load_process())
        self.dt_s = dt_s

    @staticmethod
    def available(state: dict) -> bool:
        return all(state.get(k) is not None for k in REQUIRED)

    def _setpoints(self, state: dict, override: dict | None = None) -> dict:
        keys = ("intake_pump", "distribution_pump", "chlorine_dose", "naoh_dose", "distribution_rate")
        sp = {k: state.get(k) for k in keys}
        sp.update(override or {})
        return sp

    def forecast(self, state: dict, override: dict | None = None, horizon_min: float = 240,
                 every_min: float = 10) -> list[dict]:
        raw = Raw(state["raw_ph"], state["raw_alkalinity"], state["raw_turbidity"])
        s: ProcessState = self.model.estimate(state, raw)
        sp = self._setpoints(state, override)
        out, t, next_pt = [], 0.0, 0.0
        while t <= horizon_min * 60 + 1e-6:
            if t >= next_pt - 1e-6:
                ph = self.model.ph(s)
                out.append({"min": round(t / 60), "ph": round(ph, 3), "chlorine_residual": round(s.chlorine, 3),
                            "tank_level": round(s.tank_level, 2), "hocl_pct": round(100 * hocl_fraction(ph), 1)})
                next_pt += every_min * 60
            self.model.step(s, raw, sp, self.dt_s)
            t += self.dt_s
        return out

    @staticmethod
    def _violation(traj: list[dict], limits: dict) -> tuple[float, str | None, float | None, float | None]:
        """Largest excursion outside the bands, normalised by band width."""
        worst, var, val, when = 0.0, None, None, None
        for pt in traj:
            for k, (lo, hi) in limits.items():
                v = pt[k]
                ex = max(lo - v, v - hi, 0.0) / (hi - lo)
                if ex > worst + 1e-9:
                    worst, var, val, when = ex, k, v, pt["min"]
        return worst, var, val, when

    @staticmethod
    def _first_cross(traj: list[dict], var: str, limits: dict) -> float | None:
        lo, hi = limits[var]
        for pt in traj:
            if not lo <= pt[var] <= hi:
                return pt["min"]
        return None

    def evaluate(self, state: dict, register: str, value: float, horizon_min: float = 240,
                 limits: dict | None = None) -> Verdict:
        limits = limits or DEFAULT_LIMITS
        if not self.available(state):
            return Verdict(True, "prediction unavailable (missing sensor tags)")
        base = self.forecast(state, None, horizon_min)
        cand = self.forecast(state, {register: value}, horizon_min)
        fc = {"with": cand, "without": base}
        v_c, var, val, _ = self._violation(cand, limits)
        v_b, *_ = self._violation(base, limits)
        if v_c > 0 and v_c > v_b + 1e-6:
            when = self._first_cross(cand, var, limits)
            name, unit = LABELS.get(var, (var, ""))
            lo, hi = limits[var]
            return Verdict(False, f"twin predicts {name} reaches {val:.2f}{unit} (safe {lo:g}-{hi:g}) "
                                  f"about {when:g} min after this change", var, val, when, fc)
        if v_b > 0 and v_c < v_b - 1e-6:
            return Verdict(True, "corrective: improves an unsafe forecast", forecast=fc)
        return Verdict(True, f"forecast stays in the safe band for {horizon_min:g} min", forecast=fc)
