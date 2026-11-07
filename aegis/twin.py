"""Digital twin: predicts where a command will take the water *before* it's allowed.

Static limits ("lye 0-250 ppm, max 50 per command") can't know that today's
raw water is weakly buffered, or that an algae bloom already pushed raw pH to
8.3. The twin can: it estimates the clearwell's chemistry from the plant's own
sensors, then simulates the next few hours twice, once with the command and
once without, using the carbonate-chemistry model in aegis/process.py.

Robustness: the model is never exactly right (a real plant's lye feed might be
10% stronger than its nameplate). So every forecast is run across an
uncertainty ensemble (feed strength, chlorine decay, chlorine demand varied by
the amounts in policy.json), and also checked at the long-run steady state, so
a command can't hide its effect past the horizon. The worst case decides.

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

import itertools
import math
import time

from .config import load_process
from .process import ProcessModel, ProcessState, Raw, hocl_fraction, raw_from

REQUIRED = ("ph", "chlorine_residual", "tank_level", "raw_ph", "raw_alkalinity", "raw_turbidity")
DEFAULT_LIMITS = {"ph": [6.5, 8.5], "chlorine_residual": [0.2, 4.0], "tank_level": [5.0, 100.0, 180]}
DEFAULT_UNCERTAINTY = {"naoh_feed_strength": 0.10, "chlorine_decay_per_hr": 0.30, "chlorine_demand": 0.25}
LABELS = {"ph": ("pH", ""), "chlorine_residual": ("chlorine residual", " mg/L"), "tank_level": ("clearwell level", "%")}


@dataclass
class Verdict:
    allowed: bool
    reason: str
    worst_var: str | None = None
    worst_value: float | None = None
    minutes: float | None = None
    forecast: dict | None = None      # {"with": [...], "without": [...]} for the UI
    timed_out: bool = False


# How far outside the band counts as "one unit" of badness, per variable. Dividing by the band width
# made a total loss of disinfection (0.2 mg/L below a 0.2-4.0 band) look 20x smaller than a pH
# excursion; these scales make 1 unit comparably serious for each variable.
SCALE = {"ph": 1.0, "chlorine_residual": 0.2, "tank_level": 20.0}

RAW_KEYS = ("raw_ph", "raw_alkalinity", "raw_turbidity")
RAW_BOUNDS = {"raw_ph": (5.5, 9.5), "raw_alkalinity": (5.0, 500.0), "raw_turbidity": (0.0, 300.0)}


class Twin:
    def __init__(self, params: dict | None = None, dt_s: float = 120.0, uncertainty: dict | None = None,
                 trend_window_min: float = 30, project_min: float = 60):
        self.model = ProcessModel(params or load_process())
        self.dt_s = dt_s
        self.set_uncertainty(DEFAULT_UNCERTAINTY if uncertainty is None else uncertainty)
        self.trend_window_s = trend_window_min * 60
        self.project_s = project_min * 60
        self._obs: list[tuple] = []          # (t, raw_ph, raw_alk, raw_turb)

    # ---------------------------------------------------------------- raw-water trend
    def observe(self, state: dict, t: float):
        """Feed the twin raw-water readings over time (every poll), so forecasts can follow a storm
        or bloom that's arriving instead of assuming today's raw water stays as it is."""
        if not all(state.get(k) is not None for k in RAW_KEYS):
            return
        self._obs.append((t, *(float(state[k]) for k in RAW_KEYS)))
        cutoff = t - self.trend_window_s
        while self._obs and self._obs[0][0] < cutoff:
            self._obs.pop(0)

    def trend(self) -> dict:
        """Least-squares slope (per second) of each raw-water reading over the trend window."""
        pts = self._obs
        if len(pts) < 4 or pts[-1][0] - pts[0][0] < self.trend_window_s / 3:
            return {}
        n = len(pts)
        tm = sum(p[0] for p in pts) / n
        den = sum((p[0] - tm) ** 2 for p in pts) or 1.0
        out = {}
        for i, k in enumerate(RAW_KEYS, start=1):
            vm = sum(p[i] for p in pts) / n
            out[k] = sum((p[0] - tm) * (p[i] - vm) for p in pts) / den
        return out

    def _raw_at(self, state: dict, slopes: dict, t_s: float) -> Raw:
        """Damped projection: raw-water changes level off (a storm's turbidity rises then plateaus),
        so the projected change approaches slope * tau instead of growing forever. Linear
        extrapolation overshot so badly that every option looked equally doomed."""
        if not slopes:
            return raw_from(state)
        tau = self.project_s / 3
        damp = tau * (1 - math.exp(-t_s / tau))
        st = dict(state)
        for k, sl in slopes.items():
            lo, hi = RAW_BOUNDS[k]
            st[k] = min(hi, max(lo, state[k] + sl * damp))
        return raw_from(st)

    def set_uncertainty(self, u: dict):
        """Build the ensemble: nominal + the corners that push pH and chlorine each way."""
        self.uncertainty = dict(u)
        base = self.model.params
        f, k, d = u.get("naoh_feed_strength", 0), u.get("chlorine_decay_per_hr", 0), u.get("chlorine_demand", 0)
        members = [dict(base)]
        for sf, sk in itertools.product((-1, 1), (-1, 1)):
            m = dict(base)
            m["naoh_feed_strength"] = base["naoh_feed_strength"] * (1 + sf * f)
            m["chlorine_decay_per_hr"] = base["chlorine_decay_per_hr"] * (1 + sk * k)
            m["chlorine_demand_base"] = base["chlorine_demand_base"] * (1 + sk * d)
            m["chlorine_demand_per_ntu"] = base["chlorine_demand_per_ntu"] * (1 + sk * d)
            if m != base:
                members.append(m)
        self.ensemble = [ProcessModel(m) for m in members]

    @staticmethod
    def available(state: dict) -> bool:
        return all(state.get(k) is not None for k in REQUIRED)

    def _setpoints(self, state: dict, override: dict | None = None) -> dict:
        keys = ("intake_pump", "distribution_pump", "chlorine_dose", "naoh_dose", "distribution_rate")
        sp = {k: state.get(k) for k in keys}
        sp.update(override or {})
        return sp

    def forecast(self, state: dict, override: dict | None = None, horizon_min: float = 240,
                 every_min: float = 10, model: ProcessModel | None = None) -> list[dict]:
        model = model or self.model
        raw = raw_from(state)
        s: ProcessState = model.estimate(state, raw)
        sp = self._setpoints(state, override)
        slopes = self.trend()
        out, t, next_pt = [], 0.0, 0.0
        while t <= horizon_min * 60 + 1e-6:
            if t >= next_pt - 1e-6:
                ph = model.ph(s)
                out.append({"min": round(t / 60), "ph": round(ph, 3), "chlorine_residual": round(s.chlorine, 3),
                            "tank_level": round(s.tank_level, 2), "hocl_pct": round(100 * hocl_fraction(ph), 1)})
                next_pt += every_min * 60
            model.step(s, self._raw_at(state, slopes, t) if slopes else raw, sp, self.dt_s)
            t += self.dt_s
        return out

    def steady(self, state: dict, override: dict | None = None, model: ProcessModel | None = None) -> dict:
        """Where the water ends up if nothing else changes (point for the violation check)."""
        model = model or self.model
        raw = self._raw_at(state, self.trend(), self.project_s)      # where the raw-water trend is heading
        sp = self._setpoints(state, override)
        if not sp.get("intake_pump"):
            return {"min": float("inf"), "ph": state["ph"], "chlorine_residual": state["chlorine_residual"]}
        ss = model.steady(raw, sp, state.get("tank_level", 60))
        return {"min": float("inf"), "ph": model.ph(ss), "chlorine_residual": ss.chlorine}

    @staticmethod
    def _violation(traj: list[dict], limits: dict) -> tuple[float, str | None, float | None, float | None]:
        """Badness of a trajectory: worst excursion outside the bands plus how long it lasts.

        Score = peak excursion + mean excursion over the forecast points (each normalised by
        SCALE[variable]), so a change that makes a failure arrive sooner or last longer scores
        worse even if the eventual peak is the same. A band may carry its own horizon:
        [low, high, horizon_min] (used for tank level, which this plant can't hold steady
        forever by design, so only the near future counts).
        """
        worst, var, val, when = 0.0, None, None, None
        area, npts = 0.0, 0
        for pt in traj:
            finite = pt["min"] != float("inf")
            npts += finite
            for k, band in limits.items():
                lo, hi = band[0], band[1]
                if len(band) > 2 and pt["min"] > band[2]:
                    continue
                v = pt.get(k)
                if v is None:
                    continue
                ex = max(lo - v, v - hi, 0.0) / SCALE.get(k, hi - lo)
                if finite:
                    area += ex
                if ex > worst + 1e-9:
                    worst, var, val, when = ex, k, v, pt["min"]
        return worst + area / max(1, npts), var, val, when

    # (variable, direction it's failing) -> (setpoint that moves it, sign of change that makes it worse)
    HARMFUL = {("chlorine_residual", "below"): ("chlorine_dose", -1), ("chlorine_residual", "above"): ("chlorine_dose", 1),
               ("ph", "above"): ("naoh_dose", 1), ("ph", "below"): ("naoh_dose", -1)}

    def _wrong_way(self, register: str, value: float, state: dict, base_viol: set):
        """Safety net for saturated cases (e.g. chlorine already forecast at zero either way): never
        move a dose in the harmful direction while that variable is forecast out of band that way."""
        old = state.get(register)
        if old is None or value == old:
            return None
        for (var, direction) in base_viol:
            reg, sign = self.HARMFUL.get((var, direction), (None, 0))
            if reg == register and (value - old) * sign > 0:
                return var, direction
        return None

    @staticmethod
    def _first_cross(traj: list[dict], var: str, limits: dict) -> float | None:
        lo, hi = limits[var][0], limits[var][1]
        for pt in traj:
            if not lo <= pt[var] <= hi:
                return pt["min"]
        return None

    def evaluate(self, state: dict, register: str, value: float, horizon_min: float = 360,
                 limits: dict | None = None, deadline: float | None = None, margin: float = 0.01) -> Verdict:
        """deadline: time.perf_counter() value; if passed before all model variants are done,
        returns timed_out=True instead of a partial (possibly optimistic) answer."""
        limits = limits or DEFAULT_LIMITS
        if not self.available(state):
            return Verdict(True, "prediction unavailable (missing sensor tags)")
        override = {register: value}
        worst_c, worst_b, why = 0.0, 0.0, None
        base_viol: set = set()
        fc = None
        for i, m in enumerate(self.ensemble):
            if deadline is not None and time.perf_counter() > deadline:
                return Verdict(True, "prediction skipped: time budget exceeded", timed_out=True)
            base = self.forecast(state, None, horizon_min, model=m)
            cand = self.forecast(state, override, horizon_min, model=m)
            if i == 0:
                fc = {"with": cand, "without": base}
            base_all = base + [self.steady(state, None, m)]
            for k, band in limits.items():                 # which way is the do-nothing future failing?
                for pt in base_all:
                    v = pt.get(k)
                    if v is None or (len(band) > 2 and pt["min"] > band[2]):
                        continue
                    if v < band[0]:
                        base_viol.add((k, "below"))
                    elif v > band[1]:
                        base_viol.add((k, "above"))
            cand_all = cand + [self.steady(state, override, m)]
            v_c, var, val, _ = self._violation(cand_all, limits)
            v_b, *_ = self._violation(base_all, limits)
            worst_b = max(worst_b, v_b)
            if v_c > worst_c:
                worst_c = v_c
                when = self._first_cross(cand, var, limits) if var else None
                why = (var, val, when, i)
        wrong_way = self._wrong_way(register, value, state, base_viol)
        if wrong_way:
            name, unit = LABELS.get(wrong_way[0], (wrong_way[0], ""))
            return Verdict(False, f"{name} is already forecast to go {wrong_way[1]} its safe limit; this change "
                                  f"pushes it further that way", wrong_way[0], None, None, fc)
        if worst_c > 0 and worst_c > worst_b + margin:     # only MATERIALLY worse than doing nothing
            var, val, when, i = why
            name, unit = LABELS.get(var, (var, ""))
            lo, hi = limits[var][0], limits[var][1]
            t = f"about {when:g} min after this change" if when is not None else "once the tank settles (beyond the forecast window)"
            case = "" if i == 0 else " in the worst case of the model's uncertainty range"
            return Verdict(False, f"twin predicts {name} reaches {val:.2f}{unit} (safe {lo:g}-{hi:g}) {t}{case}",
                           var, val, when, fc)
        if worst_b > 0 and worst_c < worst_b - 1e-6:
            return Verdict(True, "corrective: improves an unsafe forecast", forecast=fc)
        if worst_b > 0:
            return Verdict(True, "the forecast is unsafe either way; this change doesn't make it materially "
                                 "worse (early warnings stay on)", forecast=fc)
        return Verdict(True, f"forecast stays in the safe band (next {horizon_min:g} min and long-run, "
                             f"across {len(self.ensemble)} model variants)", forecast=fc)
