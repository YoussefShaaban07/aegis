"""Lab inputs: run the twin at plants that measure raw-water alkalinity (or turbidity) by hand.

Judge round 11: "Your twin needs online raw-water pH, alkalinity and turbidity analyzers.
A small plant has pH and chlorine analyzers; alkalinity is a titration someone does once
a day." So any twin input can come from the lab instead of the PLC:

    policy.json:  "lab_inputs": {"raw_alkalinity": {"max_age_h": 36}}

    python -m aegis.labinputs set raw_alkalinity 74 --by "J. Smith"     # on the Aegis box
    (or the dashboard: Lab sample)

The newest entry fills that reading for the twin until it is older than max_age_h. After
that the twin's chemistry is PAUSED (static rules only) and the operator is alerted, rather
than forecasting from a number nobody trusts. Every entry is audited with who entered it.

How much protection this costs is measured, not assumed: `python -m aegis.evaluate
--lab-hours 24` runs the evaluation with alkalinity from a once-a-day sample (README).
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path

from .twin import RAW_BOUNDS

SP_KEYS = ("intake_pump", "distribution_pump", "chlorine_dose", "naoh_dose", "distribution_rate")


def implied_alkalinity(state: dict, model, ph_tol: float = 0.15) -> tuple[float, float] | None:
    """The range of raw alkalinity that is consistent with the finished pH the PLC reports right now, at the
    current lye dose (finished pH falls as alkalinity rises). None if the readings needed are missing.
    ph_tol covers sensor error and the plant not being at steady state."""
    from .process import Raw
    need = ("ph", "raw_ph", "raw_turbidity") + SP_KEYS
    if model is None or any(state.get(k) is None for k in need):
        return None
    sp = {k: state[k] for k in SP_KEYS}

    def ph_at(a):
        return model.ph(model.steady(Raw(state["raw_ph"], a, state["raw_turbidity"]), sp))

    def solve(target):                          # bisection: ph_at is decreasing in alkalinity
        lo, hi = 5.0, 500.0
        if ph_at(lo) < target:
            return lo
        if ph_at(hi) > target:
            return hi
        for _ in range(40):
            mid = (lo + hi) / 2
            lo, hi = (mid, hi) if ph_at(mid) > target else (lo, mid)
        return (lo + hi) / 2
    return solve(state["ph"] + ph_tol), solve(state["ph"] - ph_tol)

DEFAULT_PATH = Path("data/lab_inputs.json")


class LabInputs:
    def __init__(self, config: dict | None = None, path: str | Path | None = None, audit=None, alerter=None,
                 clock=time.time):
        self.config = dict(config or {})
        self.path = Path(path) if path else None
        self.audit, self.alerter, self.clock = audit, alerter, clock
        self.values: dict[str, dict] = {}
        self._stale_alerted: set = set()
        self._hist: list[tuple] = []            # (t, ph, raw_ph, turbidity, setpoints) for the steadiness test
        if self.path and self.path.exists():
            try:
                self.values = json.loads(self.path.read_text())
            except (OSError, ValueError):
                self.values = {}

    def reload(self):
        if self.path and self.path.exists():
            try:
                self.values = json.loads(self.path.read_text())
            except (OSError, ValueError):
                pass

    def enter(self, name: str, value: float, by: str, confirm: bool = False) -> dict:
        if name not in self.config:
            raise ValueError(f"{name} is not configured as a lab input (policy.lab_inputs)")
        lo, hi = RAW_BOUNDS.get(name, (float("-inf"), float("inf")))
        if not lo <= float(value) <= hi:
            raise ValueError(f"{name} = {value} is outside the plausible range {lo}-{hi}")
        e = {"value": float(value), "t": self.clock(), "by": by, "confirmed": bool(confirm)}
        old = self.values.get(name)
        if old:
            e["prev"] = {"value": old["value"], "t": old["t"]}
        self.values[name] = e
        self._stale_alerted.discard(name)
        if self.path:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.write_text(json.dumps(self.values, indent=1))
        if self.audit:
            self.audit.append("lab_input", {"name": name, **e})
        return e

    def status(self) -> dict:
        now = self.clock()
        out = {}
        for name, cfg in self.config.items():
            e = self.values.get(name)
            age = None if e is None else (now - e["t"]) / 3600
            out[name] = {"value": e and e["value"], "age_h": None if age is None else round(age, 1),
                         "by": e and e["by"], "max_age_h": cfg.get("max_age_h", 36),
                         "fresh": age is not None and age <= cfg.get("max_age_h", 36)}
        return out

    def _observe(self, state: dict):
        if any(state.get(k) is None for k in ("ph", "raw_ph", "raw_turbidity")):
            return
        now = self.clock()
        self._hist.append((now, state["ph"], state["raw_ph"], state["raw_turbidity"],
                           tuple(state.get(k) for k in SP_KEYS)))
        while self._hist and now - self._hist[0][0] > 3 * 3600:
            self._hist.pop(0)

    def steady(self, minutes: float = 90) -> bool:
        """The comparison uses steady-state chemistry, so it is only fair when the plant has been steady:
        same setpoints, flat finished and raw pH, turbidity within 20%, for `minutes`."""
        if not self._hist or self._hist[-1][0] - self._hist[0][0] < minutes * 60:
            return False
        recent = [h for h in self._hist if self._hist[-1][0] - h[0] <= minutes * 60]
        ph, rph, tu = ([h[i] for h in recent] for i in (1, 2, 3))
        return (len({h[4] for h in recent}) == 1 and max(ph) - min(ph) < 0.08 and max(rph) - min(rph) < 0.08
                and max(tu) <= 1.2 * max(min(tu), 0.5))

    def check(self, name: str, value: float, state: dict, model) -> str | None:
        """Judge round 12: a typed-in number is an easy way to blind or steer the twin (an insider, a
        phished operator account, or a typo). Raw alkalinity is checked against what the plant's own
        finished pH implies at the current dose; a value far outside that is not used until confirmed."""
        if name != "raw_alkalinity" or not self.steady():
            return None                         # judged later, once the plant is steady
        rng = implied_alkalinity(state, model)
        if rng is None:
            return None
        lo, hi = rng
        if lo * 0.8 <= value <= hi * 1.25:
            return None
        return (f"lab raw alkalinity {value:g} disagrees with the plant: the finished pH it reports implies "
                f"{lo:.0f}-{hi:.0f} mg/L at the current lye dose")

    def fill(self, state: dict, model=None) -> dict:
        """Return the state with lab values filled in for readings the PLC doesn't provide.
        A PLC reading always wins. Stale lab values are left out (twin pauses) and alerted once.
        With `model`, implausible unconfirmed entries are also left out and alerted."""
        st = dict(state)
        self._observe(state)
        for name, s in self.status().items():
            if st.get(name) is not None:
                continue
            e = self.values.get(name) or {}
            bad = s["fresh"] and not e.get("confirmed") and self.check(name, s["value"], state, model)
            if bad:
                if (name, e.get("t")) not in self._stale_alerted:
                    self._stale_alerted.add((name, e.get("t")))
                    if self.alerter:
                        self.alerter.raise_alert(f"lab_implausible:{name}", "warning",
                                                 f"{bad}. Not used: twin chemistry is paused until the sample is "
                                                 "re-tested or an engineer confirms it (labinputs set ... --confirm). "
                                                 f"Entered by {e.get('by')}.")
                    if self.audit:
                        self.audit.append("lab_input_rejected", {"name": name, "value": s["value"], "reason": bad})
                continue
            prev = e.get("prev")
            if (s["fresh"] and not e.get("confirmed") and prev and not self.steady()
                    and abs(s["value"] - prev["value"]) > 0.3 * prev["value"]
                    and self.clock() - prev["t"] <= self.config[name].get("max_age_h", 36) * 3600):
                st[name] = prev["value"]        # a big unverified jump waits until it can be checked
                continue
            if s["fresh"]:
                st[name] = s["value"]
            elif name not in self._stale_alerted:
                self._stale_alerted.add(name)
                if self.alerter:
                    when = "never entered" if s["age_h"] is None else f"{s['age_h']:g} h old"
                    self.alerter.raise_alert(f"lab_stale:{name}", "warning",
                                             f"Lab {name} is {when} (limit {s['max_age_h']:g} h): digital-twin "
                                             "chemistry is paused, static rules only. Enter today's sample.")
        return st


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("set")
    s.add_argument("name")
    s.add_argument("value", type=float)
    s.add_argument("--by", required=True)
    s.add_argument("--confirm", action="store_true", help="engineer: use it even though it disagrees with the chemistry")
    sub.add_parser("show")
    ap.add_argument("--path", default=str(DEFAULT_PATH))
    a = ap.parse_args(argv)
    from .audit import AuditLog
    from .config import Tags, load_policy
    lab = LabInputs(load_policy(Tags.load()).get("lab_inputs") or {}, a.path, audit=AuditLog())
    if a.cmd == "set":
        print(lab.enter(a.name, a.value, a.by, confirm=a.confirm))
    print(json.dumps(lab.status(), indent=1))


if __name__ == "__main__":
    main()
