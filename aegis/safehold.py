"""Safe-hold: undo the change that is driving the plant toward unsafe water when nobody answers.

Why this exists (judge round 8): Aegis's evaluation assumed nobody responds to
alarms, and slow attacks built from individually legal changes (raise the
distribution rate while the clearwell is full; raise lye a little before an
algae bloom) still succeeded. The twin warned two to three hours ahead and
nobody acted. A warning that nobody reads at 3 AM protects nothing.

What it does, when `policy.safe_hold.enabled` is true:

  1. Every poll, the twin forecasts the plant at current settings
     (forewarn bands: pH / chlorine 120 min, clearwell 180 min).
  2. If the forecast crosses a limit and the open incident has NOT been
     acknowledged for `after_min` minutes, Aegis looks at the setpoints that
     changed within `lookback_min` and, for each, the values it had before.
  3. It runs the twin for each of those earlier values and picks the single
     revert that improves the forecast most (it must be materially better than
     doing nothing, and inside the hard range).
  4. It writes that value to the PLC as source "Aegis safe-hold", logs it with
     the forecasts, raises a critical alert, and HOLDS the register there for
     `hold_min`: Modbus writes that move it away are refused (check "hold")
     until someone releases the hold on the authenticated dashboard.

The hold is the important part. A Modbus packet can claim to be the HMI; it
can't log in. If the HMI itself is compromised, the attacker can't simply
re-apply the change, because releasing a hold needs an operator/engineer login.

What it deliberately does NOT do:
  - invent new setpoints: it only restores values the plant actually ran at
    recently (the operators' own choices);
  - act when the operator has acknowledged: an acknowledged incident means a
    human owns the situation;
  - act on pumps (on/off coils): stopping or starting a pump is a permit-gated
    decision for a person;
  - act more than once per `after_min`.

Off by default. An engineer turns it on per plant, after a trial in monitor mode.
"""
from __future__ import annotations

from .forewarn import first_crossings

DEFAULTS = {"enabled": False, "after_min": 15, "lookback_min": 720, "hold_min": 240,
            "registers": ["naoh_dose", "chlorine_dose", "distribution_rate"], "margin": 0.01}
SOURCE = "Aegis safe-hold"


class SafeHold:
    def __init__(self, guard, cfg: dict | None = None):
        self.guard = guard
        self.cfg = {**DEFAULTS, **(cfg if cfg is not None else (guard.policy.get("safe_hold") or {}))}
        self.warn_since: float | None = None
        self.warn_alert_t: float | None = None     # same moment on the alerter's clock
        self.last_action: float | None = None
        self.actions: list[dict] = []
        self.standing_down = False

    @property
    def enabled(self) -> bool:
        return bool(self.cfg.get("enabled")) and self.guard.twin is not None and self.guard.mode == "enforce"

    def _acked(self) -> bool:
        """A human acknowledged an incident that was open when this warning started, or a later one.
        (Incidents close by themselves after their window, so 'the open incident' isn't enough.)"""
        al = self.guard.alerter
        if al is None or self.warn_alert_t is None:
            return False
        since = self.warn_alert_t - getattr(al, "incident_window_s", 900)
        return any(inc.get("acked_at") is not None and inc["acked_at"] >= since and inc["last"] >= since
                   for inc in al.incidents)

    def _score(self, state: dict, override: dict | None) -> float:
        twin = self.guard.twin
        pred = self.guard.policy.get("prediction") or {}
        limits = pred.get("limits")
        traj = twin.forecast(state, override, pred.get("horizon_min", 360))
        traj = traj + [twin.steady(state, override)]
        from .twin import DEFAULT_LIMITS
        return twin._violation(traj, limits or DEFAULT_LIMITS)[0]

    def candidates(self) -> list[tuple[str, float]]:
        """(register, earlier value) pairs: values each register had before changes in the lookback window."""
        out, seen = [], set()
        cut = self.guard.clock() - self.cfg["lookback_min"] * 60
        for t, reg, old, new, src in reversed(self.guard.setpoint_log):
            if t < cut:
                break
            if reg not in self.cfg["registers"] or old is None or (reg, old) in seen:
                continue
            lim = self.guard.policy["limits"].get(reg)
            if lim and lim["min"] <= old <= lim["max"]:
                seen.add((reg, old))
                out.append((reg, old))
        return out

    def update(self, state: dict, now: float, sensors_trusted: bool = True) -> dict | None:
        """Call once per poll with the current PLC state. Returns an action to apply, or None.
        `now`: process time in seconds (wall/monotonic in deployment, simulated time in the demo).
        sensors_trusted=False (integrity monitor alarm, stuck analyzer): stand down. Acting on readings
        an attacker may be faking would let them use Aegis to undo the operators' good changes."""
        if not self.enabled or not self.guard.twin.available(state):
            self.warn_since = None
            return None
        if not sensors_trusted:
            self.standing_down = True
            return None
        self.standing_down = False
        fc = self.guard.twin.forecast(state, None, 180, every_min=5)
        cross = first_crossings(fc)
        if not cross:
            self.warn_since = None
            return None
        if self.warn_since is None:
            self.warn_since = now
            self.warn_alert_t = self.guard.alerter.clock() if self.guard.alerter else None
        if self._acked():
            return None
        wait = self.cfg["after_min"] * 60
        if now - self.warn_since < wait or (self.last_action is not None and now - self.last_action < wait):
            return None
        base = self._score(state, None)
        best = None
        for reg, val in self.candidates():
            if state.get(reg) == val:
                continue
            s = self._score(state, {reg: val})
            if s < base - self.cfg["margin"] and (best is None or s < best[2]):
                best = (reg, val, s)
        self.last_action = now            # one attempt per wait period, whether or not it found a fix
        if best is None:
            return None
        reg, val, s = best
        var, (mins, direction, v) = next(iter(cross.items()))
        action = {"register": reg, "value": val, "from": state.get(reg), "score_before": round(base, 4),
                  "score_after": round(s, 4), "forecast": f"{var} {direction} limit in ~{mins:g} min",
                  "unacked_min": round((now - self.warn_since) / 60, 1)}
        self.actions.append(action)
        return action
