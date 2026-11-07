"""Early warning: alert when the twin's forecast crosses an alarm limit, before the alarm trips.

A process alarm fires when the water is already bad. Our own evaluation showed
that for a slow clearwell drain the low-level alarm leaves the operator a
median of ~14 minutes before the tank is empty. The twin already forecasts
where the plant is heading at current settings, so Aegis texts the operator
when that forecast crosses a limit within the warning horizon:

    "Twin forecast: clearwell level will fall below 10% in about 95 min at current settings (now 38%)."

One alert per crossing (re-armed when the forecast clears), nominal model
(not the worst case) to keep nuisance alerts down.
"""
from __future__ import annotations

ALARM_BANDS = {"ph": (6.5, 8.5, 120, "pH", ""), "chlorine_residual": (0.2, 4.0, 120, "chlorine residual", " mg/L"),
               "tank_level": (10.0, 95.0, 180, "clearwell level", "%")}


def first_crossings(forecast: list[dict], bands: dict = ALARM_BANDS) -> dict:
    """{var: (minutes, 'below'|'above', value)} for the first forecast point outside each band."""
    out = {}
    for var, (lo, hi, horizon, *_ ) in bands.items():
        for pt in forecast:
            if pt["min"] > horizon:
                break
            v = pt.get(var)
            if v is None:
                continue
            if v < lo or v > hi:
                out[var] = (pt["min"], "below" if v < lo else "above", v)
                break
    return out


class ForecastWatch:
    def __init__(self, alerter=None, audit=None, bands: dict = ALARM_BANDS):
        self.alerter, self.audit, self.bands = alerter, audit, bands
        self.active: dict[str, dict] = {}

    def update(self, forecast: list[dict] | None, now_state: dict) -> dict:
        if not forecast:
            return self.active
        cross = first_crossings(forecast, self.bands)
        for var, (mins, direction, val) in cross.items():
            lo, hi, _, label, unit = self.bands[var]
            if mins == 0:        # already out of band: the process alarm covers it
                continue
            key = f"{var}:{direction}"
            if key in self.active:
                self.active[key]["minutes"] = mins
                continue
            limit = lo if direction == "below" else hi
            msg = (f"Twin forecast: {label} will go {direction} {limit:g}{unit} in about {mins:g} min at current "
                   f"settings (now {now_state.get(var, float('nan')):.2f}{unit}). Act now to avoid the alarm.")
            self.active[key] = {"var": var, "direction": direction, "minutes": mins, "message": msg}
            if self.audit:
                self.audit.append("forecast_warning", self.active[key])
            if self.alerter:
                self.alerter.raise_alert(f"forecast:{key}", "warning", msg)
        for key in list(self.active):
            var, direction = key.split(":")
            if var not in cross or cross[var][1] != direction:
                del self.active[key]          # forecast cleared: re-arm
        return self.active
