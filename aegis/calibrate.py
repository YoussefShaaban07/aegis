"""Fit the digital twin to a real plant from its own operating history.

Nobody at a small utility knows their lye feed's effective strength or their
chlorine decay rate to two digits, and the twin is only as good as those
numbers. So Aegis learns them: from a recorded history of setpoints and sensor
readings (the gateway writes one row per poll to data/history.csv), it replays
many short windows open-loop through the model and adjusts the parameters to
minimise prediction error (coordinate search, golden section in log space).

    python -m aegis.calibrate --history data/history.csv          # prints fitted parameters
    python -m aegis.calibrate --history data/history.csv --write  # updates config/process.json

Identifiability, honestly: a parameter can only be learned if the history
exercises it. Feed strength needs some lye changes or pH movement; decay vs
demand are partly confounded (both lower chlorine), so they're fitted jointly
and the result reports the error improvement rather than claiming exact values.
After calibrating, the twin's uncertainty band can be narrowed in policy.json.

Poisoning: calibrating on history recorded during an attack (e.g. a PLC
secretly dosing more lye) would fit the attack into the model and blind both
the twin and the integrity monitor. The dashboard refuses to apply a
calibration while integrity alarms are active or when a parameter moves more
than 25% (real feed systems don't drift that fast).
"""
from __future__ import annotations

import argparse
import csv
import json
import math
from pathlib import Path

from .config import PROCESS_PATH, load_process
from .process import ProcessModel, Raw

FIELDS = ("naoh_feed_strength", "chlorine_decay_per_hr", "chlorine_demand_base")
SP = ("intake_pump", "distribution_pump", "chlorine_dose", "naoh_dose", "distribution_rate")


def _t(row):
    return row.get("sim_t", row.get("t"))


def window_errors(history: list[dict], params: dict, window_min: float = 60, stride_min: float = 20):
    """Replay windows open-loop; return list of (pH error, chlorine error) at each window end."""
    model = ProcessModel(params)
    out = []
    i = 0
    n = len(history)
    while i < n:
        t0 = _t(history[i])
        j = i
        while j + 1 < n and _t(history[j + 1]) - t0 <= window_min * 60:
            j += 1
        if _t(history[j]) - t0 < window_min * 60 * 0.8:
            break
        r0 = history[i]
        raw = Raw(r0["raw_ph"], r0["raw_alkalinity"], r0["raw_turbidity"])
        s = model.estimate(r0, raw)
        for k in range(i, j):
            row = history[k]
            raw = Raw(row["raw_ph"], row["raw_alkalinity"], row["raw_turbidity"])
            sp = {x: row[x] for x in SP}
            s.tank_level = row["tank_level"]
            model.step(s, raw, sp, _t(history[k + 1]) - _t(row))
        end = history[j]
        out.append((model.ph(s) - end["ph"], s.chlorine - end["chlorine_residual"]))
        nxt = i
        while nxt < n and _t(history[nxt]) - t0 < stride_min * 60:
            nxt += 1
        i = max(nxt, i + 1)
    return out


def loss(history, params) -> float:
    errs = window_errors(history, params)
    if not errs:
        return float("inf")
    return sum((e1 / 0.05) ** 2 + (e2 / 0.05) ** 2 for e1, e2 in errs) / len(errs)


def mae(history, params) -> dict:
    errs = window_errors(history, params)
    n = max(1, len(errs))
    return {"windows": len(errs), "ph_mae": round(sum(abs(a) for a, _ in errs) / n, 4),
            "cl_mae": round(sum(abs(b) for _, b in errs) / n, 4)}


def _golden(f, lo, hi, iters=18):
    g = (math.sqrt(5) - 1) / 2
    a, b = lo, hi
    c, d = b - g * (b - a), a + g * (b - a)
    fc, fd = f(c), f(d)
    for _ in range(iters):
        if fc < fd:
            b, d, fd = d, c, fc
            c = b - g * (b - a); fc = f(c)
        else:
            a, c, fc = c, d, fd
            d = a + g * (b - a); fd = f(d)
    return (a + b) / 2


def fit(history: list[dict], base: dict | None = None, fields=FIELDS, passes: int = 3, span: float = 2.0,
        min_windows: int = 5) -> dict:
    base = dict(base or load_process())
    if len(history) < 30:
        raise ValueError("need at least 30 history rows (a few hours of polling)")
    before = mae(history, base)
    if before["windows"] < min_windows:
        raise ValueError(f"only {before['windows']} replay windows in this history; need at least {min_windows} "
                         "(about 2-3 hours of data) to fit without overfitting")
    cur = dict(base)
    for _ in range(passes):
        for k in fields:
            if base.get(k, 0) <= 0:
                continue
            def f(logv, k=k):
                trial = dict(cur); trial[k] = math.exp(logv)
                return loss(history, trial)
            c = math.log(cur[k])
            cur[k] = math.exp(_golden(f, c - math.log(span), c + math.log(span)))
    after = mae(history, cur)
    return {"params": {k: round(cur[k], 5) for k in fields}, "before": before, "after": after,
            "full": cur, "rows": len(history)}


def read_history_csv(path: str | Path) -> list[dict]:
    rows = []
    with open(path) as f:
        for r in csv.DictReader(f):
            rows.append({k: float(v) for k, v in r.items() if v not in ("", None)})
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--history", default="data/history.csv")
    ap.add_argument("--write", action="store_true", help="save fitted values into config/process.json")
    a = ap.parse_args()
    res = fit(read_history_csv(a.history))
    print(json.dumps({k: res[k] for k in ("params", "before", "after", "rows")}, indent=2))
    if a.write:
        p = json.loads(Path(PROCESS_PATH).read_text())
        p.update(res["params"])
        Path(PROCESS_PATH).write_text(json.dumps(p, indent=2))
        print(f"updated {PROCESS_PATH}")


if __name__ == "__main__":
    main()
