"""Learn-normal: suggest safety rules from observed traffic.

Writing a safety envelope from scratch is the hardest part of deploying any
guard, and small utilities don't have an OT security engineer to do it. So
Aegis can run in monitor mode for a trial period, watch every write that goes
to the PLC, and then *suggest* rules from what it saw:

  normal     observed min/max widened by a margin -> an ALERT-ONLY band. Values
             outside it are still allowed (a storm can legitimately need more
             chlorine than a calm week ever saw) but the operator is told.
             The hard min/max are never changed by learning.
  max_step   3 x the largest single change actually used (never looser than now)
  ramp       3 x the largest net change in any 60 s window (never looser than now)
  flood      2 x the busiest minute of the busiest source (at least 5)
  writers    which sources ever wrote each setpoint (informational: labels are spoofable)

These are suggestions, not rules: an engineer reviews the diff and applies it
with the engineer PIN. Statistics, not AI, so the suggestions are reproducible.

CLI:  python -m aegis.learn --db data/audit.db --hours 168
"""
from __future__ import annotations

import argparse
import copy
import json
import math
import random
from collections import defaultdict

MIN_OBS = 15


def _nice(x: float) -> float:
    """Round up to a human-friendly number (1, 2, 2.5, 5 x 10^n)."""
    if x <= 0:
        return 0
    e = math.floor(math.log10(x))
    for m in (1, 2, 2.5, 5, 10):
        if m * 10 ** e >= x - 1e-12:
            return round(m * 10 ** e, 6)
    return x


def observations_from_audit(entries: list[dict]) -> list[dict]:
    """Writes that actually reached the PLC (allowed, or passed in monitor/off mode)."""
    out = []
    for e in entries:
        d = e["data"]
        if e["kind"] == "decision" and d.get("allowed") and d.get("check") != "function":
            out.append({"t": d.get("t", e["t"]), "register": d["register"], "old": d.get("old"),
                        "new": d["new"], "source": d.get("source", "?")})
    return out


def suggest(obs: list[dict], policy: dict, margin: float = 0.15) -> dict:
    by_reg: dict[str, list[dict]] = defaultdict(list)
    for o in sorted(obs, key=lambda o: o["t"]):
        by_reg[o["register"]].append(o)
    new = copy.deepcopy(policy)
    changes, notes = [], []
    writers = {}

    for reg, lim in policy["limits"].items():
        rows = by_reg.get(reg, [])
        writers[reg] = sorted({r["source"] for r in rows})
        if len(rows) < MIN_OBS:
            notes.append(f"{reg}: only {len(rows)} writes observed (need {MIN_OBS}); left unchanged")
            continue
        vals = [r["new"] for r in rows] + [r["old"] for r in rows if r["old"] is not None]
        lo, hi = min(vals), max(vals)
        is_bool = lim["max"] - lim["min"] <= 1 and all(v in (0, 1) for v in vals)
        s = dict(lim)
        if not is_bool:
            span = max(hi - lo, abs(hi) * 0.1, 1e-6)
            s["normal"] = [max(lim["min"], round(lo - margin * span, 4)),
                           min(lim["max"], round(hi + margin * span, 4))]
            steps = [abs(r["new"] - r["old"]) for r in rows if r["old"] is not None and r["new"] != r["old"]]
            if steps:
                cand = _nice(3 * max(steps))
                s["max_step"] = cand if lim.get("max_step") is None else min(lim["max_step"], cand)
            # largest net change within any 60 s window
            net, j = 0.0, 0
            for i, r in enumerate(rows):
                while rows[j]["t"] < r["t"] - 60:
                    j += 1
                base = rows[j]["old"] if rows[j]["old"] is not None else rows[j]["new"]
                net = max(net, abs(r["new"] - base))
            if net > 0:
                cand = _nice(3 * net)
                s["max_change_per_min"] = cand if lim.get("max_change_per_min") is None else min(
                    lim["max_change_per_min"], cand)
        for k in ("normal", "max_step", "max_change_per_min"):
            if s.get(k) != lim.get(k):
                changes.append({"register": reg, "field": k, "current": lim.get(k), "suggested": s[k],
                                "direction": "alert band" if k == "normal" else "tighter"})
        new["limits"][reg] = s

    # flood: busiest minute per source
    per_min = defaultdict(int)
    for o in obs:
        per_min[(o["source"], int(o["t"] // 60))] += 1
    if obs:
        busiest = max(per_min.values())
        cand = max(5, 2 * busiest)
        cur = policy["max_writes_per_min_per_source"]
        if cand < cur:
            new["max_writes_per_min_per_source"] = cand
            changes.append({"register": "*", "field": "max_writes_per_min_per_source", "current": cur,
                            "suggested": cand, "direction": "tighter"})
    span_h = (max(o["t"] for o in obs) - min(o["t"] for o in obs)) / 3600 if len(obs) > 1 else 0
    return {"policy": new, "changes": changes, "notes": notes, "writers": writers,
            "based_on": {"writes": len(obs), "hours": round(span_h, 1)}}


def simulated_week(seed: int = 11, start: float = 0.0) -> list[dict]:
    """SIMULATED normal operator activity for demos/tests (clearly not real data):
    a few lye and chlorine trims per shift, daily distribution-rate changes, rare pump cycling."""
    rng = random.Random(seed)
    obs, cur = [], {"naoh_dose": 100, "chlorine_dose": 1.5, "distribution_rate": 500,
                    "intake_pump": 1, "distribution_pump": 1}
    t = start
    for day in range(7):
        for shift in range(3):
            t0 = start + day * 86400 + shift * 28800
            for _ in range(rng.randint(2, 4)):
                t = t0 + rng.uniform(0, 28000)
                reg = rng.choice(["naoh_dose", "chlorine_dose", "chlorine_dose"])
                if reg == "naoh_dose":
                    v = min(130, max(80, cur[reg] + rng.choice([-10, -5, 5, 10])))
                else:
                    v = round(min(2.0, max(1.2, cur[reg] + rng.choice([-0.1, 0.1, 0.2, -0.2]))), 2)
                obs.append({"t": t, "register": reg, "old": cur[reg], "new": v, "source": "Operator HMI"})
                cur[reg] = v
        for _ in range(2):
            t = start + day * 86400 + rng.uniform(0, 86000)
            v = min(650, max(350, cur["distribution_rate"] + rng.choice([-100, -50, 50, 100])))
            obs.append({"t": t, "register": "distribution_rate", "old": cur["distribution_rate"], "new": v,
                        "source": "Operator HMI"})
            cur["distribution_rate"] = v
        if day % 2 == 0:
            for reg in ("intake_pump", "distribution_pump"):
                t = start + day * 86400 + rng.uniform(0, 80000)
                obs += [{"t": t, "register": reg, "old": 1, "new": 0, "source": "Operator HMI"},
                        {"t": t + 900, "register": reg, "old": 0, "new": 1, "source": "Operator HMI"}]
    return sorted(obs, key=lambda o: o["t"])


def main():
    from .audit import AuditLog
    from .config import Tags, load_policy
    p = argparse.ArgumentParser(description="Suggest safety rules from observed writes in the audit log")
    p.add_argument("--db", default=None)
    p.add_argument("--hours", type=float, default=168)
    a = p.parse_args()
    import time
    audit = AuditLog(a.db)
    obs = observations_from_audit(audit.between(time.time() - a.hours * 3600, kinds=("decision",)))
    print(json.dumps(suggest(obs, load_policy(Tags.load())), indent=2))


if __name__ == "__main__":
    main()
