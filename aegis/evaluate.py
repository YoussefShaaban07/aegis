"""Evaluation harness: does the digital twin actually matter, and does it get in the way?

Runs randomized episodes on the simulator (which uses the *true* plant
parameters, deliberately different from the twin's) through two guards:

  static   range, step, ramp, interlock, flood rules only
  twin     the same rules + the digital-twin predict check

Attack episodes: an attacker that knows the static rules (never exceeds a
max step, waits out the ramp window) pursues a goal: caustic water (lye up),
no disinfection (chlorine down), chlorine overdose, or draining the clearwell
(distribution up). Random weather (normal / storm / algae bloom), random start
times and step sizes.

Operator episodes: a plausible operator making small trims, responding to
weather (raising chlorine in storms, cutting lye in blooms), sometimes over-
shooting. Ground truth for each write: run the TRUE plant forward 6 h from
that moment with and without the write; a block is "justified" if the write
made the outcome unsafe, otherwise it's a false block.

"Harm" = the true plant leaves pH 6.5-8.5, chlorine 0.2-4.0 mg/L, or the
clearwell drops below 5% at any point during the episode or 6 h after.

Everything is seeded and reproducible:
    python -m aegis.evaluate --episodes 300
The operator and attacker models are simple and written by us: this measures
the guard against these behaviours, not against real attackers.
"""
from __future__ import annotations

import argparse
import copy
from pathlib import Path
import random
import time
from dataclasses import dataclass

from .config import Tags, load_policy
from .guard import Guard
from .plant import Plant
from .twin import Twin

GOALS = {
    "caustic": ("naoh_dose", +1),       # pH up
    "no_disinfection": ("chlorine_dose", -1),
    "chlorine_overdose": ("chlorine_dose", +1),
    "drain_clearwell": ("distribution_rate", +1),
}
LIMITS = {"ph": (6.5, 8.5), "chlorine": (0.2, 4.0), "tank": (5.0, 101.0)}


def harmful(plant: Plant) -> str | None:
    if not LIMITS["ph"][0] <= plant.ph <= LIMITS["ph"][1]:
        return "pH"
    if not LIMITS["chlorine"][0] <= plant.chlorine <= LIMITS["chlorine"][1]:
        return "chlorine"
    if plant.tank_level < LIMITS["tank"][0]:
        return "clearwell empty"
    return None


def severity(plant: Plant) -> float:
    ex = [max(LIMITS["ph"][0] - plant.ph, plant.ph - LIMITS["ph"][1], 0) / 2.0,
          max(LIMITS["chlorine"][0] - plant.chlorine, plant.chlorine - LIMITS["chlorine"][1], 0) / 3.8,
          max(LIMITS["tank"][0] - plant.tank_level, 0) / 95]
    return max(ex)


def forward_harm(plant: Plant, minutes: int = 600) -> float:
    """Ground truth: worst excursion of the TRUE plant over the next `minutes` if nothing else changes."""
    p = copy.deepcopy(plant)
    p.noise = False
    worst = 0.0
    for _ in range(minutes // 5):
        p.step(5.0)
        worst = max(worst, severity(p))
    return worst


@dataclass
class Clock:
    t: float = 0.0

    def __call__(self):
        return self.t


def make_guard(plant: Plant, twin: bool, clock: Clock, policy: dict):
    g = Guard(None, plant.snapshot, policy=policy, clock=clock, twin=Twin() if twin else None)
    return g


def attack_episode(seed: int, use_twin: bool | None, policy: dict, hours: int = 8) -> dict:
    """use_twin=None runs the same episode (same weather, same seed) with NO attacker: the baseline."""
    rng = random.Random(seed)
    plant = Plant(noise=True, seed=seed)
    plant.speed = 60
    clock = Clock()
    g = make_guard(plant, use_twin, clock, policy)
    goal = rng.choice(list(GOALS))
    reg, direction = GOALS[goal]
    lim = policy["limits"][reg]
    weather_at = rng.randint(0, hours * 60)
    weather = rng.choice(["normal", "normal", "storm", "bloom"])
    start = rng.randint(0, 120)
    gap = rng.choice([61, 75, 120, 300, 900])          # seconds between attacker writes (ramp-aware)
    step = (lim.get("max_step") or (lim["max"] - lim["min"])) * rng.uniform(0.5, 1.0)
    target = lim["max"] if direction > 0 else lim["min"]
    tries = blocked = 0
    harm, harm_at, alarm_at = None, None, None
    next_write = start * 60
    for minute in range(hours * 60 + 360):
        clock.t = minute * 60.0
        if minute == weather_at:
            plant.set_scenario(weather)
        if use_twin is not None and minute < hours * 60 and clock.t >= next_write:
            cur = plant.setpoint(reg)
            if (direction > 0 and cur < target) or (direction < 0 and cur > target):
                new = round(min(target, cur + step) if direction > 0 else max(target, cur - step), 2)
                d = g.check(reg, new, plant.snapshot(), "Unknown device (unit 66)", "10.9.9.9:4444")
                tries += 1
                if d.allowed:
                    g._commit(d)
                    plant.set(reg, new)
                else:
                    blocked += 1
            next_write += gap
        plant.step(1.0)
        if alarm_at is None and plant.alarms():
            alarm_at = minute           # process alarm -> Aegis texts/calls the operator
        if harm is None:
            harm = harmful(plant)
            if harm:
                harm_at = minute
    return {"seed": seed, "goal": goal, "weather": weather, "twin": use_twin, "tries": tries, "blocked": blocked,
            "harm": harm, "harm_at_min": harm_at, "alarm_at_min": alarm_at,
            "warning_min": (harm_at - alarm_at) if (harm_at is not None and alarm_at is not None) else None}


def operator_episode(seed: int, use_twin: bool, policy: dict, hours: int = 12) -> dict:
    """A plausible operator: trims, reacts to weather, sometimes overshoots. Ground truth per write."""
    rng = random.Random(10_000 + seed)
    plant = Plant(noise=True, seed=seed)
    clock = Clock()
    g = make_guard(plant, use_twin, clock, policy)
    weather_at = rng.randint(30, hours * 60 - 120)
    weather = rng.choice(["storm", "bloom", "normal"])
    writes = []
    next_action = rng.randint(10, 60)
    for minute in range(hours * 60):
        clock.t = minute * 60.0
        if minute == weather_at:
            plant.set_scenario(weather)
        if minute >= next_action:
            s = plant.snapshot()
            # what a reasonable operator would try
            if s["chlorine_residual"] < 0.6 and plant.setpoint("chlorine_dose") < 3.5:
                reg, new = "chlorine_dose", round(plant.setpoint("chlorine_dose") + rng.choice([0.2, 0.3, 0.5]), 2)
            elif s["ph"] > 7.9 and plant.setpoint("naoh_dose") > 0:
                reg, new = "naoh_dose", max(0, plant.setpoint("naoh_dose") - rng.choice([10, 20, 40]))
            elif s["ph"] < 7.1:
                reg, new = "naoh_dose", plant.setpoint("naoh_dose") + rng.choice([5, 10, 20])
            else:
                reg = rng.choice(["naoh_dose", "chlorine_dose", "distribution_rate"])
                cur = plant.setpoint(reg)
                delta = {"naoh_dose": rng.choice([-10, -5, 5, 10, 25]), "chlorine_dose": rng.choice([-0.2, -0.1, 0.1, 0.2]),
                         "distribution_rate": rng.choice([-100, -50, 50, 100])}[reg]
                lim = policy["limits"][reg]
                new = round(min(lim["max"], max(lim["min"], cur + delta)), 2)
            d = g.check(reg, new, plant.snapshot(), "Operator HMI", "10.0.0.5:5000")
            trial = copy.deepcopy(plant); trial.set(reg, new)
            truth_with, truth_without = forward_harm(trial), forward_harm(plant)
            writes.append({"reg": reg, "new": new, "allowed": d.allowed, "check": d.check,
                           "truth_with": truth_with, "truth_without": truth_without})
            if d.allowed:
                g._commit(d)
                plant.set(reg, new)
            next_action = minute + rng.randint(20, 90)
        plant.step(1.0)
    return {"seed": seed, "twin": use_twin, "weather": weather, "writes": writes}


def summarize(attacks: list[dict], operators: list[dict]) -> dict:
    """Attack harm counts only episodes where the same weather WITHOUT the attacker stayed safe."""
    base = {e["seed"]: e["harm"] for e in attacks if e["twin"] is None}
    out = {"weather_alone_unsafe": sum(h is not None for h in base.values()), "episodes": len(base)}
    for mode in (False, True):
        a = [e for e in attacks if e["twin"] == mode and base.get(e["seed"]) is None]
        by_goal = {}
        for gname in GOALS:
            ge = [e for e in a if e["goal"] == gname]
            warn = sorted(e["warning_min"] for e in ge if e["harm"] and e["warning_min"] is not None)
            by_goal[gname] = {"episodes": len(ge), "harmful": sum(e["harm"] is not None for e in ge),
                              "median_warning_min": warn[len(warn) // 2] if warn else None}
        o = [w for e in operators if e["twin"] == mode for w in e["writes"]]
        pred_blocks = [w for w in o if w["check"] == "predict"]
        worse = lambda w: w["truth_with"] > 0 and w["truth_with"] > w["truth_without"] + 1e-3
        justified = [w for w in pred_blocks if worse(w)]
        unjust = [w for w in pred_blocks if not worse(w)]
        missed = [w for w in o if w["allowed"] and worse(w)]
        out["twin" if mode else "static"] = {
            "attack_episodes": len(a), "attack_harmful": sum(e["harm"] is not None for e in a),
            "by_goal": by_goal,
            "operator_writes": len(o), "operator_blocked_any_rule": sum(not w["allowed"] for w in o),
            "operator_blocked_by_twin": len(pred_blocks), "twin_blocks_justified": len(justified),
            "twin_false_blocks": len(unjust), "operator_mistakes_let_through": len(missed),
        }
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--episodes", type=int, default=200)
    ap.add_argument("--operator-episodes", type=int, default=40)
    ap.add_argument("--json", default=None, help="write all episode results here")
    a = ap.parse_args(argv)
    policy = load_policy(Tags.load())
    t0 = time.time()
    attacks = [attack_episode(s, tw, policy) for s in range(a.episodes) for tw in (None, False, True)]
    ops = [operator_episode(s, tw, policy) for s in range(a.operator_episodes) for tw in (False, True)]
    res = summarize(attacks, ops)
    if a.json:
        import json
        Path(a.json).write_text(json.dumps({"summary": res, "attacks": attacks,
                                            "operators": [{k: v for k, v in e.items()} for e in ops]}, indent=1, default=str))
    print(f"{a.episodes} attack episodes and {a.operator_episodes} operator episodes per guard "
          f"({time.time() - t0:.0f} s)")
    print(f"{res['weather_alone_unsafe']} of {res['episodes']} episodes were unsafe from weather alone "
          "(no attacker); they are excluded from the attack counts.\n")
    for mode in ("static", "twin"):
        r = res[mode]
        print(f"== {mode} ==")
        print(f"  attacks that made the water unsafe: {r['attack_harmful']}/{r['attack_episodes']} "
              f"({100 * r['attack_harmful'] / max(1, r['attack_episodes']):.0f}%)")
        for gname, v in r["by_goal"].items():
            w = f"   (median {v['median_warning_min']} min from alarm/SMS to harm)" if v["median_warning_min"] is not None else ""
            print(f"    {gname:18} {v['harmful']}/{v['episodes']}{w}")
        print(f"  operator writes: {r['operator_writes']}, blocked by any rule: {r['operator_blocked_any_rule']}, "
              f"by twin: {r['operator_blocked_by_twin']} (justified {r['twin_blocks_justified']}, "
              f"false {r['twin_false_blocks']}); unsafe operator writes let through: {r['operator_mistakes_let_through']}")
    return res


if __name__ == "__main__":
    main()
