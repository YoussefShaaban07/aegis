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
from .forewarn import first_crossings
from .guard import Guard
from .plant import Plant
from .twin import Twin

GOALS = {
    "caustic": ("naoh_dose", +1),       # pH up
    "no_disinfection": ("chlorine_dose", -1),
    "chlorine_overdose": ("chlorine_dose", +1),
    "drain_clearwell": ("distribution_rate", +1),
    "cycle_equipment": ("distribution_rate", 0),   # oscillate: wear pumps/valves, pressure surges
}
# stepper: largest legal step every `gap` s.  prober: binary-searches the largest change the
# guard accepts (<= 4 tries per write, staying under the flood limit).  timed: waits for the
# weather to turn (storm/bloom) and then attacks, exploiting the plant at its weakest.
STRATEGIES = ("stepper", "prober", "timed")
CYCLE_HARM = 10          # >= 10 large reversals executed = equipment stress counted as harm
LIMITS = {"ph": (6.5, 8.5), "chlorine": (0.2, 4.0), "tank": (5.0, 101.0)}
FIDELITY = "standard"     # "high": the simulated plant has physics the twin doesn't model
SAFE_HOLD = False         # twin guard also runs safe-hold (auto-revert when a warning goes unanswered)
ATTACKER = "unknown"      # "hmi": the attacker owns the operator HMI (writes as a trusted source)
LAB: dict | None = None   # {"hours": 24, "keys": ["raw_alkalinity"]}: those readings come from lab grab samples


def seen(plant: Plant) -> dict:
    """What Aegis sees: the PLC's readings, except lab-only values, which are the last grab sample."""
    snap = plant.snapshot()
    if LAB and getattr(plant, "lab", None):
        snap.update(plant.lab)
    return snap


def lab_tick(plant: Plant, minute: int, seed: int):
    """Take a grab sample every LAB['hours'] (at a seed-dependent time of day)."""
    if not LAB:
        return
    period = int(LAB["hours"] * 60)
    if minute == 0 or (minute - (seed * 37) % period) % period == 0:
        snap = plant.snapshot()
        plant.lab = {k: snap[k] for k in LAB["keys"]}


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
    g.safehold = None
    if twin and SAFE_HOLD:
        from .safehold import SafeHold
        g.safehold = SafeHold(g, {**(policy.get("safe_hold") or {}), "enabled": True})
    return g


def run_safe_hold(g: Guard, plant: Plant, minute: int, every: int = 5):
    """The deployed gateway polls every 10 s; every 5 simulated minutes is enough here. Nobody acks."""
    if g.safehold is None or minute % every:
        return None
    act = g.safehold.update(seen(plant), g.clock())
    if act:
        g.apply_safe_hold(act)
        plant.set(act["register"], act["value"])
    return act


def attack_episode(seed: int, use_twin: bool | None, policy: dict, hours: int = 8) -> dict:
    """use_twin=None runs the same episode (same weather, same seed) with NO attacker: the baseline."""
    rng = random.Random(seed)
    plant = Plant(noise=True, seed=seed, fidelity=FIDELITY)
    plant.speed = 60
    clock = Clock()
    g = make_guard(plant, use_twin, clock, policy)
    goal = rng.choice(list(GOALS))
    strategy = rng.choice(STRATEGIES)
    reg, direction = GOALS[goal]
    lim = policy["limits"][reg]
    weather_at = rng.randint(0, hours * 60)
    weather = rng.choice(["normal", "normal", "storm", "bloom"])
    start = rng.randint(0, 120)
    if strategy == "timed" and weather != "normal":
        start = min(hours * 60 - 60, weather_at + rng.randint(10, 60))
    gap = rng.choice([61, 75, 120, 300, 900]) if goal != "cycle_equipment" else rng.choice([61, 90, 120])
    step = (lim.get("max_step") or (lim["max"] - lim["min"])) * rng.uniform(0.5, 1.0)
    target = lim["max"] if direction > 0 else lim["min"]
    tries = blocked = cycles = 0
    harm, harm_at, alarm_at, fore_at = None, None, None, None
    peak = 0.0
    watch_twin = Twin()
    next_write = start * 60
    src, peer = ("Operator HMI", "10.0.0.5:5000") if ATTACKER == "hmi" else ("Unknown device (unit 66)", "10.9.9.9:4444")
    reverts = 0

    def attempt(new):
        nonlocal tries, blocked
        d = g.check(reg, new, seen(plant), src, peer)
        tries += 1
        if d.allowed:
            g._commit(d)
            plant.set(reg, new)
            return True
        blocked += 1
        return False

    for minute in range(hours * 60 + 360):
        lab_tick(plant, minute, seed)
        clock.t = minute * 60.0
        if minute == weather_at:
            plant.set_scenario(weather)
        if g.twin is not None:
            g.twin.observe(seen(plant), clock.t)      # the deployed gateway does this every poll
        if use_twin is not None and minute < hours * 60 and clock.t >= next_write:
            cur = plant.setpoint(reg)
            if goal == "cycle_equipment":
                new = 300 if cur >= 500 else 700
                if attempt(new) and abs(new - cur) >= 150:
                    cycles += 1
            elif (direction > 0 and cur < target) or (direction < 0 and cur > target):
                want = round(min(target, cur + step) if direction > 0 else max(target, cur - step), 2)
                if strategy == "prober":
                    want = target                      # start at the goal, halve the change until accepted
                    for _ in range(4):
                        if attempt(round(want, 2)):
                            break
                        want = cur + (want - cur) / 2
                        if abs(want - cur) < 0.01:
                            break
                else:
                    attempt(want)
            next_write += gap
        if use_twin and run_safe_hold(g, plant, minute):
            reverts += 1
        plant.step(1.0)
        if fore_at is None and minute % 10 == 0 and first_crossings(
                watch_twin.forecast(seen(plant), None, 180, every_min=10)):
            fore_at = minute            # twin forecast crosses a limit -> early-warning SMS
        if alarm_at is None and plant.alarms():
            alarm_at = minute           # process alarm -> Aegis texts/calls the operator
        peak = max(peak, severity(plant))
        if harm is None:
            harm = harmful(plant)
            if harm:
                harm_at = minute
        if harm is None and goal == "cycle_equipment" and cycles >= CYCLE_HARM:
            harm, harm_at = "equipment cycling", minute
    return {"seed": seed, "goal": goal, "strategy": strategy, "weather": weather, "twin": use_twin,
            "tries": tries, "blocked": blocked, "cycles": cycles, "reverts": reverts, "peak_severity": round(peak, 4),
            "harm": harm, "harm_at_min": harm_at, "alarm_at_min": alarm_at, "forewarn_at_min": fore_at,
            "warning_min": (harm_at - alarm_at) if (harm_at is not None and alarm_at is not None) else None,
            "forewarn_min": (harm_at - fore_at) if (harm_at is not None and fore_at is not None) else None}


def operator_episode(seed: int, use_twin: bool, policy: dict, hours: int = 12) -> dict:
    """A plausible operator: trims, reacts to weather, sometimes overshoots. Ground truth per write."""
    rng = random.Random(10_000 + seed)
    plant = Plant(noise=True, seed=seed, fidelity=FIDELITY)
    clock = Clock()
    g = make_guard(plant, use_twin, clock, policy)
    weather_at = rng.randint(30, hours * 60 - 120)
    weather = rng.choice(["storm", "bloom", "normal"])
    writes, reverts = [], []
    next_action = rng.randint(10, 60)
    for minute in range(hours * 60):
        lab_tick(plant, minute, seed)
        clock.t = minute * 60.0
        if minute == weather_at:
            plant.set_scenario(weather)
        if g.twin is not None:
            g.twin.observe(seen(plant), clock.t)
        if minute >= next_action:
            s = plant.snapshot()
            # what a reasonable operator would try
            if s["chlorine_residual"] < 0.6 and plant.setpoint("chlorine_dose") < 3.5:
                reg, new = "chlorine_dose", round(plant.setpoint("chlorine_dose") + rng.choice([0.2, 0.3, 0.5]), 2)
            elif s["ph"] > 7.9 and plant.setpoint("naoh_dose") > 0:
                reg, new = "naoh_dose", max(0, plant.setpoint("naoh_dose") - rng.choice([10, 20, 40]))
            elif s["ph"] < 7.1:
                reg, new = "naoh_dose", plant.setpoint("naoh_dose") + rng.choice([5, 10, 20])
            elif s["tank_level"] < 40 and plant.setpoint("distribution_rate") > 450:
                reg, new = "distribution_rate", plant.setpoint("distribution_rate") - rng.choice([50, 100])
            else:
                reg = rng.choice(["naoh_dose", "chlorine_dose", "distribution_rate"])
                cur = plant.setpoint(reg)
                # a real operator watches the clearwell: raise distribution only when it's comfortably full
                dist = rng.choice([50, 100]) if s["tank_level"] > 70 else rng.choice([-100, -50, 50])
                delta = {"naoh_dose": rng.choice([-10, -5, 5, 10, 25]), "chlorine_dose": rng.choice([-0.2, -0.1, 0.1, 0.2]),
                         "distribution_rate": dist}[reg]
                lim = policy["limits"][reg]
                new = round(min(lim["max"], max(lim["min"], cur + delta)), 2)
            d = g.check(reg, new, seen(plant), "Operator HMI", "10.0.0.5:5000")
            trial = copy.deepcopy(plant); trial.set(reg, new)
            truth_with, truth_without = forward_harm(trial), forward_harm(plant)
            writes.append({"reg": reg, "new": new, "allowed": d.allowed, "check": d.check,
                           "truth_with": truth_with, "truth_without": truth_without})
            if d.allowed:
                g._commit(d)
                plant.set(reg, new)
            next_action = minute + rng.randint(20, 90)
        if use_twin and g.safehold is not None and minute % 5 == 0:
            before = copy.deepcopy(plant)
            act = run_safe_hold(g, plant, minute)
            if act:      # ground truth: did undoing the operator's change make the true outcome better?
                reverts.append({"register": act["register"], "value": act["value"], "from": act["from"],
                                "truth_with": forward_harm(copy.deepcopy(plant)), "truth_without": forward_harm(before)})
        plant.step(1.0)
    return {"seed": seed, "twin": use_twin, "weather": weather, "writes": writes, "reverts": reverts}


def attacker_caused(e: dict, b: dict) -> bool:
    """Harm the attacker is responsible for: unsafe when the same weather without the attacker
    was safe, or clearly worse than without it (peak severity +50% and +0.02, or harm 30+ min sooner)."""
    if e["harm"] is None:
        return False
    if b["harm"] is None:
        return True
    if e["harm"] == "equipment cycling":
        return True
    worse = e["peak_severity"] > b["peak_severity"] * 1.5 + 0.02
    sooner = b["harm_at_min"] is not None and e["harm_at_min"] is not None and e["harm_at_min"] < b["harm_at_min"] - 30
    return worse or sooner


def summarize(attacks: list[dict], operators: list[dict]) -> dict:
    """An attack counts as successful only for harm the attacker caused (see attacker_caused)."""
    base = {e["seed"]: e for e in attacks if e["twin"] is None}
    out = {"weather_alone_unsafe": sum(b["harm"] is not None for b in base.values()), "episodes": len(base)}
    for e in attacks:
        if e["twin"] is not None:
            e["caused"] = attacker_caused(e, base[e["seed"]])
    for mode in (False, True):
        a = [e for e in attacks if e["twin"] == mode]
        by_goal = {}
        for gname in GOALS:
            ge = [e for e in a if e["goal"] == gname]
            warn = sorted(e["warning_min"] for e in ge if e["caused"] and e["warning_min"] is not None)
            fw = sorted(e["forewarn_min"] for e in ge if e["caused"] and e["forewarn_min"] is not None)
            by_goal[gname] = {"episodes": len(ge), "harmful": sum(e["caused"] for e in ge),
                              "median_warning_min": warn[len(warn) // 2] if warn else None,
                              "median_forewarn_min": fw[len(fw) // 2] if fw else None}
        by_strategy = {st: {"episodes": sum(e["strategy"] == st for e in a),
                            "harmful": sum(e["strategy"] == st and e["caused"] for e in a)}
                       for st in STRATEGIES}
        o = [w for e in operators if e["twin"] == mode for w in e["writes"]]
        pred_blocks = [w for w in o if w["check"] == "predict"]
        worse = lambda w: w["truth_with"] > 0 and w["truth_with"] > w["truth_without"] + 1e-3
        justified = [w for w in pred_blocks if worse(w)]
        unjust = [w for w in pred_blocks if not worse(w)]
        missed = [w for w in o if w["allowed"] and worse(w)]
        out["twin" if mode else "static"] = {
            "attack_episodes": len(a), "attack_harmful": sum(e["caused"] for e in a),
            "by_goal": by_goal, "by_strategy": by_strategy,
            "operator_writes": len(o), "operator_blocked_any_rule": sum(not w["allowed"] for w in o),
            "operator_blocked_by_twin": len(pred_blocks), "twin_blocks_justified": len(justified),
            "twin_false_blocks": len(unjust), "operator_mistakes_let_through": len(missed),
            "attack_reverts": sum(e.get("reverts", 0) for e in a),
            "operator_reverts": sum(len(e.get("reverts", [])) for e in operators if e["twin"] == mode),
            "operator_reverts_helpful": sum(r["truth_with"] < r["truth_without"] - 1e-3
                                            for e in operators if e["twin"] == mode for r in e.get("reverts", [])),
            "operator_reverts_harmful": sum(r["truth_with"] > r["truth_without"] + 1e-3
                                            for e in operators if e["twin"] == mode for r in e.get("reverts", [])),
        }
    return out


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--episodes", type=int, default=200)
    ap.add_argument("--operator-episodes", type=int, default=40)
    ap.add_argument("--json", default=None, help="write all episode results here")
    ap.add_argument("--seed-offset", type=int, default=0,
                    help="seeds 0.. were used while developing and tuning; report results on unseen "
                         "seeds, e.g. --seed-offset 100000")
    ap.add_argument("--fidelity", choices=["standard", "high"], default="standard",
                    help="high = test the twin against a plant with physics it doesn't model")
    ap.add_argument("--uncertainty", type=float, default=None,
                    help="scale the twin's uncertainty band (1 = policy default; e.g. 0.4 after calibration)")
    ap.add_argument("--safe-hold", action="store_true",
                    help="the twin guard also runs safe-hold (auto-revert after 15 min of unanswered warning)")
    ap.add_argument("--lab-hours", type=float, default=None,
                    help="the plant has no online analyzer for --lab-keys: Aegis only gets a lab grab sample every N h")
    ap.add_argument("--lab-keys", default="raw_alkalinity", help="comma list, e.g. raw_alkalinity,raw_turbidity")
    ap.add_argument("--attacker", choices=["unknown", "hmi"], default="unknown",
                    help="hmi = the attacker has taken over the operator HMI and writes as a trusted source")
    a = ap.parse_args(argv)
    global FIDELITY, SAFE_HOLD, ATTACKER, LAB
    FIDELITY, SAFE_HOLD, ATTACKER = a.fidelity, a.safe_hold, a.attacker
    LAB = {"hours": a.lab_hours, "keys": a.lab_keys.split(",")} if a.lab_hours else None
    print(f"plant fidelity: {FIDELITY}; attacker writes as: {ATTACKER}; safe-hold: {'on' if SAFE_HOLD else 'off'}"
          + (f"; {', '.join(LAB['keys'])} from a lab sample every {a.lab_hours:g} h" if LAB else ""))
    policy = load_policy(Tags.load())
    if a.uncertainty is not None:
        u = policy["prediction"].get("uncertainty") or {"naoh_feed_strength": 0.1, "chlorine_decay_per_hr": 0.3,
                                                         "chlorine_demand": 0.25}
        policy["prediction"]["uncertainty"] = {k: v * a.uncertainty for k, v in u.items()}
        print(f"twin uncertainty: {policy['prediction']['uncertainty']}")
    t0 = time.time()
    seeds = range(a.seed_offset, a.seed_offset + a.episodes)
    print(f"seeds {seeds.start}..{seeds.stop - 1}" + ("  (HELD OUT: not used during development)" if a.seed_offset else
                                                       "  (development seeds)"))
    attacks = [attack_episode(s, tw, policy) for s in seeds for tw in (None, False, True)]
    ops = [operator_episode(s, tw, policy) for s in range(a.seed_offset, a.seed_offset + a.operator_episodes)
           for tw in (False, True)]
    res = summarize(attacks, ops)
    if a.json:
        import json
        Path(a.json).write_text(json.dumps({"summary": res, "attacks": attacks,
                                            "operators": [{k: v for k, v in e.items()} for e in ops]}, indent=1, default=str))
    print(f"{a.episodes} attack episodes and {a.operator_episodes} operator episodes per guard "
          f"({time.time() - t0:.0f} s)")
    print(f"{res['weather_alone_unsafe']} of {res['episodes']} episodes were unsafe from weather alone (nobody "
          "responding). An attack counts only if it caused harm or made it clearly worse/sooner.\n")
    for mode in ("static", "twin"):
        r = res[mode]
        print(f"== {mode} ==")
        print(f"  attacks that made the water unsafe: {r['attack_harmful']}/{r['attack_episodes']} "
              f"({100 * r['attack_harmful'] / max(1, r['attack_episodes']):.0f}%)")
        for gname, v in r["by_goal"].items():
            w = (f"   (warning before harm, median: alarm {v['median_warning_min']} min, twin forecast "
                 f"{v['median_forewarn_min']} min)") if v["median_warning_min"] is not None else ""
            print(f"    {gname:18} {v['harmful']}/{v['episodes']}{w}")
        print("    by attacker strategy: " + ", ".join(f"{k} {v['harmful']}/{v['episodes']}"
                                                       for k, v in r["by_strategy"].items()))
        print(f"  operator writes: {r['operator_writes']}, blocked by any rule: {r['operator_blocked_any_rule']}, "
              f"by twin: {r['operator_blocked_by_twin']} (justified {r['twin_blocks_justified']}, "
              f"false {r['twin_false_blocks']}); unsafe operator writes let through: {r['operator_mistakes_let_through']}")
        if SAFE_HOLD and mode == "twin":
            print(f"  safe-hold reverts: {r['attack_reverts']} in attack episodes; {r['operator_reverts']} of operator "
                  f"changes (helpful {r['operator_reverts_helpful']}, harmful {r['operator_reverts_harmful']}, "
                  f"neutral {r['operator_reverts'] - r['operator_reverts_helpful'] - r['operator_reverts_harmful']})")
    return res


if __name__ == "__main__":
    main()
