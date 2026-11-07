"""Alert load: how many texts would Aegis send an operator in an ordinary week?

Judge round 10: "operators already ignore their alarms; you're adding another
pager." This runs the noisy, mismatched plant simulator for whole weeks of
ordinary life (calm days, plus storms and algae blooms that come and go) with a
simulated operator who runs the plant sensibly, acknowledges texts after a delay
and responds to them. It counts every message Aegis would send (SMS, calls,
escalations) and sorts them by cause and by kind of day.

    python -m aegis.alertload --weeks 4
    python -m aegis.alertload --weeks 4 --json docs/eval/alert_load.json

The number to watch: texts on CALM days. Every one of those is a nuisance alert.
Texts on weather days are the system doing its job, but too many still teach
people to ignore it.
"""
from __future__ import annotations

import argparse
import json
import random
from collections import Counter

from .alerts import Alerter
from . import evaluate
from .evaluate import Clock, make_guard, run_safe_hold
from .config import load_policy, Tags
from .forewarn import ForecastWatch
from .plant import Plant


def week(seed: int, days: int = 7, ack_min: int = 10, policy: dict | None = None) -> dict:
    rng = random.Random(seed)
    policy = policy or load_policy(Tags.load())
    plant = Plant(noise=True, seed=seed)
    clock = Clock()
    evaluate.SAFE_HOLD = True                         # the deployed configuration
    g = make_guard(plant, True, clock, policy)
    al = Alerter(None, throttle_s=600, clock=clock, escalate_s=600)
    al.contacts = lambda: ["operator", "supervisor"]
    g.alerter = al
    watch = ForecastWatch(al)
    plan = []                                         # (start_min, end_min, scenario) per day
    for d in range(days):
        kind = rng.choice(["normal", "normal", "normal", "normal", "storm", "bloom"])
        if kind != "normal":
            start = d * 1440 + rng.randint(0, 1200)
            plan.append((start, start + rng.randint(240, 720), kind))
    day_kind = {d: "calm" for d in range(days)}
    for s, e, k in plan:
        for d in range(s // 1440, min(days, e // 1440 + 1)):
            day_kind[d] = "weather"
    seen_alarms: set = set()
    next_trim = rng.randint(30, 120)
    acked: set = set()
    writes = Counter()
    for minute in range(days * 1440):
        clock.t = minute * 60.0
        for s, e, k in plan:
            if minute == s:
                plant.set_scenario(k)
            if minute == e:
                plant.set_scenario("normal")
        snap = plant.snapshot()
        g.twin.observe(snap, clock.t)
        now_alarms = set(plant.alarms())
        for a in now_alarms - seen_alarms:
            al.raise_alert(f"alarm:{a}", "critical" if a.startswith("pH") or "CHLORINE" in a else "warning",
                           f"Process alarm {a}")
        seen_alarms = now_alarms
        if minute % 5 == 0:
            watch.update(g.twin.forecast(snap, None, 180, every_min=5), snap)
            run_safe_hold(g, plant, minute)
        if minute % 1 == 0:
            al.tick()
        # the operator: acknowledges texts after ack_min, then acts on what they say
        respond = False
        for inc in al.incidents:
            if inc["acked_by"] is None and minute * 60 - inc["opened"] >= ack_min * 60 and inc["id"] not in acked:
                al.ack(inc["id"], "operator")
                acked.add(inc["id"])
                respond = True
        if respond or minute >= next_trim:
            s = plant.snapshot()
            fc = {w["var"] + ":" + w["direction"] for w in watch.active.values()}
            if (s["chlorine_residual"] < 0.6 or "chlorine_residual:below" in fc) and plant.setpoint("chlorine_dose") < 3.5:
                reg, new = "chlorine_dose", round(plant.setpoint("chlorine_dose") + 0.3, 2)
            elif (s["ph"] > 7.9 or "ph:above" in fc) and plant.setpoint("naoh_dose") > 0:
                reg, new = "naoh_dose", max(0, plant.setpoint("naoh_dose") - 20)
            elif s["ph"] < 7.1 or "ph:below" in fc:
                reg, new = "naoh_dose", plant.setpoint("naoh_dose") + 10
            elif (s["tank_level"] < 40 or "tank_level:below" in fc) and plant.setpoint("distribution_rate") > 300:
                reg, new = "distribution_rate", plant.setpoint("distribution_rate") - 100
            elif s["tank_level"] > 85 or "tank_level:above" in fc:
                reg, new = "distribution_rate", min(900, plant.setpoint("distribution_rate") + 100)
            elif plant.scenario == "normal" and plant.setpoint("chlorine_dose") > 1.6 and s["chlorine_residual"] > 1.0:
                reg, new = "chlorine_dose", round(plant.setpoint("chlorine_dose") - 0.2, 2)      # back to normal
            elif plant.scenario == "normal" and plant.setpoint("naoh_dose") < 90 and s["ph"] < 7.6:
                reg, new = "naoh_dose", plant.setpoint("naoh_dose") + 10
            else:
                reg, new = None, None
            if reg:
                d = g.check(reg, new, plant.snapshot(), "Operator HMI", "10.0.0.5:5000")
                writes["allowed" if d.allowed else f"blocked:{d.check}"] += 1
                if d.allowed:
                    g._commit(d)
                    plant.set(reg, new)
            next_trim = minute + rng.randint(30, 120)
        plant.step(1.0)
    texts = []
    for n in al.notifications:
        inc = next((i for i in al.incidents if i["id"] == n["incident"]), None)
        texts.append({"day": int(n["t"] // 86400), "day_kind": day_kind[int(n["t"] // 86400)],
                      "severity": n["severity"], "escalation": n["text"].startswith("ESCALATION"),
                      "cause": (inc or {}).get("title", n["text"])[:90]})
    return {"seed": seed, "days": days, "weather_days": sum(v == "weather" for v in day_kind.values()),
            "texts": texts, "operator_writes": dict(writes), "safe_hold_actions": len(g.safehold.actions)}


def summarize(weeks: list[dict]) -> dict:
    t = [x for w in weeks for x in w["texts"]]
    days = sum(w["days"] for w in weeks)
    wd = sum(w["weather_days"] for w in weeks)
    calm = [x for x in t if x["day_kind"] == "calm"]
    cause = Counter(("forecast" if x["cause"].startswith("Twin forecast") else
                     "process alarm" if x["cause"].startswith("Process alarm") else
                     "safe-hold" if "SAFE-HOLD" in x["cause"] else "other") for x in t)
    w = Counter()
    for wk in weeks:
        w.update(wk["operator_writes"])
    return {"weeks": len(weeks), "days": days, "weather_days": wd, "calm_days": days - wd,
            "texts_total": len(t), "texts_per_week": round(len(t) / len(weeks), 1),
            "texts_on_calm_days": len(calm), "texts_per_calm_day": round(len(calm) / max(1, days - wd), 2),
            "texts_per_weather_day": round((len(t) - len(calm)) / max(1, wd), 2),
            "escalations": sum(x["escalation"] for x in t), "by_cause": dict(cause),
            "calm_day_causes": [x["cause"] for x in calm][:20], "operator_writes": dict(w),
            "safe_hold_actions": sum(wk["safe_hold_actions"] for wk in weeks)}


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--weeks", type=int, default=4)
    ap.add_argument("--seed-offset", type=int, default=0)
    ap.add_argument("--ack-min", type=int, default=10, help="how long the operator takes to acknowledge a text")
    ap.add_argument("--json", default=None)
    a = ap.parse_args(argv)
    weeks = [week(a.seed_offset + i, ack_min=a.ack_min) for i in range(a.weeks)]
    s = summarize(weeks)
    print(f"{s['weeks']} simulated weeks ({s['calm_days']} calm days, {s['weather_days']} storm/bloom days), "
          f"operator acknowledges after {a.ack_min} min")
    print(f"  messages sent: {s['texts_total']} ({s['texts_per_week']} per week); escalations {s['escalations']}")
    print(f"  on calm days: {s['texts_on_calm_days']} ({s['texts_per_calm_day']} per calm day)  <- nuisance")
    print(f"  on storm/bloom days: {s['texts_per_weather_day']} per day")
    print(f"  by cause: {s['by_cause']}")
    print(f"  operator writes: {s['operator_writes']}; safe-hold actions: {s['safe_hold_actions']}")
    for c in s["calm_day_causes"]:
        print(f"    calm-day text: {c}")
    if a.json:
        with open(a.json, "w") as f:
            json.dump({"summary": s, "weeks": weeks}, f, indent=1)
    return s


if __name__ == "__main__":
    main()
