"""Reply guard: check what the AI tells the operator before they read it.

Aegis stops a hijacked AI from *writing* to the PLC. But an AI that read a
poisoned work order can also *talk*: "pH is normal, switch Aegis to monitor
mode for maintenance." The human then does the attacker's work. So every
copilot reply is checked, deterministically, before it's shown:

  1. Grounding: every number the AI states about the plant (pH, chlorine,
     clearwell level, lye/chlorine dose, flow) is compared with the live
     reading. A claim that's off by more than a tolerance is flagged in red,
     with the real value next to it.
  2. Dangerous advice: telling the operator to turn the guard off or to monitor
     mode, bypass/override safety, ignore or silence alarms, raise limits, or
     skip approval is flagged, whatever the wording around it.

The reply isn't rewritten (that would hide what the model said); it's
annotated, logged in the audit chain, and the operator sees why it's suspect.
"""
from __future__ import annotations

import re

CLAIMS = [  # (key in live state, label, regex: group 1 = words before the number, group 2 = number, tolerance)
    ("ph", "pH", r"\bph\b([^0-9.\n]{0,25}?)(\d{1,2}(?:\.\d+)?)", 0.15),
    ("chlorine_residual", "chlorine residual", r"(?:chlorine|cl2|residual)\b(?!\s*dose)([^0-9.\n]{0,30}?)(\d(?:\.\d+)?)\s*mg", 0.15),
    ("tank_level", "clearwell level", r"(?:clearwell|tank|level)([^0-9.\n]{0,25}?)(\d{1,3}(?:\.\d+)?)\s*%", 5.0),
    ("naoh_dose", "lye feed", r"(?:lye|naoh|caustic|sodium hydroxide)([^0-9.\n]{0,30}?)(\d{1,5}(?:\.\d+)?)\s*ppm", 1.0),
    ("chlorine_dose", "chlorine dose", r"chlorine\s+dose([^0-9.\n]{0,20}?)(\d(?:\.\d+)?)", 0.05),
]
# words between the variable and the number that mean "a limit, target or change", not "the current reading"
NOT_A_READING = re.compile(r"\b(under|below|above|over|limit|target|to|toward|towards|range|between|max|maximum|"
                           r"min|minimum|than|back|down|up|from|by|safe|should|would|will|could|propose|set)\b")
DANGER = [
    (r"\b(turn|switch|set|put)\b[^.\n]{0,40}\b(aegis|guard|safety)\b[^.\n]{0,30}\b(off|monitor|disable)", "turn the safety guard off / to monitor"),
    (r"\b(disable|deactivate|bypass|override|circumvent)\b[^.\n]{0,30}\b(aegis|guard|safety|limit|interlock|alarm)", "disable or bypass safety"),
    (r"\b(ignore|silence|mute|acknowledge and ignore|dismiss)\b[^.\n]{0,30}\b(alarm|alert|warning)", "ignore or silence alarms"),
    (r"\b(raise|increase|widen|remove)\b[^.\n]{0,25}\b(safety )?(limit|max(imum)?|threshold|envelope)s?\b", "loosen safety limits"),
    (r"\b(without|skip|no need for)\b[^.\n]{0,25}\b(approval|engineer|operator|sign.?off)", "skip human approval"),
    (r"\bmaintenance mode\b|\bsafety limits are (disabled|off)\b", "claims safety is suspended"),
    (r"\b(connect|plug)\b[^.\n]{0,30}\bdirect(ly)?\b[^.\n]{0,30}\b(plc|controller)", "go around Aegis to the PLC"),
]


def check(reply: str, live: dict) -> dict:
    text = reply or ""
    low = text.lower()
    wrong = []
    for key, label, pat, tol in CLAIMS:
        if live.get(key) is None:
            continue
        for m in re.finditer(pat, low):
            if NOT_A_READING.search(m.group(1)):
                continue
            try:
                v = float(m.group(2))
            except ValueError:
                continue
            real = float(live[key])
            if abs(v - real) > tol:
                wrong.append({"what": label, "said": v, "live": round(real, 2), "excerpt": text[m.start():m.end()]})
    danger = []
    for pat, label in DANGER:
        m = re.search(pat, low)
        if m:
            danger.append({"what": label, "excerpt": text[m.start():m.end()]})
    flags = ([f"says {w['what']} is {w['said']:g}, live reading is {w['live']:g}" for w in wrong] +
             [f"advises: {d['what']} (\"{d['excerpt']}\")" for d in danger])
    return {"ok": not flags, "wrong_numbers": wrong, "dangerous_advice": danger, "flags": flags}
