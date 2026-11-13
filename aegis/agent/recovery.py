"""Recovery planning (spec section 8): deterministic candidates, tested in the twin, filed as proposals.

Candidates
  1. revert: for every register a suspicious source changed and got through, the last value an operator
     approved before the incident;
  2. weather response: if the forecast crosses a band even with the incident's writes removed, the standard
     corrective move (cut lye in a bloom, raise chlorine in a storm, slow distribution if the clearwell is
     falling), in small steps within the policy's step limit;
  3. containment: text only, never actions.
Model-suggested steps are treated as more candidates and pass the same tests.

Each kept step must (a) not leave the 6 h twin forecast unsafe where doing nothing was safe, (b) not make
the forecast worse than doing nothing, and (c) pass the guard's own dry-run pre-check. Never: fight an active
safe-hold, or change setpoints while the integrity monitor says readings can't be trusted.
"""
from __future__ import annotations

from .tools import SETPOINTS, Evidence, _compare

SUSPICIOUS = ("external_attack", "compromised_trusted_source", "ai_manipulation")
FIX = {  # (variable, direction it is going wrong) -> (register, sign of the corrective move)
    ("ph", "above"): ("naoh_dose", -1), ("ph", "below"): ("naoh_dose", +1),
    ("chlorine_residual", "below"): ("chlorine_dose", +1), ("chlorine_residual", "above"): ("chlorine_dose", -1),
    ("tank_level", "below"): ("distribution_rate", -1), ("tank_level", "above"): ("distribution_rate", +1),
}
CONTAIN = {
    "external_attack": ["Keep the lockdown on the source's IPs; do not clear it until the device is identified.",
                        "Check the firewall: only the Aegis gateway should reach the PLC."],
    "compromised_trusted_source": ["Treat the HMI PC as compromised: disconnect it from the network and check it "
                                   "for remote-access tools before anyone uses it again.",
                                   "Keep the lockdown in place; operators can use the Aegis console meanwhile.",
                                   "Change the HMI and remote-access passwords."],
    "ai_manipulation": ["Keep the AI copilot in propose mode (it must not write directly).",
                        "Remove or correct the work order that contained instructions to the AI."],
    "plc_or_sensor_integrity": ["Take a lab grab sample for pH and chlorine now and compare with the PLC.",
                                "Check the PLC program and setpoints at the front panel; readings may not be "
                                "trustworthy until the lab confirms them."],
    "operator_error": ["Confirm the intended setpoint with the operator on shift."],
    "process_or_weather": ["Watch raw-water pH and turbidity; take a lab sample if the trend continues."],
    "benign_false_positive": ["If the block was wrong, an operator can use Allow once (hard limits still apply)."],
    "insufficient_evidence": ["Take a lab grab sample and review the timeline with the operator on shift."],
}


def _num(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def _last_good(ev: Evidence, register: str, before: float, bad_sources: set) -> float | None:
    """Last value an operator (not a suspicious source) set before the incident, from the audit log."""
    good = [e for e in ev.audit.between(ev.window[0] - 7 * 86400, before, kinds=("decision",))
            if e["id"] <= ev.head.get("id", 0) and e["data"].get("register") == register
            and e["data"].get("allowed") and not e["data"].get("would_block")
            and e["data"].get("source") not in bad_sources and _num(e["data"].get("new"))]
    return float(good[-1]["data"]["new"]) if good else None


def candidates(ev: Evidence, cls: str, F: dict, policy: dict, model_steps: list | None = None) -> list[dict]:
    out = []
    inc = ev.incident
    srcs = set(inc.sources)
    t_first = min((ev.by_id[i]["t"] for i in inc.trigger_ids if i in ev.by_id), default=inc.opened_t)
    if cls in SUSPICIOUS or cls == "operator_error":
        allowed = [e for e in ev.of("decision") if e["data"].get("source") in srcs and e["data"].get("allowed")
                   and not e["data"].get("would_block") and e["data"].get("register") in SETPOINTS
                   and _num(e["data"].get("old")) and _num(e["data"].get("new"))
                   and e["data"]["new"] != e["data"]["old"]]
        seen = set()
        for e in allowed:
            reg = e["data"]["register"]
            if reg in seen:
                continue
            seen.add(reg)
            first_t = min(x["t"] for x in allowed if x["data"]["register"] == reg)
            good = _last_good(ev, reg, first_t - 1, srcs if cls != "operator_error" else set())
            val = good if good is not None else float(next(x for x in allowed if x["data"]["register"] == reg)
                                                      ["data"]["old"])
            out.append({"register": reg, "value": val, "kind": "revert",
                        "why": f"revert {reg} to the last value approved before the incident",
                        "cite": [x["id"] for x in allowed if x["data"]["register"] == reg][:5]})
    tw = ev.twin(ev.window[1])
    if tw:
        twin, state = tw
        traj = twin.forecast(state, {c["register"]: c["value"] for c in out} or None, 360, every_min=10)
        from ..forewarn import first_crossings
        from .tools import _bands
        cross = first_crossings(traj, _bands(traj))
        for var, (mins, direction, _v) in sorted(cross.items(), key=lambda kv: kv[1][0]):
            fx = FIX.get((var, direction))
            if not fx:
                continue
            reg, sign = fx
            if any(c["register"] == reg for c in out) or state.get(reg) is None:
                continue
            lim = (policy.get("limits") or {}).get(reg) or {}
            step = lim.get("max_step") or ((lim.get("max", 1) - lim.get("min", 0)) / 10)
            for frac in (0.5, 1.0):
                v = float(state[reg]) + sign * step * frac
                if "min" in lim:
                    v = max(lim["min"], v)
                if "max" in lim:
                    v = min(lim["max"], v)
                out.append({"register": reg, "value": round(v, 3), "kind": "weather",
                            "why": f"forecast: {var} goes {direction} its band in ~{mins:g} min; small corrective step",
                            "cite": (F.get("forecast_warnings") or {}).get("ids", [])[:3]})
    for s in model_steps or []:
        if s.get("register") in SETPOINTS and _num(s.get("value")):
            out.append({"register": s["register"], "value": float(s["value"]), "kind": "model",
                        "why": str(s.get("why", ""))[:300], "cite": list(s.get("cite") or [])[:10]})
    return out


def fit_to_policy(c: dict, state: dict, policy: dict) -> dict:
    """Clamp a step to the policy: inside [min, max] and at most max_step away from the current value. A larger
    move becomes the first step toward the target (the guard allows at most max_step per command)."""
    lim = (policy.get("limits") or {}).get(c["register"]) or {}
    v = float(c["value"])
    if "min" in lim:
        v = max(float(lim["min"]), v)
    if "max" in lim:
        v = min(float(lim["max"]), v)
    cur = state.get(c["register"])
    ms = lim.get("max_step")
    if ms and isinstance(cur, (int, float)) and abs(v - cur) > ms:
        import math
        n = math.ceil(abs(v - cur) / ms - 1e-9)
        target = v
        v = round(cur + math.copysign(ms * 0.999, v - cur), 4)
        c = {**c, "target": target, "why": c["why"] + f" (first of {n} steps toward {target:g}; the guard allows "
                                                       f"at most {ms:g} per command)"}
    return {**c, "value": v}


def _active_holds(ev: Evidence) -> set:
    held = set()
    for e in ev.of("safe_hold", "hold_released"):
        reg = e["data"].get("register")
        if e["kind"] == "safe_hold":
            held.add(reg)
        else:
            held.discard(reg)
    return held


async def plan(ev: Evidence, cls: str, F: dict, policy: dict, guard_check=None,
               model_steps: list | None = None) -> dict:
    """-> {"steps": kept, "rejected": [...], "containment": [...], "plan_forecast": ...}.
    guard_check: optional async (register, value) -> (allowed, reason): the guard's dry-run pre-check."""
    contain = list(CONTAIN.get(cls, []))
    untrusted = any((F.get(k) or {}).get("value") for k in ("physics_mismatch", "stuck_sensor", "lab_disagrees",
                                                            "drift_without_decision"))
    if untrusted or cls == "plc_or_sensor_integrity":
        return {"steps": [], "rejected": [], "containment": contain,
                "note": "readings may not be trustworthy: no setpoint changes proposed; take a grab sample first"}
    if cls == "benign_false_positive":
        return {"steps": [], "rejected": [], "containment": contain, "note": "nothing to recover"}
    tw = ev.twin(ev.window[1])
    if not tw:
        return {"steps": [], "rejected": [], "containment": contain, "note": "no plant readings: cannot test steps"}
    twin, state = tw
    held = _active_holds(ev)
    kept, rejected = [], []
    for c in candidates(ev, cls, F, policy, model_steps):
        why_not = None
        if c["kind"] == "model":
            # never "fix up" a model-suggested step into something acceptable: out of policy means rejected
            f = fit_to_policy(c, state, policy)
            if abs(f["value"] - float(c["value"])) > 1e-9:
                why_not = "outside the policy's range or step limit"
        else:
            c = fit_to_policy(c, state, policy)
        if c["register"] in held:
            why_not = "safe-hold is holding this register"
        elif any(k["register"] == c["register"] for k in kept):
            why_not = "already have a step for this register"
        elif state.get(c["register"]) is not None and abs(float(state[c["register"]]) - c["value"]) < 1e-9:
            why_not = "already at that value"
        if why_not is None:
            base = {k["register"]: k["value"] for k in kept}
            r_alone = _compare(twin, state, {**base, c["register"]: c["value"]}, 6)
            # reference: the plan so far (or doing nothing if the plan is empty)
            ref = _compare(twin, state, base, 6)["with"] if base else r_alone["without"]
            w, wo = r_alone["with"]["excursion"], ref["excursion"]
            new_cross = set(r_alone["with"]["crossings"]) - set(ref["crossings"])
            if w > wo + 1e-6:
                why_not = f"twin: makes the forecast worse ({w:g} vs {wo:g})"
            elif new_cross:
                why_not = f"twin: creates a new band crossing ({', '.join(sorted(new_cross))})"
            elif w > 0 and c["kind"] == "weather" and w >= wo - 1e-6:
                why_not = "twin: does not improve an unsafe forecast"
            c["twin"] = {"with": w, "without": wo, "verdict": r_alone["verdict"]}
        if why_not is None and guard_check is not None:
            ok, reason = await guard_check(c["register"], c["value"])
            if not ok:
                why_not = f"guard pre-check would block it: {reason}"
            c["guard"] = reason
        (rejected if why_not else kept).append({**c, **({"rejected_because": why_not} if why_not else {})})
    plan_fc = _compare(twin, state, {k["register"]: k["value"] for k in kept}, 6) if kept else None
    return {"steps": kept, "rejected": rejected, "containment": contain, "plan_forecast": plan_fc}
