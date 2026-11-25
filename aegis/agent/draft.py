"""Deterministic draft verdict (no model).

Used as the fallback when no model is available, and shown to the model as a starting point. Each claim
names one signal from features.py and cites the audit entries behind it; it states nothing else, so it
always passes the citation validator.
"""
from __future__ import annotations

from .schema import Verdict

SIGNALS = {
    # "!name" = the signal is absent (value False), e.g. the source was never seen before
    "external_attack": ["!registered_source", "!source_known", "unknown_write_through", "recon_fc", "lockdown", "writes_after_block",
                        "monotone_push", "probing"],
    "compromised_trusted_source": ["ip_matches_label", "!human_present", "monotone_push", "regular_interval",
                                   "probing", "writes_after_block", "lockdown"],
    "operator_error": ["human_present", "retry_after_block", "typo_like", "correction_follows", "weather_aligned"],
    "process_or_weather": ["harm_forecast_without_writes", "forecast_warnings", "raw_water_changed_recently",
                           "mismatch_on_steep_curve"],
    "plc_or_sensor_integrity": ["drift_without_decision", "physics_mismatch", "stuck_sensor", "lab_disagrees"],
    "ai_manipulation": ["ai_proposal_blocked", "ai_reply_flagged", "untrusted_instructions"],
    "benign_false_positive": ["n_blocked"],
    "insufficient_evidence": [],
}
QUESTION = {
    "external_attack": "Which device uses this IP address?",
    "compromised_trusted_source": "Was an operator at the HMI PC at that time?",
    "operator_error": "What value did the operator intend?",
    "process_or_weather": "Has a lab sample confirmed the raw-water change?",
    "plc_or_sensor_integrity": "Does a lab grab sample agree with the PLC readings?",
    "ai_manipulation": "Who wrote the work order the copilot read?",
    "benign_false_positive": "Was the blocked change actually needed?",
    "insufficient_evidence": "What does the operator on shift remember?",
}
LABEL = {"external_attack": "Likely an outside device writing to the plant.",
         "compromised_trusted_source": "Likely the HMI PC itself is compromised.",
         "operator_error": "Likely an operator mistake.",
         "process_or_weather": "Likely a raw-water / weather change, not a person.",
         "plc_or_sensor_integrity": "PLC or sensor readings may not be trustworthy.",
         "ai_manipulation": "The AI copilot was given planted instructions.",
         "benign_false_positive": "The block was probably not needed.",
         "insufficient_evidence": "Not enough evidence to decide."}


def _who(ev, ids):
    """'Unknown device (unit 77) at 127.0.0.66': source and IP exactly as the cited entries carry them."""
    for i in ids:
        d = (ev.by_id.get(i) or {}).get("data") or {}
        if d.get("source"):
            ip = str(d.get("peer") or "").rsplit(":", 1)[0]
            return f"{d['source']} at {ip}" if ip and ip[0].isdigit() else str(d["source"])
    return "The writer"


def _values(ev, ids):
    """'chlorine_dose 1.9, 2.3, 2.7': the values the cited writes asked for, in order."""
    reg, vals = None, []
    for i in sorted(ids):
        d = (ev.by_id.get(i) or {}).get("data") or {}
        if d.get("register") and d.get("new") is not None and (reg is None or d["register"] == reg):
            reg = d["register"]
            if d["new"] not in vals:
                vals.append(d["new"])
    return f"{reg} {', '.join(str(v) for v in vals[:6])}" if reg and vals else ""


# Plain-language reason per signal. Concrete details (device, IP, values) come only from the cited entries,
# so every sentence still passes the citation validator; general sentences carry no numbers.
PLAIN = {
    "!registered_source": lambda ev, ids: f"{_who(ev, ids)} is not registered with the guard as one of the "
                                          "plant's own computers, so nobody vouches for it.",
    "!source_known": lambda ev, ids: "Its network address never appeared in the plant's normal traffic before.",
    "recon_fc": lambda ev, ids: "Before writing, it sent diagnostic or scanning requests, like someone mapping the PLC.",
    "lockdown": lambda ev, ids: "The guard locked this source out after repeated blocked writes.",
    "writes_after_block": lambda ev, ids: "It kept writing after the guard had already blocked it.",
    "monotone_push": lambda ev, ids: (f"Each write pushed the same setting further in one direction "
                                      f"({_values(ev, ids)}): a deliberate ramp, not a correction."
                                      if _values(ev, ids) else "Each write pushed the same setting further in one direction."),
    "probing": lambda ev, ids: "It tried values just past the safety limits, as if testing where they are.",
    "ip_matches_label": lambda ev, ids: f"The writes come from a trusted computer's own address ({_who(ev, ids)}), "
                                        "so they look legitimate on the network.",
    "!human_present": lambda ev, ids: "No operator was signed in or active on the dashboard when the writes came in.",
    "regular_interval": lambda ev, ids: "The writes came at machine-regular intervals, not at a person's pace.",
    "human_present": lambda ev, ids: "An operator was signed in and active at the time.",
    "retry_after_block": lambda ev, ids: "After the block, the same operator retried with a corrected value.",
    "typo_like": lambda ev, ids: "The blocked value looks like a typo of a normal value (for example an extra zero).",
    "correction_follows": lambda ev, ids: "A normal value followed shortly after, as a correction.",
    "weather_aligned": lambda ev, ids: "The change makes sense for the raw-water conditions at the time.",
    "harm_forecast_without_writes": lambda ev, ids: "The digital twin forecasts trouble even without any of these writes, "
                                                    "so the water itself is changing.",
    "forecast_warnings": lambda ev, ids: "The digital twin's forecast warned that the water would leave the safe range.",
    "raw_water_changed_recently": lambda ev, ids: "Raw-water readings (pH, alkalinity, turbidity) changed shortly before.",
    "mismatch_on_steep_curve": lambda ev, ids: "The mismatch is on a steep part of the chemistry curve, where small "
                                               "changes swing pH a lot.",
    "drift_without_decision": lambda ev, ids: "Process values drifted with no approved write to explain it.",
    "physics_mismatch": lambda ev, ids: "The measured chemistry doesn't match what the approved setpoints should produce.",
    "stuck_sensor": lambda ev, ids: "A sensor reading stopped changing.",
    "lab_disagrees": lambda ev, ids: "A lab grab sample disagrees with the PLC's readings.",
    "ai_proposal_blocked": lambda ev, ids: "The AI copilot proposed a change that the guard blocked.",
    "ai_reply_flagged": lambda ev, ids: "The copilot's reply was flagged for following instructions it had read.",
    "untrusted_instructions": lambda ev, ids: "Text the copilot read (a work order) contained instructions telling it "
                                              "what to do.",
    "unknown_write_through": lambda ev, ids: f"{_who(ev, ids)} changed {_values(ev, ids) or 'a setpoint'} with the "
                                             "guard off, and nothing stopped it.",
    "n_blocked": lambda ev, ids: "Aegis blocked these writes.",
}


def _signal(ev, F, key):
    neg = key.startswith("!")
    name = key.lstrip("!")
    f = F.get(name) or {}
    if neg:
        if f.get("value") is not False:
            return None
        # an absence is shown by the entries it is about: the incident's own triggering writes (for
        # "not registered", the writer's own writes, which name it even when a forecast warning triggered)
        own = [i for i in f.get("ids") or [] if i in ev.by_id] if name == "registered_source" else []
        ids = (own or [i for i in ev.incident.trigger_ids if i in ev.by_id])[:5]
    else:
        ids = [i for i in f.get("ids") or [] if i in ev.by_id][:8]
        if not f.get("value"):
            return None
    if not ids:
        return None
    say = PLAIN.get(key)
    return {"text": say(ev, ids) if say else f"Signal {name} is {'absent' if neg else 'present'}.", "cite": ids}


def techniques(ev) -> list[dict]:
    seen: dict = {}
    for e in ev.of("decision"):
        if e["id"] not in set(ev.incident.entry_ids):
            continue
        for t in e["data"].get("techniques") or []:
            tid, name = (t[0], t[1]) if isinstance(t, (list, tuple)) and len(t) > 1 else (t, t)
            seen.setdefault(tid, {"id": tid, "name": str(name)[:60], "cite": []})
            if len(seen[tid]["cite"]) < 5:
                seen[tid]["cite"].append(e["id"])
    return list(seen.values())[:10]


def build(ev, F: dict, cls: str, confidence: str, alternatives: list[str] = ()) -> Verdict:
    claims = [c for c in (_signal(ev, F, k) for k in SIGNALS.get(cls, [])) if c]
    if confidence == "high" and len(claims) < 2:
        confidence = "medium"
    hyps = [{"name": cls, "status": "supported", "for": claims[:4], "against": []}]
    for alt in alternatives:
        if alt != cls:
            hyps.append({"name": alt, "status": "rejected" if confidence != "low" else "open",
                         "for": [c for c in (_signal(ev, F, k) for k in SIGNALS.get(alt, [])) if c][:2],
                         "against": []})
    inc = ev.incident
    allowed = [e for e in ev.of("decision") if e["id"] in set(inc.entry_ids) and e["data"].get("allowed")
               and e["data"].get("source") in inc.sources and e["data"].get("new") != e["data"].get("old")]
    got = [{"text": f"{e['data'].get('register')} changed from {e['data'].get('old')} to {e['data'].get('new')}.",
            "cite": [e["id"]]} for e in allowed[:5]]
    techs = techniques(ev)
    if cls == "ai_manipulation":
        ids = [i for i in (F.get("ai_origin") or {}).get("ids") or [] if i in ev.by_id][:5]
        if ids:
            techs.append({"id": "LLM01", "name": "Prompt injection", "cite": ids})
    blocked = (F.get("n_blocked") or {}).get("value") or 0
    summary = LABEL[cls] + " " + (f"Aegis blocked {blocked} write(s)." if blocked else "No write was blocked.")
    return Verdict.model_validate({
        "classification": {"primary": cls, "secondary": None, "confidence": confidence, "rationale": claims[:6]},
        "hypotheses": hyps[:6],
        "scope": {"sources": sorted(inc.sources)[:10], "ips": sorted(inc.ips)[:16],
                  "registers": sorted(inc.registers)[:10], "writes_allowed_from_source": got,
                  "still_active": False},
        "attack_techniques": techs,
        "recovery": [],
        "open_questions": [QUESTION[cls]],
        "summary_for_operator": summary,
    })
