"""Deterministic draft verdict (no model).

Used as the fallback when no model is available, and shown to the model as a starting point. Each claim
names one signal from features.py and cites the audit entries behind it; it states nothing else, so it
always passes the citation validator.
"""
from __future__ import annotations

from .schema import Verdict

SIGNALS = {
    # "!name" = the signal is absent (value False), e.g. the source was never seen before
    "external_attack": ["!source_known", "recon_fc", "lockdown", "writes_after_block", "monotone_push", "probing"],
    "compromised_trusted_source": ["ip_matches_label", "!human_present", "monotone_push", "regular_interval",
                                   "probing", "writes_after_block", "lockdown"],
    "operator_error": ["human_present", "correction_follows", "weather_aligned"],
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


def _signal(ev, F, key):
    neg = key.startswith("!")
    key = key.lstrip("!")
    f = F.get(key) or {}
    if neg:
        if f.get("value") is not False:
            return None
        # an absence is shown by the entries it is about: the incident's own triggering writes
        ids = [i for i in ev.incident.trigger_ids if i in ev.by_id][:5]
        return {"text": f"Signal {key} is absent for these writes.", "cite": ids} if ids else None
    ids = [i for i in f.get("ids") or [] if i in ev.by_id][:8]
    if not f.get("value") or not ids:
        return None
    return {"text": f"Signal {key} is present.", "cite": ids}


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
