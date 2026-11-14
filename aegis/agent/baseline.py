"""Rule baseline (spec section 13.3): the classifier Sentinel has to beat, on the same features.

Ordered rules, first match wins. Written to be a fair, sensible baseline, not a straw man: it uses
every feature the agent gets. If the agent cannot beat it, the README says so.
"""
from __future__ import annotations

HMI_LIKE = ("Operator HMI",)


def v(F: dict, k: str):
    return (F.get(k) or {}).get("value")


def ids(F: dict, *ks) -> list[int]:
    out = []
    for k in ks:
        out += (F.get(k) or {}).get("ids") or []
    return sorted(set(out))


def classify(F: dict) -> dict:
    blocked = v(F, "n_blocked") or 0
    persistent = (v(F, "writes_after_block") or 0) > 3
    pushy = bool(v(F, "monotone_push") or v(F, "regular_interval") or v(F, "probing") or persistent)

    def out(cls, conf, rule, *keys):
        return {"primary": cls, "confidence": conf, "rule": rule, "evidence_ids": ids(F, *keys),
                "remaining_risk": "process_or_weather" if v(F, "harm_forecast_without_writes") else None}

    integ = v(F, "drift_without_decision") or v(F, "physics_mismatch") or v(F, "stuck_sensor") or v(F, "lab_disagrees")
    hard_integ = v(F, "drift_without_decision") or v(F, "stuck_sensor") or v(F, "lab_disagrees")
    if integ and not hard_integ and blocked == 0 and v(F, "mismatch_on_steep_curve"):
        return out("process_or_weather", "low", "physics-only mismatch where the model already predicts a high pH "
                   "(steep titration curve: model error, not dosing)", "mismatch_on_steep_curve", "physics_mismatch")
    if integ and blocked == 0:
        return out("plc_or_sensor_integrity", "high" if (v(F, "lab_disagrees") or v(F, "drift_without_decision"))
                   else "medium", "integrity signal with no blocked writes",
                   "drift_without_decision", "physics_mismatch", "stuck_sensor", "lab_disagrees")
    if v(F, "ai_origin"):
        return out("ai_manipulation", "high" if v(F, "untrusted_instructions") else "medium",
                   "copilot proposal or reply in the incident", "ai_proposal_blocked", "ai_reply_flagged",
                   "untrusted_instructions")
    if v(F, "recon_fc") or (v(F, "flood_rate") or 0) >= 1 or (blocked and not v(F, "source_known")):
        return out("external_attack", "high" if (v(F, "recon_fc") or not v(F, "ip_matches_label")) else "medium",
                   "recon function codes, flood, or unknown source/IP", "recon_fc", "flood_rate", "primary_source",
                   "source_known")
    if blocked and not v(F, "human_present") and pushy:
        return out("compromised_trusted_source", "medium",
                   "trusted label, no human present, and a push/probe/persistence pattern", "human_present",
                   "monotone_push", "regular_interval", "probing", "writes_after_block")
    if blocked and v(F, "correction_follows") and v(F, "human_present"):
        return out("operator_error", "medium", "known operator, present, corrected the write", "correction_follows",
                   "human_present")
    if blocked == 0 and v(F, "harm_forecast_without_writes"):
        return out("process_or_weather", "medium", "forecast unsafe even without the incident's writes",
                   "harm_forecast_without_writes", "forecast_warnings")
    if blocked and pushy:
        return out("compromised_trusted_source", "low", "push/probe/persistence pattern from a trusted label",
                   "monotone_push", "regular_interval", "probing", "writes_after_block")
    if blocked:
        block_checks = v(F, "block_checks") or {}
        if set(block_checks) == {"predict"} and not v(F, "writes_make_forecast_worse"):
            return out("benign_false_positive", "low", "only twin blocks, and the counterfactual is not worse",
                       "block_checks", "writes_make_forecast_worse")
        return out("operator_error", "low", "blocked write from a known source", "primary_source", "n_blocked")
    if v(F, "forecast_warnings"):
        return out("process_or_weather", "low", "forecast warning without blocked writes", "forecast_warnings")
    return out("insufficient_evidence", "low", "no rule matched")


def severity(cls: str) -> str:
    return {"external_attack": "HIGH", "compromised_trusted_source": "HIGH", "ai_manipulation": "HIGH",
            "plc_or_sensor_integrity": "HIGH", "operator_error": "MEDIUM", "process_or_weather": "MEDIUM",
            "benign_false_positive": "LOW", "insufficient_evidence": "MEDIUM"}.get(cls, "MEDIUM")
