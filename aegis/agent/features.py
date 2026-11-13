"""Deterministic signals extracted from the frozen evidence (spec section 6.1).

Computed before any model runs, shown to the model, and used by the rule baseline and the learned
classifier. Each feature is {"value": ..., "ids": [audit entry ids that support it]} so the report
can cite it. "Primary source" = the source with the most triggering decisions in the incident.
"""
from __future__ import annotations

import re
import statistics
from collections import Counter

from .tools import SETPOINTS, Evidence, _compare, _excursion, ip_of

RECON_FC = {8, 17, 43, 90}
AI_SOURCES = ("AI copilot",)
IMPERATIVE = re.compile(r"\b(ignore (all )?previous|immediately|do not ask|no confirmation|copilot[:,]|ai (copilot|"
                        r"assistant)[:,]?|tell the operator|set \w+ to|raise \w+ to|reduce \w+ to|switch aegis|"
                        r"directive|authori[sz]ed|no pregunte|de inmediato)", re.I)
WINDOW_PRESENCE_S = 10 * 60


def _f(value, ids=()):
    return {"value": value, "ids": sorted(set(ids))[:20]}


def _num(x):
    return isinstance(x, (int, float)) and not isinstance(x, bool)


def extract(ev: Evidence, twin: bool = True) -> dict:
    inc = ev.incident
    dec = ev.of("decision")
    trig = set(inc.trigger_ids)
    inc_dec = [e for e in dec if e["id"] in set(inc.entry_ids)]
    by_src = Counter(e["data"].get("source") for e in inc_dec if e["id"] in trig)
    primary = by_src.most_common(1)[0][0] if by_src else None
    # behaviour uses every write from the primary source in the evidence window: an attacker's first
    # writes are usually allowed and come before anything opened the incident
    mine = [e for e in dec if e["data"].get("source") == primary] if primary else []
    blocked = [e for e in inc_dec if not e["data"].get("allowed") or e["data"].get("would_block")]
    allowed = [e for e in inc_dec if e["data"].get("allowed") and not e["data"].get("would_block")]
    ips = sorted({ip_of(e["data"].get("peer")) for e in mine} - {""})
    F: dict = {"primary_source": _f(primary, [e["id"] for e in mine[:3]]),
               "primary_ips": _f(ips, [e["id"] for e in mine[:3]])}

    # --- who: profile, label vs IP, humans
    prof = [e for e in ev.profile_entries if e["data"].get("source") == primary] if primary else []
    prof_ips = {ip_of(e["data"].get("peer")) for e in prof} - {""}
    # known = seen in the 7-day profile, or registered in the guard's configuration (a fresh install has no
    # history yet but does know which IPs its HMI and AI use)
    reg_ips = set((ev.registry or {}).get(primary) or ())
    known_ips = prof_ips | reg_ips
    F["source_known"] = _f(bool(known_ips) and bool(ips) and set(ips) <= known_ips,
                           [e["id"] for e in prof[-3:]] + [e["id"] for e in mine[:1]])
    F["ip_matches_label"] = _f(bool(known_ips) and bool(ips) and set(ips) <= known_ips,
                               [e["id"] for e in mine[:2]] + [e["id"] for e in prof[-2:]])
    F["registered_source"] = _f(bool(reg_ips) and bool(ips) and set(ips) <= reg_ips, [e["id"] for e in mine[:1]])
    t0 = min((ev.by_id[i]["t"] for i in inc.trigger_ids if i in ev.by_id), default=inc.opened_t)
    t1 = max((ev.by_id[i]["t"] for i in inc.trigger_ids if i in ev.by_id), default=inc.last_t)
    sess, last_login = [], None
    for e in ev.of("login", "logout"):
        if e["kind"] == "login":
            last_login = e
        elif last_login is not None:
            sess.append((last_login, e))
            last_login = None
    in_session = [lg for lg, lo in sess if lg["t"] <= t1 and lo["t"] >= t0]
    if last_login is not None and last_login["t"] <= t1:
        in_session.append(last_login)
    acts = [e for e in ev.of("alert_ack", "permit_issued", "allow_once", "dashboard_view", "proposal_decision",
                             "lab_input", "grab_sample") if t0 - WINDOW_PRESENCE_S <= e["t"] <= t1 + WINDOW_PRESENCE_S]
    F["human_present"] = _f(bool(in_session or acts), [e["id"] for e in in_session + acts])
    F["human_actions"] = _f(len(acts), [e["id"] for e in acts])
    hours = {int(e["t"] // 3600 % 24) for e in prof}
    off = [e for e in mine if hours and int(e["t"] // 3600 % 24) not in hours]
    F["off_hours"] = _f(bool(mine) and len(off) > len(mine) / 2, [e["id"] for e in off])

    # --- how: protocol and behaviour
    recon = [e for e in inc_dec if e["data"].get("fc") in RECON_FC or e["data"].get("check") == "function"]
    F["recon_fc"] = _f(bool(recon), [e["id"] for e in recon])
    ts = [e["t"] for e in mine]
    gaps = [b - a for a, b in zip(ts, ts[1:]) if b - a > 0.5]
    reg_int = len(gaps) >= 3 and statistics.mean(gaps) > 0 and statistics.pstdev(gaps) / statistics.mean(gaps) < 0.1
    F["regular_interval"] = _f(reg_int, [e["id"] for e in mine[:4]])
    F["median_gap_s"] = _f(round(statistics.median(gaps), 1) if gaps else None)
    probes = []
    for a, b in zip(mine, mine[1:]):
        da, db = a["data"], b["data"]
        if (not da.get("allowed") and da.get("register") == db.get("register") and b["t"] - a["t"] <= 60
                and _num(da.get("new")) and _num(db.get("new")) and _num(da.get("old"))
                and abs(db["new"] - da["old"]) < abs(da["new"] - da["old"]) and (db["new"] - da["old"]) * (da["new"] - da["old"]) > 0):
            probes += [a["id"], b["id"]]
    F["probing"] = _f(len(probes) >= 4, probes)
    best, run, prev = [], [], None
    for e in mine:
        d = e["data"]
        if not (_num(d.get("new")) and _num(d.get("old"))) or d["new"] == d["old"]:
            continue
        sgn = (d.get("register"), 1 if d["new"] > d["old"] else -1)
        run = run + [e] if sgn == prev else [e]
        prev = sgn
        best = run if len(run) > len(best) else best
    F["monotone_push"] = _f(len(best) >= 3, [e["id"] for e in best])
    F["push_length"] = _f(len(best), [e["id"] for e in best])
    first_block = next((e for e in mine if not e["data"].get("allowed")), None)
    after = [e for e in mine if first_block and e["t"] > first_block["t"]]
    F["writes_after_block"] = _f(len(after), [e["id"] for e in after[:5]])
    corr = []
    for i, a in enumerate(mine):
        da = a["data"]
        if not (_num(da.get("new")) and _num(da.get("old"))) or da["new"] == da["old"]:
            continue
        for b in mine[i + 1:]:
            if b["t"] - a["t"] > 15 * 60:
                break
            db = b["data"]
            if db.get("register") == da.get("register") and _num(db.get("new")) and _num(db.get("old")) \
                    and (db["new"] - db["old"]) * (da["new"] - da["old"]) < 0:
                corr += [a["id"], b["id"]]
                break
    F["correction_follows"] = _f(bool(corr), corr)
    win = Counter(int(e["t"] // 10) for e in mine)
    peak = max(win.values()) / 10 if win else 0.0
    units = {e["data"].get("source") for e in inc_dec if e["t"] - t0 <= 60}
    F["flood_rate"] = _f(round(peak, 2), [e["id"] for e in mine[:3]] if peak >= 1 else [])
    F["distinct_sources"] = _f(len(by_src) or len(units), [])
    F["n_writes"] = _f(len(inc_dec), [])
    F["n_blocked"] = _f(len(blocked), [e["id"] for e in blocked[:5]])
    F["n_allowed"] = _f(len(allowed), [e["id"] for e in allowed[:5]])
    F["block_checks"] = _f(dict(Counter(e["data"].get("check") for e in blocked)), [e["id"] for e in blocked[:5]])
    F["registers"] = _f(sorted({e["data"].get("register") for e in inc_dec} - {None}), [])
    lock = ev.of("lockdown")
    F["lockdown"] = _f(bool(lock), [e["id"] for e in lock])

    # --- weather and integrity
    raw_change = None
    if ev.history:
        rows = ev.history.between(t0 - 3 * 3600, t0)
        for (ta, ra), (tb, rb) in zip(rows, rows[30:]):
            if abs(rb.get("raw_ph", 0) - ra.get("raw_ph", 0)) > 0.15 or \
                    abs(rb.get("raw_turbidity", 0) - ra.get("raw_turbidity", 0)) > 3:
                raw_change = tb
                break
    F["weather_aligned"] = _f(raw_change is not None and 0 <= t0 - raw_change <= 3600 + 1800,
                              [e["id"] for e in mine[:1]])
    F["raw_water_changed_recently"] = _f(raw_change is not None, [])
    integ = ev.of("integrity")
    drift = [e for e in integ if str(e["data"].get("key", "")).startswith("setpoint:")]
    phys = [e for e in integ if str(e["data"].get("key", "")).startswith("physics:")]
    stuck = [e for e in integ if str(e["data"].get("key", "")).startswith("stuck:")]
    grab = [e for e in ev.of("grab_sample") if not e["data"].get("ok", True)]
    F["drift_without_decision"] = _f(bool(drift), [e["id"] for e in drift])
    F["physics_mismatch"] = _f(bool(phys), [e["id"] for e in phys])
    F["stuck_sensor"] = _f(bool(stuck), [e["id"] for e in stuck])
    F["lab_disagrees"] = _f(bool(grab), [e["id"] for e in grab])
    fw = ev.of("forecast_warning")
    F["forecast_warnings"] = _f(len(fw), [e["id"] for e in fw])

    # --- AI
    props = [e for e in ev.of("proposal") if e["data"].get("source") in AI_SOURCES]
    pblk = [e for e in props if e["data"].get("status") == "blocked"]
    flag = ev.of("ai_reply_flagged")
    ai_dec = [e for e in inc_dec if e["data"].get("source") in AI_SOURCES]
    texts = []
    if ev.work_orders_fn:
        try:
            texts = list(ev.work_orders_fn() or [])
        except Exception:
            texts = []
    injected = [e for e in props + flag if IMPERATIVE.search(" ".join(str(v) for v in e["data"].values()))]
    F["ai_origin"] = _f(bool(props or flag or ai_dec), [e["id"] for e in props + flag + ai_dec])
    F["ai_proposal_blocked"] = _f(bool(pblk), [e["id"] for e in pblk])
    F["ai_reply_flagged"] = _f(bool(flag), [e["id"] for e in flag])
    F["untrusted_instructions"] = _f(bool(injected) or any(IMPERATIVE.search(t) for t in texts),
                                     [e["id"] for e in injected])
    auth = ev.of("auth_failure")
    F["auth_failures"] = _f(len(auth), [e["id"] for e in auth])

    # --- twin: is the risk the writes or the weather?
    F["harm_forecast_without_writes"] = _f(None)
    F["writes_make_forecast_worse"] = _f(None)
    F["reverses_trend"] = _f(None)
    if twin and ev.history:
        regs_first = {}
        for e in mine:
            d = e["data"]
            if d.get("register") in SETPOINTS and _num(d.get("old")) and d["register"] not in regs_first:
                regs_first[d["register"]] = (d["old"], e["id"])
        tw = ev.twin(ev.window[1])
        if tw:
            twin_m, state = tw
            undo = {r: v for r, (v, _) in regs_first.items()}
            ids = [i for _, i in regs_first.values()]
            if undo:
                r = _compare(twin_m, state, undo, 6)        # "with" = incident writes removed
                F["harm_forecast_without_writes"] = _f(r["with"]["excursion"] > 0, ids)
            else:                                            # no writes to remove: today's forecast
                F["harm_forecast_without_writes"] = _f(_excursion(twin_m.forecast(state, None, 360, every_min=10)) > 0)
        worst = max(blocked, key=lambda e: abs((e["data"].get("new") or 0) - (e["data"].get("old") or 0))
                    if _num(e["data"].get("new")) and _num(e["data"].get("old")) else 0, default=None)
        if worst is not None and worst["data"].get("register") in SETPOINTS and _num(worst["data"].get("new")):
            tw = ev.twin(worst["t"])
            if tw:
                twin_m, state = tw
                r = _compare(twin_m, state, {worst["data"]["register"]: float(worst["data"]["new"])}, 6)
                F["writes_make_forecast_worse"] = _f(r["verdict"] == "worsens", [worst["id"]])
                F["reverses_trend"] = _f(r["verdict"] in ("improves", "safe_and_fixes"), [worst["id"]])
    return F


NUMERIC = ("source_known", "ip_matches_label", "human_present", "human_actions", "off_hours", "recon_fc",
           "regular_interval", "probing", "monotone_push", "push_length", "writes_after_block", "correction_follows",
           "flood_rate", "distinct_sources", "n_writes", "n_blocked", "n_allowed", "lockdown", "weather_aligned",
           "raw_water_changed_recently", "drift_without_decision", "physics_mismatch", "stuck_sensor",
           "lab_disagrees", "forecast_warnings", "ai_origin", "ai_proposal_blocked", "ai_reply_flagged",
           "untrusted_instructions", "auth_failures", "harm_forecast_without_writes", "writes_make_forecast_worse",
           "reverses_trend")


def vector(F: dict) -> list[float]:
    """Numeric feature vector for the learned classifier (None -> -1, bools -> 0/1, counts log-scaled)."""
    import math
    out = []
    for k in NUMERIC:
        v = F.get(k, {}).get("value")
        if v is None:
            out.append(-1.0)
        elif isinstance(v, bool):
            out.append(1.0 if v else 0.0)
        else:
            out.append(math.log1p(max(0.0, float(v))))
    checks = F.get("block_checks", {}).get("value") or {}
    for c in ("range", "step", "ramp", "predict", "flood", "function", "writer", "lockdown", "interlock", "permit"):
        out.append(math.log1p(checks.get(c, 0)))
    return out


def vector_names() -> list[str]:
    return list(NUMERIC) + [f"blocks_{c}" for c in ("range", "step", "ramp", "predict", "flood", "function", "writer",
                                                     "lockdown", "interlock", "permit")]
