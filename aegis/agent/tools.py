"""Sentinel's tools. All of them are read-only.

The investigation starts by freezing the evidence: Sentinel records the audit log's verify() result
and head(), and takes a snapshot of every entry in the incident window (incident start minus 2 h, up
to the head). Every tool reads that snapshot, never the live log, so the model reasons about a fixed
body of evidence, and every record it sees carries the audit entry id it can cite.

Text an attacker can influence (source labels, AI replies and the questions behind them, work orders,
SMS replies) is returned as {"untrusted_text": "..."}: the system prompt tells the model it is
evidence, never instructions.

Deliberately NOT tools: set_setpoint, guard mode or policy changes, clearing lockdowns, permits,
allow-once, sending SMS, web or file access. This module imports no Modbus or CIP client and holds no
reference to the guard; tests check both.
"""
from __future__ import annotations

import bisect
import math
import statistics
from collections import Counter, deque
from dataclasses import dataclass, field

from ..forewarn import ALARM_BANDS, first_crossings
from ..twin import SCALE, Twin

WINDOW_BEFORE_S = 2 * 3600          # evidence window starts this long before the incident opened
PROFILE_S = 7 * 24 * 3600           # source profile looks this far back before the window
MAX_RECORDS = 50
TEXT_MAX = 300
TREND_TAGS = ("ph", "chlorine_residual", "tank_level", "flow_out", "raw_ph", "raw_alkalinity", "raw_turbidity",
              "hocl_pct", "water_temp", "naoh_dose", "chlorine_dose", "distribution_rate", "fluoride")
SETPOINTS = ("naoh_dose", "chlorine_dose", "distribution_rate", "fluoride_dose")
HUMAN_KINDS = ("login", "logout", "auth_failure", "auth_denied", "permit_issued", "allow_once", "allow_once_used",
               "alert_ack", "alert_reply_ignored", "policy_change", "guard_mode", "guard_toggle", "settings",
               "lockdown_cleared", "hold_released", "proposal_decision", "lab_input", "lab_input_rejected",
               "grab_sample")


# Keys whose values an attacker (or anyone outside Aegis) can influence. Every record goes through these.
UNTRUSTED_KEYS = {"source", "sender", "message", "question", "reply", "reason", "notes", "text", "from", "user",
                  "title", "by", "decided_by", "label", "work_order", "note"}


def untrusted(s) -> dict:
    return {"untrusted_text": str(s)[:TEXT_MAX]}


def ip_of(peer: str | None) -> str:
    return peer.rsplit(":", 1)[0] if peer and ":" in peer else ""


def label_text(v) -> str:
    """The raw string inside a possibly-wrapped value."""
    return v["untrusted_text"] if isinstance(v, dict) and "untrusted_text" in v else (v or "")


# ---------------------------------------------------------------------------------------------- history
class PlantHistory:
    """Readings over time (what Aegis saw), so tools can show trends and run the twin from a past moment.
    The server feeds it from its poll loop; the evaluation feeds it through the episode observer."""

    def __init__(self, maxlen: int = 20000):
        self.t: deque = deque(maxlen=maxlen)
        self.rows: deque = deque(maxlen=maxlen)

    def record(self, t: float, readings: dict):
        if self.t and t < self.t[-1]:
            return                                   # keep it ordered; late samples are dropped
        self.t.append(float(t))
        self.rows.append({k: v for k, v in readings.items() if isinstance(v, (int, float, bool))})

    def __call__(self, t: float, readings: dict):    # usable directly as an episode observer
        self.record(t, readings)

    def at(self, t: float) -> tuple[float, dict] | None:
        """Latest sample at or before t."""
        i = bisect.bisect_right(list(self.t), t) - 1
        return (self.t[i], self.rows[i]) if i >= 0 else None

    def between(self, since: float, until: float) -> list[tuple[float, dict]]:
        ts = list(self.t)
        a, b = bisect.bisect_left(ts, since), bisect.bisect_right(ts, until)
        rows = list(self.rows)
        return list(zip(ts[a:b], rows[a:b]))


# ---------------------------------------------------------------------------------------------- evidence
@dataclass
class Evidence:
    """The frozen evidence for one investigation."""
    audit: object
    incident: object
    history: PlantHistory | None = None
    now: float | None = None
    twin_params: dict | None = None
    twin_uncertainty: dict | None = None
    status_fn: object = None             # optional () -> {"guard_mode", "safe_hold", ...}
    work_orders_fn: object = None        # optional () -> list[str]
    features: dict | None = None
    baseline: dict | None = None
    # filled by freeze()
    head: dict = field(default_factory=dict)
    verify: dict = field(default_factory=dict)
    window: tuple = (0.0, 0.0)
    entries: list = field(default_factory=list)
    by_id: dict = field(default_factory=dict)
    profile_entries: list = field(default_factory=list)

    def freeze(self) -> "Evidence":
        self.verify = self.audit.verify()
        self.head = self.audit.head()
        start = self.incident.opened_t - WINDOW_BEFORE_S
        end = self.now if self.now is not None else max(self.incident.last_t, self.incident.opened_t)
        rows = [e for e in self.audit.between(start, None) if e["id"] <= self.head["id"]]
        end = max([end] + [e["t"] for e in rows])
        self.window = (start, end)
        self.entries = rows
        self.by_id = {e["id"]: e for e in rows}
        self.profile_entries = [e for e in self.audit.between(start - PROFILE_S, start, kinds=("decision",))
                                if e["id"] <= self.head["id"]]
        return self

    def of(self, *kinds) -> list[dict]:
        return [e for e in self.entries if e["kind"] in kinds]

    def latest_state(self) -> tuple[float, dict] | None:
        return self.history.at(self.window[1]) if self.history else None

    def twin(self, at_t: float) -> tuple[Twin, dict] | None:
        """A fresh twin primed with the 30 min of raw-water readings before at_t, and the state at at_t."""
        if not self.history:
            return None
        s = self.history.at(at_t)
        if s is None:
            return None
        tw = Twin(self.twin_params, uncertainty=self.twin_uncertainty)
        for t, row in self.history.between(at_t - 30 * 60, at_t):
            tw.observe(row, t)
        return tw, dict(s[1])

    def rel_min(self, t: float) -> float:
        return round((t - self.incident.opened_t) / 60, 1)


# ---------------------------------------------------------------------------------------------- formatting
def _reason(d: dict):
    """The guard writes decision reasons itself, but some quote the source label; then wrap it."""
    r = str(d.get("reason", ""))[:TEXT_MAX]
    src = str(d.get("source") or "")
    return untrusted(r) if src and src in r else r


def fmt_decision(ev: Evidence, e: dict) -> dict:
    d = e["data"]
    return {"id": e["id"], "t": round(e["t"], 1), "min_from_open": ev.rel_min(e["t"]),
            "source": untrusted(d.get("source", "")), "ip": ip_of(d.get("peer")), "register": d.get("register"),
            "old": d.get("old"), "new": d.get("new"), "check": d.get("check"), "reason": _reason(d),
            "allowed": bool(d.get("allowed")), "would_block": bool(d.get("would_block")), "fc": d.get("fc"),
            "techniques": [t[0] if isinstance(t, (list, tuple)) else t for t in d.get("techniques") or []]}


def fmt_entry(ev: Evidence, e: dict, untrusted_keys=()) -> dict:
    """untrusted_keys is kept for readability at call sites; UNTRUSTED_KEYS always applies."""
    keys = UNTRUSTED_KEYS | set(untrusted_keys)
    d = {k: (untrusted(v) if k in keys and v is not None and not isinstance(v, (int, float, bool)) else v)
         for k, v in e["data"].items()}
    return {"id": e["id"], "t": round(e["t"], 1), "min_from_open": ev.rel_min(e["t"]), "kind": e["kind"], **d}


def _cap(xs: list, limit: int) -> dict:
    limit = max(1, min(int(limit or MAX_RECORDS), MAX_RECORDS))
    return {"records": xs[:limit], "total": len(xs), "truncated": len(xs) > limit}


# ---------------------------------------------------------------------------------------------- twin helpers
def _bands(traj: list[dict]) -> dict:
    return {k: v for k, v in ALARM_BANDS.items() if any(p.get(k) is not None for p in traj)}


def _excursion(traj: list[dict]) -> float:
    """Worst distance outside the alarm bands, in comparable units (twin.SCALE); 0 = stays inside."""
    worst = 0.0
    for k, (lo, hi, *_rest) in _bands(traj).items():
        for p in traj:
            v = p.get(k)
            if v is None:
                continue
            worst = max(worst, (lo - v) / SCALE.get(k, 1.0), (v - hi) / SCALE.get(k, 1.0))
    return round(worst, 4)


def _summ(traj: list[dict]) -> dict:
    out = {"crossings": {k: {"minutes": m, "direction": d, "value": v}
                         for k, (m, d, v) in first_crossings(traj, _bands(traj)).items()},
           "excursion": _excursion(traj)}
    for k in ("ph", "chlorine_residual", "tank_level", "hocl_pct", "fluoride"):
        vals = [p[k] for p in traj if p.get(k) is not None]
        if vals:
            out[k] = {"min": round(min(vals), 3), "max": round(max(vals), 3), "end": round(vals[-1], 3)}
    return out


def _compare(tw: Twin, state: dict, override: dict, hours: float) -> dict:
    mins = hours * 60
    without = tw.forecast(state, None, mins, every_min=10)
    with_ = tw.forecast(state, override, mins, every_min=10)
    w, wo = _summ(with_), _summ(without)
    if w["excursion"] == 0 and wo["excursion"] == 0:
        verdict = "safe"
    elif w["excursion"] < wo["excursion"] - 1e-6:
        verdict = "improves" if w["excursion"] > 0 else "safe_and_fixes"
    elif w["excursion"] > wo["excursion"] + 1e-6:
        verdict = "worsens"
    else:
        verdict = "unsafe_either_way"
    return {"hours": hours, "with": w, "without": wo, "verdict": verdict}


# ---------------------------------------------------------------------------------------------- tools
def get_incident(ev: Evidence) -> dict:
    inc = ev.incident
    trig = [ev.by_id[i] for i in inc.trigger_ids if i in ev.by_id]
    fmt = lambda e: (fmt_decision(ev, e) if e["kind"] == "decision"
                     else fmt_entry(ev, e, ("source", "sender", "message")))
    # compact: counts plus the first and last few triggers (get_decisions pages through the rest)
    by_check = Counter(e["data"].get("check") for e in trig if e["kind"] == "decision")
    shown = trig if len(trig) <= 8 else trig[:5] + trig[-3:]
    ids = list(inc.entry_ids)
    return {"incident": {**inc.summary(), "sources": [untrusted(s) for s in sorted(inc.sources)]},
            "window": {"start": ev.window[0], "end": ev.window[1]},
            "evidence_frozen_at": {"head_id": ev.head.get("id"), "head_hash": ev.head.get("hash"),
                                   "chain_ok": ev.verify.get("ok")},
            "coalesced_entry_ids": ids if len(ids) <= 40 else {"first": ids[:20], "last": ids[-10:], "total": len(ids)},
            "trigger_counts": {"by_kind": dict(inc.kinds), "decisions_by_check": dict(by_check)},
            "triggers_sample": [fmt(e) for e in shown],
            "triggers_omitted": max(0, len(trig) - len(shown)),
            "features": ev.features, "baseline": ev.baseline}


def get_decisions(ev: Evidence, source: str | None = None, ip: str | None = None, register: str | None = None,
                  since: float | None = None, until: float | None = None, only_blocked: bool = False,
                  limit: int = MAX_RECORDS) -> dict:
    out = []
    for e in ev.of("decision"):
        d = e["data"]
        if source and d.get("source") != source:
            continue
        if ip and ip_of(d.get("peer")) != ip:
            continue
        if register and d.get("register") != register:
            continue
        if since is not None and e["t"] < since:
            continue
        if until is not None and e["t"] > until:
            continue
        if only_blocked and d.get("allowed") and not d.get("would_block"):
            continue
        out.append(fmt_decision(ev, e))
    res = _cap(out, limit)
    sup = [fmt_entry(ev, e, ("sender",)) for e in ev.of("decisions_suppressed")
           if (not register or e["data"].get("register") == register)]
    if sup:
        res["suppressed_bursts"] = sup[:10]
    return res


def get_source_profile(ev: Evidence, source: str | None = None, ip: str | None = None) -> dict:
    if not source and not ip:
        return {"error": "give source or ip"}

    def mine(e):
        d = e["data"]
        return (source is None or d.get("source") == source) and (ip is None or ip_of(d.get("peer")) == ip)
    past = [e for e in ev.profile_entries if mine(e)]
    now = [e for e in ev.of("decision") if mine(e)]

    def stats(xs):
        if not xs:
            return {"writes": 0}
        steps = [abs(e["data"]["new"] - e["data"]["old"]) for e in xs
                 if isinstance(e["data"].get("new"), (int, float)) and isinstance(e["data"].get("old"), (int, float))]
        span_h = max((xs[-1]["t"] - xs[0]["t"]) / 3600, 1 / 60)
        return {"writes": len(xs), "registers": dict(Counter(e["data"].get("register") for e in xs)),
                "ips": sorted({ip_of(e["data"].get("peer")) for e in xs} - {""}),
                "hours_of_day": sorted({int(e["t"] // 3600 % 24) for e in xs}),
                "median_step": round(statistics.median(steps), 4) if steps else None,
                "writes_per_hour": round(len(xs) / span_h, 2),
                "blocked": sum(not e["data"].get("allowed") for e in xs)}
    p, n = stats(past), stats(now)
    new = {}
    if p["writes"]:
        new["registers"] = sorted(set(n.get("registers", {})) - set(p["registers"]))
        new["ips"] = sorted(set(n.get("ips", [])) - set(p["ips"]))
        new["hours_of_day"] = sorted(set(n.get("hours_of_day", [])) - set(p["hours_of_day"]))
    return {"query": {"source": untrusted(source) if source else None, "ip": ip},
            "previous_7_days": p, "this_window": n,
            "new_in_this_window": new if p["writes"] else "no history for this source in the previous 7 days",
            "window_ids": [e["id"] for e in now][:MAX_RECORDS]}


def get_lockdowns(ev: Evidence) -> dict:
    """From the audit log (citable), not from guard state."""
    locks = [fmt_entry(ev, e, ("source",)) for e in ev.of("lockdown")]
    cleared = [fmt_entry(ev, e, ("source",)) for e in ev.of("lockdown_cleared")]
    active = {label_text(x["source"]) for x in locks} - {label_text(x["source"]) for x in cleared}
    return {"lockdowns": locks, "cleared": cleared, "still_locked": [untrusted(s) for s in sorted(active)]}


def get_integrity(ev: Evidence, since: float | None = None) -> dict:
    xs = [fmt_entry(ev, e, ("message", "notes", "by")) for e in ev.of("integrity", "grab_sample", "lab_input_rejected")
          if since is None or e["t"] >= since]
    return _cap(xs, MAX_RECORDS)


def get_forecast_warnings(ev: Evidence, since: float | None = None) -> dict:
    xs = [fmt_entry(ev, e) for e in ev.of("forecast_warning", "recovery_guidance") if since is None or e["t"] >= since]
    res = _cap(xs, MAX_RECORDS)
    tw = ev.twin(ev.window[1])
    if tw:
        twin, state = tw
        traj = twin.forecast(state, None, 360, every_min=10)
        res["current_forecast"] = {"hours": 6, **_summ(traj)}
    else:
        res["current_forecast"] = "no plant readings available"
    return res


def get_trend(ev: Evidence, tag: str, minutes: float = 120) -> dict:
    if tag not in TREND_TAGS:
        return {"error": f"unknown tag; one of {list(TREND_TAGS)}"}
    if not ev.history:
        return {"error": "no plant readings available"}
    minutes = max(5, min(float(minutes), 24 * 60))
    rows = [(t, r[tag]) for t, r in ev.history.between(ev.window[1] - minutes * 60, ev.window[1]) if tag in r]
    if not rows:
        return {"tag": tag, "samples": []}
    step = max(1, math.ceil(len(rows) / 40))
    pts = rows[::step]
    if pts[-1] != rows[-1]:
        pts.append(rows[-1])
    vals = [v for _, v in rows]
    return {"tag": tag, "minutes": minutes, "min": round(min(vals), 4), "max": round(max(vals), 4),
            "first": round(vals[0], 4), "last": round(vals[-1], 4),
            "samples": [{"min_from_open": ev.rel_min(t), "value": round(v, 4)} for t, v in pts]}


def get_plant_status(ev: Evidence) -> dict:
    s = ev.latest_state()
    out = {"readings": None, "out_of_band": []}
    if s:
        t, row = s
        out["readings_at_min_from_open"] = ev.rel_min(t)
        out["readings"] = {k: round(v, 4) if isinstance(v, float) else v for k, v in row.items()}
        for k, (lo, hi, *_r) in ALARM_BANDS.items():
            v = row.get(k)
            if v is not None and not lo <= v <= hi:
                out["out_of_band"].append({"tag": k, "value": round(v, 3), "band": [lo, hi]})
    if ev.status_fn:
        try:
            out["guard"] = ev.status_fn()
        except Exception as ex:          # status is a convenience; never let it break the investigation
            out["guard"] = {"error": str(ex)[:100]}
    holds = [fmt_entry(ev, e) for e in ev.of("safe_hold", "hold_released", "safe_hold_failed")]
    if holds:
        out["safe_hold_events"] = holds[-10:]
    modes = [fmt_entry(ev, e) for e in ev.of("guard_mode", "guard_toggle")]
    if modes:
        out["guard_mode_changes"] = modes[-10:]
    return out


def get_human_activity(ev: Evidence, since: float | None = None) -> dict:
    xs = [fmt_entry(ev, e, ("text", "from", "notes", "user", "title")) for e in ev.of(*HUMAN_KINDS)
          if since is None or e["t"] >= since]
    acks = sum(x["kind"] == "alert_ack" for x in xs)
    logins = sum(x["kind"] == "login" for x in xs)
    return {**_cap(xs, MAX_RECORDS), "counts": dict(Counter(x["kind"] for x in xs)),
            "note": "no logins, acks, permits or dashboard actions in the window" if not xs else
            f"{logins} logins and {acks} alert acks in the window"}


def get_ai_activity(ev: Evidence, since: float | None = None) -> dict:
    xs = [fmt_entry(ev, e, ("question", "reply", "reason", "source")) for e in ev.of("proposal", "proposal_decision",
                                                                                     "ai_reply_flagged", "settings")
          if since is None or e["t"] >= since]
    out = _cap(xs, MAX_RECORDS)
    if ev.work_orders_fn:
        try:
            out["work_orders_the_copilot_can_read"] = [untrusted(w) for w in (ev.work_orders_fn() or [])][:20]
            out["work_orders_note"] = "not in the audit log: cannot be cited, only described as untrusted input"
        except Exception:
            pass
    return out


def simulate(ev: Evidence, changes: list, hours: float = 6) -> dict:
    hours = max(1.0, min(float(hours), 12.0))
    override = {}
    for c in changes or []:
        if not isinstance(c, dict) or c.get("register") not in SETPOINTS or not isinstance(c.get("value"), (int, float)):
            return {"error": f"each change is {{register: one of {list(SETPOINTS)}, value: number}}"}
        override[c["register"]] = float(c["value"])
    if not override:
        return {"error": "no changes given"}
    tw = ev.twin(ev.window[1])
    if not tw:
        return {"error": "no plant readings available"}
    twin, state = tw
    return {"changes": override, "from_state_at_min": ev.rel_min(ev.latest_state()[0]),
            **_compare(twin, state, override, hours)}


def counterfactual(ev: Evidence, decision_id: int) -> dict:
    e = ev.by_id.get(int(decision_id))
    if e is None or e["kind"] != "decision":
        return {"error": "not a decision in this incident's window"}
    d = e["data"]
    if d.get("allowed") and not d.get("would_block"):
        return {"error": "that write was allowed; use simulate for what-ifs on allowed writes"}
    if d.get("register") not in SETPOINTS or not isinstance(d.get("new"), (int, float)):
        return {"error": "counterfactual only for setpoint writes"}
    tw = ev.twin(e["t"])
    if not tw:
        return {"error": "no plant readings at that time"}
    twin, state = tw
    r = _compare(twin, state, {d["register"]: float(d["new"])}, 6)
    prevented = {k: v for k, v in r["with"]["crossings"].items() if k not in r["without"]["crossings"]}
    return {"decision_id": e["id"], "register": d["register"], "blocked_value": d["new"], "was": d.get("old"),
            "if_it_had_landed": r, "harm_prevented": prevented,
            "summary": ("would have pushed " + ", ".join(f"{k} {v['direction']} its band in ~{v['minutes']:g} min"
                                                       for k, v in prevented.items())) if prevented else
            ("no new band crossing; " + r["verdict"])}


def verify_evidence(ev: Evidence, ids: list) -> dict:
    ids = [int(i) for i in (ids or [])][:MAX_RECORDS]
    rows = ev.audit.check_rows(ids)
    out = []
    for i in ids:
        r = rows[i]
        snap = ev.by_id.get(i)
        rec = {"id": i, "exists": r["exists"], "in_window": snap is not None, "hash_ok": r["hash_ok"],
               "link_ok": r["link_ok"], "unchanged_since_freeze": bool(snap and r.get("hash") == snap["hash"])}
        rec["ok"] = all(rec[k] for k in ("exists", "in_window", "hash_ok", "link_ok", "unchanged_since_freeze"))
        if snap:
            rec["kind"] = snap["kind"]
            rec["data"] = fmt_decision(ev, snap) if snap["kind"] == "decision" else fmt_entry(ev, snap)
        out.append(rec)
    return {"results": out, "all_ok": all(x["ok"] for x in out) if out else False}


# ---------------------------------------------------------------------------------------------- registry
_S = {"type": "string"}
_N = {"type": "number"}
_I = {"type": "integer"}
TOOLS = {
    "get_incident": (get_incident, "The incident: triggering events, window, coalesced entry ids, extracted features "
                                   "and the rule baseline's verdict.", {}),
    "get_decisions": (get_decisions, "Guard decisions in the window, filterable. Each has an audit id to cite.",
                      {"source": _S, "ip": _S, "register": _S, "since": _N, "until": _N,
                       "only_blocked": {"type": "boolean"}, "limit": _I}),
    "get_source_profile": (get_source_profile, "How a source (label) or IP behaved over the previous 7 days vs this "
                                               "window: registers, step sizes, hours, rate, IPs; what is new.",
                           {"source": _S, "ip": _S}),
    "get_lockdowns": (get_lockdowns, "Lockdowns and clears in the window (from the audit log).", {}),
    "get_integrity": (get_integrity, "Integrity events: setpoint drift, physics mismatch, stuck sensors, lab "
                                     "grab samples.", {"since": _N}),
    "get_forecast_warnings": (get_forecast_warnings, "Forecast warnings in the window and the twin's current 6 h "
                                                     "forecast band crossings.", {"since": _N}),
    "get_trend": (get_trend, "Recent samples of one plant reading.", {"tag": {"type": "string", "enum": list(TREND_TAGS)},
                                                                      "minutes": _N}),
    "get_plant_status": (get_plant_status, "Latest readings, out-of-band values, guard and safe-hold status.", {}),
    "get_human_activity": (get_human_activity, "Logins, PIN failures, permits, allow-once, alert acks, mode and "
                                               "policy changes: was a real operator present?", {"since": _N}),
    "get_ai_activity": (get_ai_activity, "Copilot proposals, flagged AI replies, autonomy changes, and the work orders "
                                         "the copilot can read (untrusted).", {"since": _N}),
    "simulate": (simulate, "Twin forecast with and without setpoint changes from the current state.",
                 {"changes": {"type": "array", "items": {"type": "object", "properties": {
                     "register": {"type": "string", "enum": list(SETPOINTS)}, "value": _N},
                     "required": ["register", "value"]}}, "hours": _N}),
    "counterfactual": (counterfactual, "What the twin predicts would have happened if a blocked write had landed.",
                       {"decision_id": _I}),
    "verify_evidence": (verify_evidence, "Check audit entry ids: exist, inside the window, hash and chain link "
                                         "intact, unchanged since the evidence was frozen.",
                        {"ids": {"type": "array", "items": _I}}),
}
REQUIRED = {"get_trend": ["tag"], "simulate": ["changes"], "counterfactual": ["decision_id"], "verify_evidence": ["ids"]}


def schemas() -> list[dict]:
    """OpenAI-style function definitions for the model."""
    return [{"type": "function", "function": {"name": n, "description": desc,
                                              "parameters": {"type": "object", "properties": props,
                                                             "required": REQUIRED.get(n, [])}}}
            for n, (_, desc, props) in TOOLS.items()]


_PY = {"string": str, "number": (int, float), "integer": int, "boolean": bool, "array": list, "object": dict}


def call(ev: Evidence, name: str, args: dict | None) -> dict:
    """Run one tool with validated arguments. Unknown tools and bad arguments return an error dict;
    nothing here can raise into the loop or reach anything but the frozen evidence and the twin."""
    if name not in TOOLS:
        return {"error": f"no such tool: {str(name)[:40]}. Tools are read-only: {sorted(TOOLS)}"}
    fn, _, props = TOOLS[name]
    args = dict(args or {})
    extra = set(args) - set(props)
    if extra:
        return {"error": f"unknown argument(s) {sorted(extra)}"}
    for k in REQUIRED.get(name, []):
        if k not in args:
            return {"error": f"missing argument {k}"}
    for k, v in args.items():
        typ = props[k].get("type")
        if v is None:
            continue
        if typ and (not isinstance(v, _PY[typ]) or (typ in ("number", "integer") and isinstance(v, bool))):
            return {"error": f"argument {k} must be {typ}"}
        if "enum" in props[k] and v not in props[k]["enum"]:
            return {"error": f"argument {k} must be one of {props[k]['enum']}"}
    try:
        return fn(ev, **args)
    except Exception as ex:                 # a tool bug becomes evidence of a tool bug, not a crash
        return {"error": f"{type(ex).__name__}: {str(ex)[:200]}"}
