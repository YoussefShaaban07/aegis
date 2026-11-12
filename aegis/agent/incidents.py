"""Incident store: turns audit-log events into incidents worth investigating.

Sentinel tails the audit log (it never hooks into the guard, so the guard's code and timing are
untouched). An event that matters opens an incident; later events that look like the same activity
join it, so a 30-write flood is one incident, not 30 investigations.

Triggers (spec section 4.1)
    decision            blocked, or would-block in monitor mode
    decision (unusual)  only on the 3rd "unusual but allowed" write from one source within 30 min
    decisions_suppressed  a burst of identical blocked writes summarised by the guard
    lockdown            always (investigated immediately)
    integrity           severity warning or critical (critical is investigated immediately)
    grab_sample         lab result disagrees with the PLC
    forecast_warning    only if a write was allowed in the previous 60 min (otherwise it is weather,
                        handled by the operator, not an incident)
    ai_reply_flagged    always
    proposal            an AI copilot proposal the guard pre-check blocked (never Sentinel's own)
    auth_failure        3 or more within 10 min
    safe_hold           always (Aegis had to revert a setpoint)

Coalescing (4.2)
    An event joins an open incident if it is within 15 min of that incident's last event and shares a
    source, an IP or a register. Events that carry none of those (auth failures, forecast warnings,
    plant-wide integrity events) join the most recent open incident within 15 min, else open their own.
    Allowed writes never open an incident but join a matching one (they are what "got through").
    An incident is ready 30 min after its last event, or at once on lockdown / integrity critical.

Budget (4.2)
    At most 1 investigation running and 6 started per hour; the rest queue. If more than 10 are queued,
    the overflow falls back to the deterministic report and ONE alert says so, so an attacker cannot
    exhaust the agent by flooding events.

States (4.3)
    COLLECTING -> READY -> INVESTIGATING -> REPORTED -> AWAITING_APPROVAL -> CLOSED, plus
    FAILED_FALLBACK, and REOPENED (a matching event within 2 h of being reported or closed; it then
    collects again). The spec's OPEN state is the moment of creation, recorded in the history.

Sentinel's own audit entries (kind "agent_*") are ignored, so the agent cannot trigger itself.
"""
from __future__ import annotations

import itertools
from collections import deque
from dataclasses import dataclass, field

SAFE_HOLD_SOURCE = "Aegis safe-hold"

DEFAULTS = {
    "join_window_s": 15 * 60,       # an event joins an incident whose last event is this recent
    "quiet_s": 30 * 60,             # ready after this long with no new events
    "reopen_s": 2 * 3600,           # a matching event this soon after close reopens the incident
    "unusual_n": 3, "unusual_window_s": 30 * 60,
    "auth_n": 3, "auth_window_s": 10 * 60,
    "forecast_write_window_s": 60 * 60,
    "max_running": 1, "max_per_hour": 6, "max_queue": 10,
}

COLLECTING, READY, INVESTIGATING = "COLLECTING", "READY", "INVESTIGATING"
REPORTED, AWAITING_APPROVAL, CLOSED = "REPORTED", "AWAITING_APPROVAL", "CLOSED"
FAILED_FALLBACK, REOPENED = "FAILED_FALLBACK", "REOPENED"
ACTIVE = (COLLECTING, REOPENED)                   # still accepting events
DONE = (REPORTED, AWAITING_APPROVAL, CLOSED, FAILED_FALLBACK)


def ip_of(peer: str | None) -> str:
    """'10.9.9.9:4444' -> '10.9.9.9'. Internal peers ('aegis', '') give ''."""
    if not peer or ":" not in peer:
        return ""
    return peer.rsplit(":", 1)[0]


@dataclass
class Incident:
    id: int
    opened_t: float
    last_t: float
    state: str = COLLECTING
    entry_ids: list = field(default_factory=list)     # audit entry ids that belong to this incident
    trigger_ids: list = field(default_factory=list)   # the subset that were triggers (not just context)
    kinds: dict = field(default_factory=dict)         # trigger kind -> count
    sources: set = field(default_factory=set)
    ips: set = field(default_factory=set)
    registers: set = field(default_factory=set)
    urgent: bool = False                              # lockdown / integrity critical: don't wait out quiet_s
    ready_t: float | None = None
    started_t: float | None = None
    done_t: float | None = None
    reopened: int = 0
    note: str = ""
    history: list = field(default_factory=list)       # (t, state)
    result: dict | None = None                        # filled by the investigation loop

    def keys(self) -> tuple[set, set, set]:
        return self.sources, self.ips, self.registers

    def summary(self) -> dict:
        return {"id": self.id, "state": self.state, "opened_t": self.opened_t, "last_t": self.last_t,
                "events": len(self.entry_ids), "triggers": len(self.trigger_ids), "kinds": dict(self.kinds),
                "sources": sorted(self.sources), "ips": sorted(self.ips), "registers": sorted(self.registers),
                "reopened": self.reopened, "note": self.note,
                "classification": (self.result or {}).get("classification")}


def _keys(e: dict) -> tuple[set, set, set]:
    """(sources, ips, registers) an audit entry refers to."""
    d, k = e["data"], e["kind"]
    src, ips, regs = set(), set(), set()
    if k in ("decision", "proposal"):
        if d.get("source"):
            src.add(d["source"])
        if ip_of(d.get("peer")):
            ips.add(ip_of(d.get("peer")))
        if d.get("register") or d.get("name"):
            regs.add(d.get("register") or d.get("name"))
    elif k == "decisions_suppressed":             # sender is an IP when the guard knew one, else a label
        s = d.get("sender") or ""
        (ips if s.replace(".", "").isdigit() else src).add(s)
        if d.get("register"):
            regs.add(d["register"])
    elif k == "lockdown":
        if d.get("source"):
            src.add(d["source"])
        if d.get("last_register"):
            regs.add(d["last_register"])
    elif k in ("safe_hold", "integrity"):
        if d.get("register"):
            regs.add(d["register"])
    src.discard("")
    ips.discard("")
    return src, ips, regs


class IncidentManager:
    def __init__(self, audit, config: dict | None = None, alerter=None, clock=None):
        self.audit = audit
        self.cfg = {**DEFAULTS, **(config or {})}
        self.alerter = alerter
        self.clock = clock or getattr(audit, "clock", None)
        self.incidents: dict[int, Incident] = {}
        self._ids = itertools.count(1)
        self.last_id = 0
        self._unusual: dict[str, deque] = {}        # source -> recent unusual decisions (t, id)
        self._auth: deque = deque()                 # recent auth failures (t, id)
        self._last_allowed_write: float | None = None
        self._starts: deque = deque()               # times investigations started (rate limit)
        self._overflow_alerted = False

    # ------------------------------------------------------------------ helpers
    def _now(self, now):
        return now if now is not None else (self.clock() if self.clock else 0.0)

    def _log(self, kind: str, data: dict):
        if self.audit is not None:
            self.audit.append(kind, data)

    def _set(self, inc: Incident, state: str, t: float):
        inc.state = state
        inc.history.append((t, state))

    def get(self, iid: int) -> Incident | None:
        return self.incidents.get(iid)

    def list(self) -> list[Incident]:
        return sorted(self.incidents.values(), key=lambda i: -i.id)

    # ------------------------------------------------------------------ classification of events
    def _trigger(self, e: dict) -> tuple[bool, bool, str]:
        """-> (is_trigger, urgent, why). Non-triggers may still join an incident as context."""
        k, d, t = e["kind"], e["data"], e["t"]
        if k == "decision":
            if d.get("source") == SAFE_HOLD_SOURCE:
                return False, False, ""             # the safe_hold entry is the trigger
            if not d.get("allowed") or d.get("would_block"):
                return True, False, "blocked write" if not d.get("allowed") else "would-block (monitor)"
            if d.get("allowed") and d.get("old") is not None and d.get("new") != d.get("old"):
                self._last_allowed_write = t
            if d.get("check") == "unusual":
                q = self._unusual.setdefault(d.get("source", ""), deque())
                q.append((t, e["id"]))
                while q and t - q[0][0] > self.cfg["unusual_window_s"]:
                    q.popleft()
                if len(q) >= self.cfg["unusual_n"]:
                    return True, False, f"{len(q)} unusual writes in 30 min"
            return False, False, ""
        if k == "decisions_suppressed":
            return True, False, "burst of blocked writes"
        if k == "lockdown":
            return True, True, "source locked down"
        if k == "integrity":
            sev = d.get("severity")
            if sev in ("warning", "critical"):
                return True, sev == "critical", f"integrity {sev}"
            return False, False, ""
        if k == "grab_sample":
            return (not d.get("ok", True)), False, "lab disagrees with PLC"
        if k == "forecast_warning":
            w = self._last_allowed_write
            if w is not None and 0 <= t - w <= self.cfg["forecast_write_window_s"]:
                return True, False, "forecast crossing after a write"
            return False, False, ""
        if k == "ai_reply_flagged":
            return True, False, "AI reply flagged"
        if k == "proposal" and d.get("status") == "blocked" and d.get("source") != "Sentinel":
            return True, False, "AI proposal blocked by the guard"
        if k == "auth_failure":
            self._auth.append((t, e["id"]))
            while self._auth and t - self._auth[0][0] > self.cfg["auth_window_s"]:
                self._auth.popleft()
            if len(self._auth) >= self.cfg["auth_n"]:
                return True, False, f"{len(self._auth)} failed PIN attempts in 10 min"
            return False, False, ""
        if k == "safe_hold":
            return True, False, "safe-hold reverted a setpoint"
        return False, False, ""

    # ------------------------------------------------------------------ matching
    def _match(self, e: dict, keyed: bool) -> Incident | None:
        """Open incident this event belongs to (or a recently finished one to reopen)."""
        src, ips, regs = _keys(e)
        t = e["t"]
        cands = []
        for inc in self.incidents.values():
            open_ = inc.state in ACTIVE and t - inc.last_t <= self.cfg["join_window_s"]
            reopen = inc.state in DONE and inc.done_t is not None and t - inc.done_t <= self.cfg["reopen_s"]
            if not (open_ or reopen):
                continue
            if keyed:
                s, i, r = inc.keys()
                if not (src & s or ips & i or regs & r):
                    continue
            elif not open_:
                continue                           # unkeyed events never reopen an incident
            cands.append((open_, inc.last_t, inc.id, inc))
        return max(cands)[3] if cands else None      # open beats finished; then most recently active

    def _add(self, inc: Incident, e: dict, trigger: bool, why: str, urgent: bool, earlier: list = ()):
        for eid in earlier:                        # e.g. the first 2 unusual writes / auth failures
            if eid not in inc.entry_ids:
                inc.entry_ids.append(eid)
        if e["id"] not in inc.entry_ids:
            inc.entry_ids.append(e["id"])
        if trigger:
            inc.trigger_ids.append(e["id"])
            inc.kinds[e["kind"]] = inc.kinds.get(e["kind"], 0) + 1
        s, i, r = _keys(e)
        inc.sources |= s
        inc.ips |= i
        inc.registers |= r
        inc.last_t = max(inc.last_t, e["t"])
        inc.urgent = inc.urgent or urgent
        if why and not inc.note:
            inc.note = why

    # ------------------------------------------------------------------ main entry points
    def ingest(self, e: dict) -> Incident | None:
        """Process one audit entry. Returns the incident it was attached to, if any."""
        if e["kind"].startswith("agent_"):
            return None
        trigger, urgent, why = self._trigger(e)
        src, ips, regs = _keys(e)
        keyed = bool(src or ips or regs)
        inc = self._match(e, keyed)
        if inc is None and not trigger:
            return None
        if inc is not None and inc.state in DONE:
            if not trigger:
                return None                         # context alone never reopens
            inc.reopened += 1
            inc.done_t = None
            self._set(inc, REOPENED, e["t"])
            self._log("agent_incident_open", {"incident": inc.id, "reopened": inc.reopened, "trigger_id": e["id"],
                                              "kind": e["kind"], "why": why})
        if inc is None:
            inc = Incident(next(self._ids), e["t"], e["t"])
            inc.history.append((e["t"], "OPEN"))
            self._set(inc, COLLECTING, e["t"])
            self.incidents[inc.id] = inc
            self._log("agent_incident_open", {"incident": inc.id, "trigger_id": e["id"], "kind": e["kind"],
                                              "why": why})
        earlier = []
        if trigger and e["kind"] == "decision" and e["data"].get("check") == "unusual":
            earlier = [i for _, i in self._unusual.get(e["data"].get("source", ""), ())]
        if trigger and e["kind"] == "auth_failure":
            earlier = [i for _, i in self._auth]
        self._add(inc, e, trigger, why, urgent, earlier)
        return inc

    def poll(self, now: float | None = None) -> list[Incident]:
        """Read new audit entries, update incidents, and return the ones to investigate now."""
        while True:
            batch = self.audit.after(self.last_id)
            if not batch:
                break
            for e in batch:
                self.last_id = e["id"]
                self.ingest(e)
        return self.tick(now)

    def tick(self, now: float | None = None) -> list[Incident]:
        """Promote quiet incidents to READY and start as many as the budget allows."""
        now = self._now(now)
        for inc in self.incidents.values():
            if inc.state in ACTIVE and (inc.urgent or now - inc.last_t >= self.cfg["quiet_s"]):
                inc.ready_t = now
                self._set(inc, READY, now)
        queue = sorted((i for i in self.incidents.values() if i.state == READY),
                       key=lambda i: (not i.urgent, i.ready_t, i.id))
        while self._starts and now - self._starts[0] > 3600:
            self._starts.popleft()
        running = sum(i.state == INVESTIGATING for i in self.incidents.values())
        out = []
        for inc in queue:
            if running >= self.cfg["max_running"] or len(self._starts) >= self.cfg["max_per_hour"]:
                break
            self._set(inc, INVESTIGATING, now)
            inc.started_t = now
            self._starts.append(now)
            running += 1
            out.append(inc)
        # overflow: keep the 10 most urgent/oldest waiting, deterministic fallback for the rest, one alert
        waiting = [i for i in queue if i.state == READY]
        if len(waiting) > self.cfg["max_queue"]:
            over = waiting[self.cfg["max_queue"]:]
            for inc in over:
                self.fallback(inc.id, "queue overflow: deterministic report only", now)
            if not self._overflow_alerted:
                self._overflow_alerted = True
                msg = (f"Sentinel: {len(waiting)} incidents waiting; investigating the first "
                       f"{self.cfg['max_queue']}, deterministic reports only for the other {len(over)}.")
                self._log("agent_fallback", {"reason": "queue_overflow", "fallback": [i.id for i in over]})
                if self.alerter:
                    self.alerter.raise_alert("sentinel:overflow", "warning", msg)
        elif len(waiting) < self.cfg["max_queue"]:
            self._overflow_alerted = False
        return out

    def finish(self, iid: int, state: str = REPORTED, now: float | None = None, result: dict | None = None):
        """Called by the investigation loop when it is done with an incident."""
        inc = self.incidents[iid]
        now = self._now(now)
        if result is not None:
            inc.result = result
        inc.done_t = now
        self._set(inc, state, now)
        return inc

    def fallback(self, iid: int, why: str, now: float | None = None):
        inc = self.finish(iid, FAILED_FALLBACK, now)
        inc.note = why
        return inc

    def close(self, iid: int, now: float | None = None):
        return self.finish(iid, CLOSED, now)
