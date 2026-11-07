"""Aegis guard: a Modbus TCP proxy in front of the PLC.

Every write, whether it comes from the operator HMI, the AI copilot, or an
attacker, is decoded and checked before it reaches the PLC. Reads pass through.

Checks, in order (first failure wins):
  0. function   only known function codes pass; diagnostics (8), device ID (43),
                vendor programming codes (90 UMAS) etc. are blocked and logged
  1. flood      too many write attempts from one source in 60 s
  2. allowlist  register/coil must be listed in the policy
  3. range      absolute min/max
  4. step       largest change in a single command
  5. ramp       largest net change within any 60 s window (slow-ramp attacks)
  6. interlock  process conditions (e.g. don't stop distribution when tank is nearly full)
  6b. permit    critical commands (e.g. stopping the town's pump) need a
                single-use permit issued on the dashboard with the PIN
  7. predict    digital twin: simulate the next hours with and without the
                command; block if it would drive pH / chlorine / level out of
                the safe band (catches changes that pass every static rule)
  8. unusual    (alert only) outside the band learned from normal traffic

Every write function code is covered, including Mask Write (22) and
Read/Write Multiple (23), which naive filters forget and attackers use to slip past them.

Modes: enforce (block), monitor (log "would block" but pass: for a trial
period at a utility before trusting it), off (pass everything, loudly).

No LLM anywhere in here: a hijacked AI cannot talk its way past it.
"""
from __future__ import annotations

import inspect
import statistics
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from . import modbus
from .config import Tags, load_policy, save_policy, validate_policy

SOURCES = {1: "Operator HMI", 2: "AI copilot"}   # Modbus unit-id labels (spoofable; log only)
WINDOW = 60.0
MODES = ("enforce", "monitor", "off")

# MITRE ATT&CK for ICS technique IDs, attached to each block so incident
# reports speak the language security teams and CISA use.
ATTACK = {
    "function": [("T0855", "Unauthorized Command Message")],
    "flood": [("T0806", "Brute Force I/O")],
    "allowlist": [("T0855", "Unauthorized Command Message")],
    "range": [("T0836", "Modify Parameter")],
    "step": [("T0836", "Modify Parameter")],
    "ramp": [("T0836", "Modify Parameter")],
    "interlock": [("T0831", "Manipulation of Control")],
    "permit": [("T0855", "Unauthorized Command Message"), ("T0826", "Loss of Availability")],
    "predict": [("T0831", "Manipulation of Control"), ("T0836", "Modify Parameter")],
}
FC_ATTACK = {8: ("T0814", "Denial of Service"), 43: ("T0888", "Remote System Information Discovery"),
             90: ("T0843", "Program Download"), 17: ("T0888", "Remote System Information Discovery")}
AI_TAG = ("LLM01", "Prompt injection (OWASP LLM Top 10)")


@dataclass
class Decision:
    allowed: bool
    source: str
    register: str
    old: float | None
    new: float
    reason: str
    peer: str
    check: str = "ok"
    t: float = field(default_factory=time.time)
    unit: str = ""
    fc: int = 0
    techniques: list = field(default_factory=list)
    would_block: bool = False          # monitor mode: logged, not enforced
    forecast: dict | None = None       # twin forecast (UI only, not audited)

    def as_dict(self, forecast: bool = False):
        d = dict(self.__dict__)
        if not forecast:
            d.pop("forecast", None)
        return d


def _pct(xs, q):
    if not xs:
        return None
    xs = sorted(xs)
    return xs[min(len(xs) - 1, int(q * len(xs)))]


class Guard:
    def __init__(self, upstream: modbus.Client | None, read_state, tags: Tags | None = None,
                 policy: dict | None = None, enabled: bool = True, audit=None, alerter=None,
                 clock=time.time, policy_path=None, twin=None, mode: str | None = None):
        """upstream: client to the real PLC. read_state(): current values (sync or async)."""
        self.upstream = upstream
        self.read_state = read_state
        self.tags = tags or Tags.load()
        self.policy_path = policy_path
        self.policy = validate_policy(policy, self.tags) if policy else load_policy(self.tags)
        self.mode = mode or ("enforce" if enabled else "off")
        self.audit = audit
        self.alerter = alerter
        self.clock = clock
        self.twin = twin
        self.log: deque[Decision] = deque(maxlen=200)
        self._changes: dict[str, deque] = defaultdict(deque)   # register -> (t, before, after)
        self._attempts: dict[str, deque] = defaultdict(deque)  # source -> attempt times
        self.lat_check: deque = deque(maxlen=5000)   # ms spent deciding (per write request)
        self.lat_total: deque = deque(maxlen=5000)   # ms per request incl. PLC round trip
        self.counts = defaultdict(int)
        # Hosts whose HMI/AI-labelled writes are counted per label only (the
        # all-in-one demo runs HMI, AI and attackers on one machine). Any other
        # label from these hosts is still counted per IP.
        self.trusted_ips: set[str] = set()
        self.permits: dict[tuple, dict] = {}

    @property
    def enabled(self) -> bool:
        return self.mode != "off"

    # ------------------------------------------------------------------ rules
    def _unit(self, register: str) -> str:
        t = self.tags.holding.get(register)
        return t.unit if t else ""

    def _baseline(self, register: str, current: float | None, now: float) -> float | None:
        """Value this register had at the start of the 60 s window."""
        dq = self._changes[register]
        while dq and now - dq[0][0] > WINDOW:
            dq.popleft()
        return dq[0][1] if dq else current

    def check(self, register: str, new: float, state: dict, source: str, peer: str,
              dry_run: bool = False, together: dict | None = None, fc: int = 0) -> Decision:
        """Decide one write. `together`: other values written in the same request (for the twin)."""
        now = self.clock()
        old = state.get(register)
        u = self._unit(register)

        def deny(check, reason):
            tech = list(ATTACK.get(check, []))
            if source == "AI copilot":
                tech.append(AI_TAG)
            return Decision(False, source, register, old, new, reason, peer, check, now, u, fc, tech)

        # 1. flood: counted per source label AND per IP address, because Modbus
        #    unit IDs are free to spoof (an attacker can rotate them to dodge a per-label cap)
        cap = self.policy["max_writes_per_min_per_source"]
        ip = peer.rsplit(":", 1)[0] if peer and ":" in peer else None
        trusted = ip in self.trusted_ips and source in SOURCES.values()   # HMI/AI on the trusted host
        keys = [source] + ([f"ip:{ip}"] if ip and not trusted else [])
        worst = 0
        for k in keys:
            att = self._attempts[k]
            while att and now - att[0] > WINDOW:
                att.popleft()
            if not dry_run:
                att.append(now)
            worst = max(worst, len(att))
        if worst > cap:
            return deny("flood", f"{worst} write attempts in 60 s from this source (limit {cap}): "
                                 "possible automated attack")

        lim = self.policy["limits"].get(register)
        # 2. allowlist
        if lim is None:
            return deny("allowlist", "register not on the write allowlist")
        reason = lim.get("reason", "")
        # 3. range
        if not lim["min"] <= new <= lim["max"]:
            return deny("range", f"outside safe range {lim['min']:g}-{lim['max']:g} {u} ({reason})")
        # 4. step
        step = lim.get("max_step")
        if step is not None and old is not None and abs(new - old) > step + 1e-9:
            return deny("step", f"change of {abs(new - old):g} {u} exceeds max {step:g} per command ({reason})")
        # 5. ramp
        per_min = lim.get("max_change_per_min")
        base = self._baseline(register, old, now)
        if per_min is not None and base is not None and abs(new - base) > per_min + 1e-9:
            return deny("ramp", f"net change of {abs(new - base):g} {u} within 60 s would exceed "
                                f"{per_min:g} {u}/min (slow-ramp protection; was {base:g} a minute ago)")
        # 6. interlocks
        for il in self.policy.get("interlocks", []):
            if il["register"] == register and new == il["value"]:
                v = state.get(il["when"])
                if v is not None and ((il["op"] == ">" and v > il["threshold"]) or
                                      (il["op"] == "<" and v < il["threshold"])):
                    return deny("interlock", f"interlock: {il['message']}")
        # 6b. critical commands need an operator permit issued out-of-band (dashboard + PIN).
        #     A Modbus packet can claim to be the HMI; it can't create a permit.
        need = lim.get("permit_values") or []
        permit_note = ""
        if new in need and new != old and not dry_run:   # a proposal's approval issues the permit
            key = (register, float(new))
            pm = self.permits.get(key)
            if not pm or pm["expires"] < now:
                return deny("permit", f"{register} = {new:g} is a critical command and needs an operator permit "
                                      "(issued on the Aegis dashboard with the engineer PIN)")
            self.permits.pop(key, None)            # single use
            permit_note = f"; used single-use permit issued by {pm['by']}"
        # 7. digital twin
        pred = self.policy.get("prediction") or {}
        forecast, note = None, "within safety envelope"
        if self.twin is not None and pred.get("enabled", True) and pred:
            override = dict(together or {})
            override[register] = new
            v = self._twin_eval(state, override, pred)
            forecast = v.forecast
            if not v.allowed:
                d = deny("predict", v.reason)
                d.forecast = forecast
                return d
            note = f"within safety envelope; {v.reason}"
        note += permit_note
        # 8. learned-normal band: allowed, but unusual values are flagged to the operator
        nb = lim.get("normal")
        if nb and not nb[0] <= new <= nb[1]:
            return Decision(True, source, register, old, new,
                            f"UNUSUAL: outside the learned normal band {nb[0]:g}-{nb[1]:g} {u} (allowed; operator alerted)",
                            peer, "unusual", now, u, fc, [], False, forecast)
        return Decision(True, source, register, old, new, note, peer, "ok", now, u, fc, [], False, forecast)

    def _twin_eval(self, state, override: dict, pred: dict):
        # evaluate the combined change: apply all but one as part of the "state"
        *rest, last = list(override.items())
        st = dict(state)
        st.update(dict(rest))
        return self.twin.evaluate(st, last[0], last[1], pred.get("horizon_min", 360), pred.get("limits"))

    # ------------------------------------------------------------------ bookkeeping
    def _commit(self, d: Decision):
        if d.allowed and d.old is not None and d.new != d.old:
            self._changes[d.register].append((d.t, d.old, d.new))

    def _record(self, d: Decision):
        self.log.appendleft(d)
        self.counts["blocked" if not d.allowed else ("would_block" if d.would_block else "allowed")] += 1
        if self.audit:
            self.audit.append("decision", d.as_dict())
        if d.check == "unusual" and self.alerter:
            self.alerter.raise_alert(f"unusual:{d.source}:{d.register}", "warning",
                                     f"{d.source} set {d.register} to {d.new:g} {d.unit}: {d.reason}.")
        if (not d.allowed or d.would_block) and self.alerter:
            sev = "warning" if d.source == "Operator HMI" or d.would_block else "critical"
            verb = "Would have blocked (monitor mode)" if d.would_block else "Blocked"
            who = d.peer.rsplit(":", 1)[0] if d.peer and ":" in d.peer and not d.peer.startswith("127.0.0.1:") else d.source
            self.alerter.raise_alert(
                f"blocked:{who}:{d.register}:{d.check}", sev,
                f"{verb} {d.source} from setting {d.register} to {d.new:g} {d.unit}. {d.reason}.")

    async def _state(self) -> dict:
        s = self.read_state()
        return await s if inspect.isawaitable(s) else s

    async def dry_run(self, register: str, value: float, source: str) -> Decision:
        """Pre-check a proposed change without applying or counting it."""
        return self.check(register, value, await self._state(), source, "proposal", dry_run=True)

    async def forecast(self, override: dict | None = None, horizon_min: float | None = None) -> list | None:
        st = await self._state()
        if self.twin is None or not self.twin.available(st):
            return None
        h = horizon_min or (self.policy.get("prediction") or {}).get("horizon_min", 360)
        return self.twin.forecast(st, override, h)

    def latency(self) -> dict:
        c, t = list(self.lat_check), list(self.lat_total)
        r = lambda x: None if x is None else round(x, 3)
        return {"n": len(c), "check_p50_ms": r(_pct(c, .5)), "check_p99_ms": r(_pct(c, .99)),
                "total_p50_ms": r(_pct(t, .5)), "total_p99_ms": r(_pct(t, .99)),
                "check_mean_ms": r(statistics.fmean(c)) if c else None}

    # ------------------------------------------------------------------ admin
    def set_policy(self, policy: dict, by: str = "engineer"):
        new = validate_policy(policy, self.tags)
        old = self.policy
        self.policy = new
        save_policy(new, self.policy_path) if self.policy_path else None
        if self.audit:
            self.audit.append("policy_change", {"by": by, "old": old, "new": new})

    def issue_permit(self, register: str, value: float, minutes: float = 10, by: str = "operator") -> dict:
        lim = self.policy["limits"].get(register) or {}
        if float(value) not in [float(v) for v in lim.get("permit_values") or []]:
            raise ValueError(f"{register} = {value:g} does not need a permit")
        pm = {"register": register, "value": float(value), "expires": self.clock() + minutes * 60, "by": by}
        self.permits[(register, float(value))] = pm
        if self.audit:
            self.audit.append("permit_issued", pm)
        return pm

    def set_mode(self, mode: str, by: str = "engineer"):
        if mode not in MODES:
            raise ValueError(f"mode must be one of {MODES}")
        self.mode = mode
        if self.audit:
            self.audit.append("guard_mode", {"mode": mode, "by": by})
        if mode != "enforce" and self.alerter:
            msg = ("Safety guard was DISABLED by {by}. Commands now reach the PLC unchecked." if mode == "off" else
                   "Safety guard switched to MONITOR mode by {by}: unsafe commands are logged but NOT blocked.")
            self.alerter.raise_alert("guard_mode", "critical", msg.format(by=by))

    def set_enabled(self, enabled: bool, by: str = "engineer"):
        self.set_mode("enforce" if enabled else "off", by)

    # ------------------------------------------------------------------ proxy
    async def _targets(self, req: modbus.Request) -> list[tuple[str, float, int]]:
        """(name, engineering value, raw) for every register/coil this write would change."""
        table = req.table
        if req.fc == modbus.MASK_WRITE:   # resulting value depends on the current one
            cur = (await self.upstream.read_holding(req.address, 1))[0]
            vals = [modbus.mask_result(cur, req.and_mask, req.or_mask)]
        else:
            vals = req.values
        out = []
        for i, raw in enumerate(vals):
            tag = self.tags.by_addr.get((table, req.address + i))
            name = tag.name if tag else f"{table} {req.address + i}"
            out.append((name, tag.from_raw(raw) if tag else raw, raw))
        return out

    def _apply_mode(self, d: Decision) -> Decision:
        if self.mode == "off":
            d.allowed, d.reason, d.check, d.techniques = True, "GUARD OFF: passed through unchecked", "disabled", []
        elif self.mode == "monitor" and not d.allowed:
            d.allowed, d.would_block = True, True
            d.reason = f"MONITOR MODE (not enforced): would block: {d.reason}"
        return d

    async def handle(self, req: modbus.Request, peer) -> bytes:
        t0 = time.perf_counter()
        peer_s = f"{peer[0]}:{peer[1]}" if peer else "?"
        source = SOURCES.get(req.unit, f"Unknown device (unit {req.unit})")
        checked = False
        if not req.known:
            name = modbus.FC_NAMES.get(req.fc, f"function code {req.fc}")
            tech = [FC_ATTACK[req.fc]] if req.fc in FC_ATTACK else list(ATTACK["function"])
            d = Decision(False, source, f"FC {req.fc}", None, req.fc,
                         f"function code {req.fc} ({name}) is not allowed through the guard",
                         peer_s, "function", self.clock(), "", req.fc, tech)
            self._record(self._apply_mode(d))
            self.lat_check.append((time.perf_counter() - t0) * 1000)
            if not d.allowed:
                raise modbus.ModbusError(modbus.ILLEGAL_FUNCTION)
            checked = True
        elif req.is_write:
            try:
                targets = await self._targets(req)
                state = await self._state()
            except (ConnectionError, OSError):
                raise modbus.ModbusError(modbus.GATEWAY_TARGET_FAILED)
            together = {n: v for n, v, _ in targets}
            decisions = []
            for name, value, _ in targets:
                others = {k: v for k, v in together.items() if k != name}
                decisions.append(self._apply_mode(
                    self.check(name, value, state, source, peer_s, together=others, fc=req.fc)))
            ok = all(d.allowed for d in decisions)
            for d in decisions:
                if not d.allowed or ok:
                    self._record(d)
                if ok:
                    self._commit(d)
            self.lat_check.append((time.perf_counter() - t0) * 1000)
            checked = True
            if not ok:
                raise modbus.ModbusError(modbus.ILLEGAL_VALUE)   # whole write rejected
        try:
            out = await self.upstream.call_pdu(req.raw, unit=None)
        except modbus.ModbusError:
            raise
        except (ConnectionError, OSError):
            if self.alerter:
                self.alerter.raise_alert("plc_unreachable", "critical",
                                         "Aegis cannot reach the PLC: commands are failing safe (rejected).")
            raise modbus.ModbusError(modbus.GATEWAY_TARGET_FAILED)
        finally:
            if checked:
                self.lat_total.append((time.perf_counter() - t0) * 1000)
        return out


async def read_plc_state(client: modbus.Client, tags: Tags) -> dict:
    """Read every configured tag from a real PLC (used in gateway mode)."""
    out = {}
    readers = {"holding": client.read_holding, "input": client.read_input,
               "coil": client.read_coils, "discrete": client.read_discrete}
    for table, reader in readers.items():
        group = tags.table(table)
        if not group:
            continue
        start, count = Tags.span(group)
        regs = await reader(start, count)
        for t in group.values():
            out[t.name] = t.from_raw(regs[t.address - start])
    return out
