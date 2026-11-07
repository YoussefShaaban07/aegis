"""Aegis guard: a Modbus TCP proxy in front of the PLC.

Every write, whether it comes from the operator HMI, the AI copilot, or an
attacker, is decoded and checked against a deterministic safety envelope
(config/policy.json) before it reaches the PLC. Reads pass through.

Checks, in order:
  1. flood        too many write attempts from one source in 60 s
  2. allowlist    register must be listed in the policy
  3. range        absolute min/max
  4. step         largest change in a single command
  5. ramp         largest net change within any 60 s window (stops attackers
                  who sneak up on a value with many small, individually-legal steps)
  6. interlocks   process conditions (e.g. don't stop distribution when tank is nearly full)

No LLM anywhere in here: a hijacked AI cannot talk its way past it.
"""
from __future__ import annotations

import inspect
import time
from collections import defaultdict, deque
from dataclasses import dataclass, field

from . import modbus
from .config import Tags, load_policy, save_policy, validate_policy

SOURCES = {1: "Operator HMI", 2: "AI copilot"}   # Modbus unit-id labels (spoofable; log only)
WINDOW = 60.0


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

    def as_dict(self):
        return dict(self.__dict__)


class Guard:
    def __init__(self, upstream: modbus.Client | None, read_state, tags: Tags | None = None,
                 policy: dict | None = None, enabled: bool = True, audit=None, alerter=None,
                 clock=time.time, policy_path=None):
        """upstream: client to the real PLC. read_state(): current values (sync or async)."""
        self.upstream = upstream
        self.read_state = read_state
        self.tags = tags or Tags.load()
        self.policy_path = policy_path
        self.policy = validate_policy(policy, self.tags) if policy else load_policy(self.tags)
        self.enabled = enabled
        self.audit = audit
        self.alerter = alerter
        self.clock = clock
        self.log: deque[Decision] = deque(maxlen=200)
        self._changes: dict[str, deque] = defaultdict(deque)   # register -> (t, before, after)
        self._attempts: dict[str, deque] = defaultdict(deque)  # source -> attempt times

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
              dry_run: bool = False) -> Decision:
        now = self.clock()
        old = state.get(register)
        u = self._unit(register)

        def deny(check, reason):
            return Decision(False, source, register, old, new, reason, peer, check, now, u)

        # 1. flood (counted per source, allowed and blocked attempts alike)
        att = self._attempts[source]
        while att and now - att[0] > WINDOW:
            att.popleft()
        if not dry_run:
            att.append(now)
        cap = self.policy["max_writes_per_min_per_source"]
        if len(att) > cap:
            return deny("flood", f"{len(att)} write attempts in 60 s from this source (limit {cap}): "
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
        return Decision(True, source, register, old, new, "within safety envelope", peer, "ok", now, u)

    # ------------------------------------------------------------------ bookkeeping
    def _commit(self, d: Decision):
        if d.allowed and d.old is not None and d.new != d.old:
            self._changes[d.register].append((d.t, d.old, d.new))

    def _record(self, d: Decision):
        self.log.appendleft(d)
        if self.audit:
            self.audit.append("decision", d.as_dict())
        if not d.allowed and self.alerter:
            sev = "warning" if d.source == "Operator HMI" else "critical"
            self.alerter.raise_alert(
                f"blocked:{d.source}:{d.register}:{d.check}", sev,
                f"Blocked {d.source} from setting {d.register} to {d.new:g} {d.unit}. {d.reason}.")

    async def _state(self) -> dict:
        s = self.read_state()
        return await s if inspect.isawaitable(s) else s

    async def dry_run(self, register: str, value: float, source: str) -> Decision:
        """Pre-check a proposed change without applying or counting it."""
        return self.check(register, value, await self._state(), source, "proposal", dry_run=True)

    # ------------------------------------------------------------------ admin
    def set_policy(self, policy: dict, by: str = "engineer"):
        new = validate_policy(policy, self.tags)
        old = self.policy
        self.policy = new
        save_policy(new, self.policy_path) if self.policy_path else None
        if self.audit:
            self.audit.append("policy_change", {"by": by, "old": old, "new": new})

    def set_enabled(self, enabled: bool, by: str = "engineer"):
        self.enabled = enabled
        if self.audit:
            self.audit.append("guard_toggle", {"enabled": enabled, "by": by})
        if not enabled and self.alerter:
            self.alerter.raise_alert("guard_disabled", "critical",
                                     f"Safety guard was DISABLED by {by}. Commands now reach the PLC unchecked.")

    # ------------------------------------------------------------------ proxy
    async def handle(self, req: modbus.Request, peer) -> bytes:
        peer_s = f"{peer[0]}:{peer[1]}" if peer else "?"
        source = SOURCES.get(req.unit, f"Unknown device (unit {req.unit})")
        if req.is_write:
            state = await self._state()
            decisions = []
            for i, raw in enumerate(req.values):
                tag = self.tags.by_address.get(req.address + i)
                name = tag.name if tag else f"register {req.address + i}"
                value = tag.from_raw(raw) if tag else raw
                d = self.check(name, value, state, source, peer_s)
                if not self.enabled:
                    d.allowed, d.reason, d.check = True, "GUARD DISABLED: passed through unchecked", "disabled"
                decisions.append(d)
            ok = all(d.allowed for d in decisions)
            for d in decisions:
                if not d.allowed or ok:
                    self._record(d)
                if ok:
                    self._commit(d)
            if not ok:
                raise modbus.ModbusError(modbus.ILLEGAL_VALUE)   # whole write rejected
        try:
            if req.fc == modbus.READ_HOLDING:
                return modbus.response_pdu(req, await self.upstream.read_holding(req.address, req.count))
            if req.fc == modbus.READ_INPUT:
                return modbus.response_pdu(req, await self.upstream.read_input(req.address, req.count))
            if req.fc == modbus.WRITE_SINGLE:
                await self.upstream.write(req.address, req.values[0])
            else:
                await self.upstream.write_many(req.address, req.values)
            return modbus.response_pdu(req)
        except modbus.ModbusError:
            raise
        except Exception:
            raise modbus.ModbusError(modbus.DEVICE_FAILURE)


async def read_plc_state(client: modbus.Client, tags: Tags) -> dict:
    """Read every configured tag from a real PLC (used in gateway mode)."""
    out = {}
    for table, reader in ((tags.holding, client.read_holding), (tags.input, client.read_input)):
        if not table:
            continue
        start, count = tags.span(table)
        regs = await reader(start, count)
        for t in table.values():
            out[t.name] = t.from_raw(regs[t.address - start])
    return out
