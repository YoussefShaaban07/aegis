"""Aegis guard: a Modbus TCP proxy in front of the PLC.

Every write, whether it comes from the operator HMI, the AI copilot, or an
attacker, is decoded and checked against a deterministic safety envelope
before it reaches the PLC. Reads pass through. Nothing here uses an LLM:
a hijacked AI cannot talk its way past it.
"""
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

from . import modbus
from .plant import REG_NAME, UNITS, from_raw

# Who's who, by Modbus unit id (Modbus has no auth; this is only a label for the log).
SOURCES = {1: "Operator HMI", 2: "AI copilot"}


@dataclass
class Limit:
    min: float
    max: float
    max_step: float | None = None     # largest change allowed in one write
    reason: str = ""


# Engineering safety envelope (would be signed off by the utility's engineer).
POLICY: dict[str, Limit] = {
    "chlorine_dose": Limit(0.2, 4.0, 0.5, "EPA max residual disinfectant level is 4.0 mg/L"),
    "naoh_dose": Limit(0, 300, 50, "lye overdose raises pH above the EPA 6.5-8.5 range"),
    "distribution_rate": Limit(100, 900, 200, "pump and pipe design limits"),
    "intake_pump": Limit(0, 1),
    "distribution_pump": Limit(0, 1),
}


@dataclass
class Decision:
    allowed: bool
    source: str
    register: str
    old: float | None
    new: float
    reason: str
    peer: str
    t: float = field(default_factory=time.time)

    def as_dict(self):
        return {**self.__dict__, "unit": UNITS.get(self.register, "")}


class Guard:
    def __init__(self, upstream: modbus.Client, read_state, enabled: bool = True):
        """upstream: client to the real PLC. read_state(): current plant snapshot."""
        self.upstream = upstream
        self.read_state = read_state
        self.enabled = enabled
        self.log: deque[Decision] = deque(maxlen=200)
        self.listeners = []

    def check(self, register: str, new: float, state: dict, source: str, peer: str) -> Decision:
        old = state.get(register)
        lim = POLICY.get(register)
        if lim is None:
            return Decision(False, source, register, old, new, "register not on the write allowlist", peer)
        if not lim.min <= new <= lim.max:
            u = UNITS.get(register, "")
            return Decision(False, source, register, old, new,
                            f"outside safe range {lim.min:g}-{lim.max:g} {u} ({lim.reason})", peer)
        if lim.max_step is not None and old is not None and abs(new - old) > lim.max_step:
            return Decision(False, source, register, old, new,
                            f"change of {abs(new - old):g} exceeds max step {lim.max_step:g} per command "
                            f"({lim.reason})", peer)
        # interlocks
        if register == "distribution_pump" and new == 0 and state.get("tank_level", 0) > 90:
            return Decision(False, source, register, old, new,
                            "interlock: can't stop distribution while clearwell is above 90%", peer)
        if register == "intake_pump" and new == 0 and state.get("tank_level", 100) < 15:
            return Decision(False, source, register, old, new,
                            "interlock: can't stop intake while clearwell is below 15%", peer)
        return Decision(True, source, register, old, new, "within safety envelope", peer)

    def _record(self, d: Decision):
        self.log.appendleft(d)
        for fn in self.listeners:
            fn(d)

    async def handle(self, req: modbus.Request, peer) -> bytes:
        peer_s = f"{peer[0]}:{peer[1]}" if peer else "?"
        source = SOURCES.get(req.unit, f"Unknown device (unit {req.unit})")
        if req.is_write:
            state = self.read_state()
            decisions = []
            for i, raw in enumerate(req.values):
                name = REG_NAME.get(req.address + i, f"register {req.address + i}")
                value = from_raw(name, raw) if name in POLICY else raw
                d = self.check(name, value, state, source, peer_s)
                if not self.enabled:
                    d.allowed, d.reason = True, "GUARD DISABLED: passed through unchecked"
                decisions.append(d)
            for d in decisions:
                self._record(d)
            if not all(d.allowed for d in decisions):
                raise modbus.ModbusError(modbus.ILLEGAL_VALUE)  # whole write rejected
        # forward to the real PLC
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
