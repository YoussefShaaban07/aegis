"""Simulated small-town water treatment plant + its PLC (Modbus TCP).

Process: intake pump -> chemical dosing (chlorine for disinfection, sodium
hydroxide / lye for pH) -> clearwell tank -> distribution pump -> town.

Safety reference values (EPA): pH secondary standard 6.5-8.5;
chlorine maximum residual disinfectant level 4.0 mg/L.
"""
from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import dataclass, field

from . import modbus

# ---- register map (what an HMI / attacker sees on the wire) ----
HOLDING = {  # writable setpoints / commands
    "intake_pump": 0,          # 0/1
    "distribution_pump": 1,    # 0/1
    "chlorine_dose": 2,        # mg/L x100
    "naoh_dose": 3,            # ppm
    "distribution_rate": 4,    # gallons per minute
}
INPUT = {  # read-only sensors
    "tank_level": 0,           # % x10
    "chlorine_residual": 1,    # mg/L x100
    "ph": 2,                   # x100
    "flow_out": 3,             # gpm
    "alarms": 4,               # bitfield
}
SCALE = {"chlorine_dose": 100, "chlorine_residual": 100, "ph": 100, "tank_level": 10}
UNITS = {"chlorine_dose": "mg/L", "naoh_dose": "ppm", "distribution_rate": "gpm",
         "tank_level": "%", "chlorine_residual": "mg/L", "ph": "pH", "flow_out": "gpm"}
ALARMS = ["pH HIGH", "pH LOW", "CHLORINE HIGH", "CHLORINE LOW", "TANK HIGH", "TANK LOW"]

NORMAL = {"intake_pump": 1, "distribution_pump": 1, "chlorine_dose": 1.5,
          "naoh_dose": 100, "distribution_rate": 500}


def to_raw(name: str, value: float) -> int:
    return int(round(value * SCALE.get(name, 1)))


def from_raw(name: str, raw: int) -> float:
    s = SCALE.get(name, 1)
    return raw / s if s != 1 else raw


@dataclass
class Plant:
    speed: float = 30.0                 # simulated seconds per real second
    capacity_gal: float = 100_000
    intake_gpm: float = 520
    hr: list[int] = field(default_factory=lambda: [0] * 8)
    tank_level: float = 60.0            # %
    chlorine: float = 1.3               # mg/L residual
    ph: float = 7.0
    flow_out: float = 0.0
    history: deque = field(default_factory=lambda: deque(maxlen=600))
    _last: float = field(default_factory=time.monotonic)

    def __post_init__(self):
        for k, v in NORMAL.items():
            self.hr[HOLDING[k]] = to_raw(k, v)

    # ---- setpoints ----
    def setpoint(self, name: str) -> float:
        return from_raw(name, self.hr[HOLDING[name]])

    # ---- physics ----
    def step(self, real_dt: float | None = None):
        now = time.monotonic()
        real_dt = (now - self._last) if real_dt is None else real_dt
        self._last = now
        dt = real_dt * self.speed  # simulated seconds

        intake = self.intake_gpm if self.setpoint("intake_pump") else 0.0
        out = self.setpoint("distribution_rate") if self.setpoint("distribution_pump") else 0.0
        if self.tank_level <= 2:
            out = 0.0
        self.flow_out = out
        self.tank_level += (intake - out) / 60 * dt / self.capacity_gal * 100
        self.tank_level = min(100.0, max(0.0, self.tank_level))

        # chemistry: first-order lag toward the dosed target
        cl_target = 0.85 * self.setpoint("chlorine_dose") if intake else self.chlorine * 0.98
        ph_target = 7.0 + 1.6 * math.log10(1 + self.setpoint("naoh_dose") / 100) - 0.48
        self.chlorine += (cl_target - self.chlorine) * (1 - math.exp(-dt / 600))
        self.ph += (ph_target - self.ph) * (1 - math.exp(-dt / 450))

        self.history.append({"t": time.time(), **self.snapshot(values_only=True)})

    def alarms(self) -> list[str]:
        out = []
        if self.ph > 8.5: out.append("pH HIGH")
        if self.ph < 6.5: out.append("pH LOW")
        if self.chlorine > 4.0: out.append("CHLORINE HIGH")
        if self.chlorine < 0.2: out.append("CHLORINE LOW")
        if self.tank_level > 95: out.append("TANK HIGH")
        if self.tank_level < 10: out.append("TANK LOW")
        return out

    def input_registers(self) -> list[int]:
        bits = sum(1 << ALARMS.index(a) for a in self.alarms())
        return [to_raw("tank_level", self.tank_level), to_raw("chlorine_residual", self.chlorine),
                to_raw("ph", self.ph), int(self.flow_out), bits, 0, 0, 0]

    def snapshot(self, values_only: bool = False) -> dict:
        d = {"tank_level": round(self.tank_level, 1), "chlorine_residual": round(self.chlorine, 2),
             "ph": round(self.ph, 2), "flow_out": round(self.flow_out)}
        d.update({k: self.setpoint(k) for k in HOLDING})
        if values_only:
            return d
        return {**d, "alarms": self.alarms()}

    # ---- PLC: Modbus handler ----
    async def handle(self, req: modbus.Request, peer) -> bytes:
        if req.fc == modbus.READ_HOLDING:
            regs = self.hr
        elif req.fc == modbus.READ_INPUT:
            regs = self.input_registers()
        else:
            regs = self.hr
        if req.address + req.count > len(regs):
            raise modbus.ModbusError(modbus.ILLEGAL_ADDRESS)
        if req.is_write:
            for i, v in enumerate(req.values):
                self.hr[req.address + i] = v
            return modbus.response_pdu(req)
        return modbus.response_pdu(req, regs[req.address:req.address + req.count])


REG_NAME = {v: k for k, v in HOLDING.items()}
