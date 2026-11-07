"""Simulated small-town water treatment plant + its PLC (Modbus TCP).

Process: raw water -> intake pump -> chemical dosing (chlorine for
disinfection, sodium hydroxide / lye for pH) -> clearwell tank -> distribution
pump -> town. Chemistry and mixing come from aegis/process.py.

The simulator deliberately differs from the guard's twin, the way a real plant
differs from any model of it: slightly different "true" parameters, a drifting
chlorine demand, and sensor noise. The twin's live accuracy score measures that gap.

Weather scenarios change the raw water:
  normal  pH 6.9, alkalinity 77 mg/L, turbidity 1 NTU
  storm   runoff: turbidity 15 NTU (chlorine demand jumps), alkalinity 55, pH 6.8
  bloom   algae consume CO2 in the reservoir: raw pH 8.3 (lye dose must drop)

Safety reference values (EPA): pH secondary standard 6.5-8.5; chlorine maximum
residual disinfectant level 4.0 mg/L; a detectable residual (we use 0.2 mg/L) is required.
"""
from __future__ import annotations

import random
import time
from collections import deque
from dataclasses import dataclass, field

from . import modbus
from .config import Tags, load_process
from .process import HiFiModel, ProcessModel, ProcessState, Raw, hocl_fraction

TAGS = Tags.load()
HOLDING = {n: t.address for n, t in TAGS.holding.items()}   # writable tags (name -> address)
UNITS = {n: t.unit for n, t in TAGS.all.items()}
ALARMS = ["pH HIGH", "pH LOW", "CHLORINE HIGH", "CHLORINE LOW", "TANK HIGH", "TANK LOW"]

NORMAL = {"intake_pump": 1, "distribution_pump": 1, "chlorine_dose": 1.5,
          "naoh_dose": 100, "distribution_rate": 500}
SCENARIOS = {
    "normal": Raw(6.9, 77.0, 1.0),
    "storm": Raw(6.8, 55.0, 15.0),
    "bloom": Raw(8.3, 77.0, 2.0),
}


def to_raw(name: str, value: float) -> int:
    return TAGS.all[name].to_raw(value)


def from_raw(name: str, raw: int) -> float:
    return TAGS.all[name].from_raw(raw)


def _true_params(fidelity: str = "standard") -> dict:
    p = load_process()
    # the real plant is never exactly the model
    p.update(naoh_feed_strength=p["naoh_feed_strength"] * 1.03,
             chlorine_decay_per_hr=p["chlorine_decay_per_hr"] * 1.2)
    if fidelity == "high":          # structure the twin has wrong, not just parameters
        p.update(baffling_cells=p.get("baffling_cells", 1) + 1, kla_per_hr=0.25)
    return p


@dataclass
class Plant:
    speed: float = 60.0                 # simulated seconds per real second
    seed: int | None = 7
    noise: bool = True
    coils: list[int] = field(default_factory=lambda: [0] * 16)
    hr: list[int] = field(default_factory=lambda: [0] * 16)
    history: deque = field(default_factory=lambda: deque(maxlen=2400))
    scenario: str = "normal"
    sim_time: float = 0.0
    fidelity: str = "standard"          # "high": physics the twin doesn't model (see process.HiFiModel)
    _last: float = field(default_factory=time.monotonic)

    def __post_init__(self):
        self.model = HiFiModel(_true_params("high")) if self.fidelity == "high" else ProcessModel(_true_params())
        self._lag = None                # analyzer readings (high fidelity: first-order lag)
        self.rng = random.Random(self.seed)
        self.raw = Raw(**SCENARIOS["normal"].__dict__)
        self._raw_target = Raw(**self.raw.__dict__)
        self.demand_drift = 0.0
        self.compromise: dict | None = None
        self.reset()

    # ---- setpoints ----
    def _cell(self, name: str):
        t = TAGS.holding[name]
        return (self.coils if t.table == "coil" else self.hr), t.address

    def setpoint(self, name: str) -> float:
        regs, a = self._cell(name)
        return from_raw(name, regs[a])

    def set(self, name: str, value: float):
        regs, a = self._cell(name)
        regs[a] = to_raw(name, value)

    def setpoints(self) -> dict:
        """What the PLC's registers say (and report over Modbus)."""
        return {k: self.setpoint(k) for k in HOLDING}

    def physical_setpoints(self) -> dict:
        """What the pumps actually do. Differs only when the PLC is compromised."""
        sp = self.setpoints()
        if self.compromise:
            sp.update(self.compromise.get("actual", {}))
        return sp

    def compromise_plc(self, actual: dict, freeze_sensors: bool = False):
        """Stuxnet-style demo: the PLC doses `actual` while its registers keep reporting
        the old setpoints; optionally it also replays frozen 'normal' sensor values."""
        s = self.sensors()
        self.compromise = {"actual": dict(actual), "freeze": freeze_sensors,
                           "frozen": {"ph": s["ph"], "chlorine_residual": s["chlorine_residual"]}}

    def reset(self):
        self.compromise = None
        for k, v in NORMAL.items():
            self.set(k, v)
        self.set_scenario("normal", immediate=True)
        self.state: ProcessState = self.model.steady(self.raw, self.setpoints())
        self.demand_drift = 0.0
        self.history.clear()

    def set_scenario(self, name: str, immediate: bool = False):
        self.scenario = name
        self._raw_target = Raw(**SCENARIOS[name].__dict__)
        if self.fidelity == "high":
            self._raw_target.temp_c = 15.0           # colder water: different chemistry constants
        if immediate:
            self.raw = Raw(**self._raw_target.__dict__)

    # ---- convenience views (sensor values) ----
    @property
    def ph(self) -> float:
        return self.model.ph(self.state)

    @property
    def chlorine(self) -> float:
        return self.state.chlorine

    @property
    def tank_level(self) -> float:
        return self.state.tank_level

    @property
    def flow_out(self) -> float:
        return self.state.flow_out

    # ---- physics ----
    def step(self, real_dt: float | None = None):
        now = time.monotonic()
        real_dt = (now - self._last) if real_dt is None else real_dt
        self._last = now
        dt = real_dt * self.speed
        self.sim_time += dt
        # raw water drifts toward the scenario over ~20 simulated minutes
        k = 1 - pow(2.718281828, -dt / 1200)
        for f in ("ph", "alkalinity", "turbidity", "temp_c"):
            cur, tgt = getattr(self.raw, f), getattr(self._raw_target, f)
            setattr(self.raw, f, cur + (tgt - cur) * k)
        if self.noise:   # chlorine demand wanders (organic load changes)
            self.demand_drift += self.rng.gauss(0, 0.004) * (dt / 60) ** 0.5
            self.demand_drift = max(-0.15, min(0.15, self.demand_drift * 0.999))
        demand = self.model.demand(self.raw) + self.demand_drift
        sub = max(1, int(dt // 30))
        for _ in range(sub):
            self.model.step(self.state, self.raw, self.physical_setpoints(), dt / sub, demand)
        if self.fidelity == "high":     # pH analyzer ~2 min lag, chlorine analyzer ~3 min
            if self._lag is None:
                self._lag = [self.ph, self.chlorine]
            self._lag[0] += (self.ph - self._lag[0]) * (1 - pow(2.718281828, -dt / 120))
            self._lag[1] += (self.chlorine - self._lag[1]) * (1 - pow(2.718281828, -dt / 180))
        self.history.append({"t": time.time(), "sim_t": self.sim_time, **self.snapshot(values_only=True)})

    def _noise(self, sd: float) -> float:
        return self.rng.gauss(0, sd) if self.noise else 0.0

    def alarms(self) -> list[str]:
        out = []
        if self.ph > 8.5: out.append("pH HIGH")
        if self.ph < 6.5: out.append("pH LOW")
        if self.chlorine > 4.0: out.append("CHLORINE HIGH")
        if self.chlorine < 0.2: out.append("CHLORINE LOW")
        if self.tank_level > 95: out.append("TANK HIGH")
        if self.tank_level < 10: out.append("TANK LOW")
        return out

    def sensors(self) -> dict:
        """What the instruments report through the PLC (with a little noise)."""
        fz = self.compromise["frozen"] if (self.compromise and self.compromise.get("freeze")) else None
        lag = self._lag if (self.fidelity == "high" and self._lag) else (self.ph, self.chlorine)
        ph = fz["ph"] if fz else lag[0]
        cl = fz["chlorine_residual"] if fz else lag[1]
        return {"tank_level": round(self.tank_level + self._noise(0.05), 1),
                "chlorine_residual": round(max(0.0, cl + self._noise(0.01)), 2),
                "ph": round(ph + self._noise(0.01), 2),
                "flow_out": round(self.flow_out),
                "raw_ph": round(self.raw.ph + self._noise(0.01), 2),
                "raw_alkalinity": round(self.raw.alkalinity),
                "raw_turbidity": round(self.raw.turbidity, 1),
                "water_temp": round(self.raw.temp_c, 1)}

    def input_registers(self) -> list[int]:
        s = self.sensors()
        regs = [0] * 16
        for n, t in TAGS.table("input").items():
            if n == "alarms":
                regs[t.address] = sum(1 << ALARMS.index(a) for a in self.reported_alarms())
            elif n in s:
                regs[t.address] = max(0, min(65535, t.to_raw(s[n])))
        return regs

    def snapshot(self, values_only: bool = False) -> dict:
        d = self.sensors()
        d["hocl_pct"] = round(100 * hocl_fraction(d["ph"]), 1)
        d.update(self.setpoints())
        if values_only:
            return d
        return {**d, "alarms": self.reported_alarms(), "scenario": self.scenario}

    def reported_alarms(self) -> list[str]:
        """Alarms as the PLC reports them (a compromised PLC computes them from its fake readings)."""
        if not (self.compromise and self.compromise.get("freeze")):
            return self.alarms()
        fz = self.compromise["frozen"]
        out = []
        if fz["ph"] > 8.5: out.append("pH HIGH")
        if fz["ph"] < 6.5: out.append("pH LOW")
        return out

    def truth(self) -> dict:
        """Simulator ground truth (for the demo only; a real operator can't see this)."""
        return {"ph": round(self.ph, 2), "chlorine_residual": round(self.chlorine, 2),
                "naoh_dose_actual": self.physical_setpoints()["naoh_dose"],
                "chlorine_dose_actual": self.physical_setpoints()["chlorine_dose"],
                "compromised": bool(self.compromise), "sensors_frozen": bool(self.compromise and self.compromise.get("freeze"))}

    # ---- PLC: Modbus handler ----
    async def handle(self, req: modbus.Request, peer) -> bytes:
        fc = req.fc
        if not req.known:
            raise modbus.ModbusError(modbus.ILLEGAL_FUNCTION)
        if fc in (modbus.READ_COILS, modbus.READ_DISCRETE, modbus.WRITE_COIL, modbus.WRITE_COILS):
            regs = self.coils if fc != modbus.READ_DISCRETE else [1 if a in self.alarms() else 0 for a in ALARMS] + [0] * 10
        elif fc == modbus.READ_INPUT:
            regs = self.input_registers()
        else:
            regs = self.hr
        if fc == modbus.READ_WRITE:
            if req.read_address + req.read_count > len(regs) or req.address + req.count > len(regs):
                raise modbus.ModbusError(modbus.ILLEGAL_ADDRESS)
            for i, v in enumerate(req.values):           # spec: write happens before read
                regs[req.address + i] = v
            return modbus.response_pdu(req, regs[req.read_address:req.read_address + req.read_count])
        if req.address + req.count > len(regs):
            raise modbus.ModbusError(modbus.ILLEGAL_ADDRESS)
        if fc == modbus.MASK_WRITE:
            regs[req.address] = modbus.mask_result(regs[req.address], req.and_mask, req.or_mask)
            return modbus.response_pdu(req)
        if req.is_write:
            for i, v in enumerate(req.values):
                regs[req.address + i] = v
            return modbus.response_pdu(req)
        return modbus.response_pdu(req, regs[req.address:req.address + req.count])
