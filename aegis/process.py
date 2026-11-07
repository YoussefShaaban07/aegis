"""Water-treatment process model: carbonate chemistry + mixed clearwell.

Used twice:
  * by the simulator (aegis/plant.py), with "true" parameters, noise and weather;
  * by the guard's digital twin (aegis/twin.py), with nominal parameters and a
    state *estimated from the plant's own sensors*, to predict where a command
    will drive the water before the command is allowed.

Chemistry (standard textbook water chemistry, 25 C, closed system):
  Carbonic acid system  H2CO3* <-> HCO3- <-> CO3--   (pK1 6.35, pK2 10.33)
  Alkalinity (eq/L) = CT*(a1 + 2*a2) + [OH-] - [H+]
  Adding NaOH raises alkalinity 1 eq per mol and leaves total carbonate CT
  unchanged, so pH is found by solving the charge balance for [H+].
  This is why lye is dangerous: in weakly buffered water the pH response is a
  titration curve, flat and then suddenly steep. A fixed max-step limit can't
  know where on the curve the plant is today; the model can.

Disinfection: free chlorine is HOCl (strong disinfectant) <-> OCl- (weak),
pKa 7.54, so at pH 9 only about 3% of the chlorine is doing real work.

Clearwell: continuously stirred tank. Every constituent x follows
  dx/dt = (Q_in / V) * (x_in - x)  [- k*x for chlorine decay]
Simplifications (stated, not hidden): one well-mixed tank, no CO2 exchange with
air, no temperature effect, chlorine demand is instantaneous at the inlet.
"""
from __future__ import annotations

import math
from dataclasses import dataclass, field

PKA_HOCL = 7.54
CACO3_EQ_MG = 50_000.0     # mg/L as CaCO3 per eq/L
NAOH_MG_PER_EQ = 40_000.0  # mg/L NaOH per eq/L


# ------------------------------------------------------------------ chemistry
def _alphas(h: float, k1: float, k2: float) -> tuple[float, float]:
    d = h * h + k1 * h + k1 * k2
    return k1 * h / d, k1 * k2 / d          # a1 (HCO3-), a2 (CO3--)


def alk_from_ph(ph: float, ct: float, pk1=6.35, pk2=10.33, pkw=14.0) -> float:
    """Alkalinity (eq/L) of water with total carbonate ct (mol/L) at this pH."""
    h = 10 ** -ph
    a1, a2 = _alphas(h, 10 ** -pk1, 10 ** -pk2)
    return ct * (a1 + 2 * a2) + 10 ** -pkw / h - h


def ct_from_ph_alk(ph: float, alk: float, pk1=6.35, pk2=10.33, pkw=14.0) -> float:
    """Total carbonate (mol/L) from a measured pH and alkalinity (eq/L)."""
    h = 10 ** -ph
    a1, a2 = _alphas(h, 10 ** -pk1, 10 ** -pk2)
    return max(0.0, (alk - 10 ** -pkw / h + h) / (a1 + 2 * a2))


def ph_from_alk(alk: float, ct: float, pk1=6.35, pk2=10.33, pkw=14.0) -> float:
    """Solve the charge balance for pH (bisection; alkalinity rises monotonically with pH)."""
    lo, hi = 2.0, 13.5
    for _ in range(34):          # 11.5 / 2^34 < 1e-9 pH units
        mid = (lo + hi) / 2
        if alk_from_ph(mid, ct, pk1, pk2, pkw) > alk:
            hi = mid
        else:
            lo = mid
    return (lo + hi) / 2


def hocl_fraction(ph: float) -> float:
    """Share of free chlorine present as HOCl (the strong disinfectant)."""
    return 1.0 / (1.0 + 10 ** (ph - PKA_HOCL))


def mgl_caco3_to_eq(x: float) -> float:
    return x / CACO3_EQ_MG


# ------------------------------------------------------------------ model
NOMINAL = {
    "capacity_gal": 100_000, "intake_gpm": 520, "naoh_feed_strength": 0.1,
    "chlorine_decay_per_hr": 0.15, "chlorine_demand_base": 0.2, "chlorine_demand_per_ntu": 0.08,
    "pK1": 6.35, "pK2": 10.33, "pKw": 14.0,
}


@dataclass
class ProcessState:
    tank_level: float = 60.0      # %
    alk: float = 0.0              # clearwell alkalinity, eq/L
    ct: float = 0.0               # clearwell total carbonate, mol/L
    chlorine: float = 0.9         # free chlorine residual, mg/L
    flow_out: float = 0.0


@dataclass
class Raw:
    ph: float = 6.9
    alkalinity: float = 77.0      # mg/L as CaCO3
    turbidity: float = 1.0        # NTU


@dataclass
class ProcessModel:
    params: dict = field(default_factory=lambda: dict(NOMINAL))

    def pk(self):
        p = self.params
        return p["pK1"], p["pK2"], p["pKw"]

    def demand(self, raw: Raw) -> float:
        p = self.params
        return p["chlorine_demand_base"] + p["chlorine_demand_per_ntu"] * raw.turbidity

    def inlet(self, raw: Raw, sp: dict, demand: float | None = None) -> tuple[float, float, float]:
        """Composition of dosed water entering the clearwell: (alk eq/L, ct mol/L, chlorine mg/L)."""
        raw_alk = mgl_caco3_to_eq(raw.alkalinity)
        ct = ct_from_ph_alk(raw.ph, raw_alk, *self.pk())
        naoh_mg = sp["naoh_dose"] * self.params["naoh_feed_strength"]
        alk = raw_alk + naoh_mg / NAOH_MG_PER_EQ
        d = self.demand(raw) if demand is None else demand
        return alk, ct, max(0.0, sp["chlorine_dose"] - d)

    def ph(self, s: ProcessState) -> float:
        return ph_from_alk(s.alk, s.ct, *self.pk())

    def step(self, s: ProcessState, raw: Raw, sp: dict, dt: float, demand: float | None = None) -> ProcessState:
        """Advance dt simulated seconds (exact solution of the mixing ODE for constant inputs)."""
        p = self.params
        q_in = p["intake_gpm"] if sp.get("intake_pump") else 0.0
        q_out = sp["distribution_rate"] if sp.get("distribution_pump") else 0.0
        if s.tank_level <= 2:
            q_out = 0.0
        vol = max(s.tank_level, 1.0) / 100 * p["capacity_gal"]
        if q_in > 0:
            f = 1 - math.exp(-q_in / 60 * dt / vol)
            a_in, c_in, cl_in = self.inlet(raw, sp, demand)
            s.alk += (a_in - s.alk) * f
            s.ct += (c_in - s.ct) * f
            s.chlorine += (cl_in - s.chlorine) * f
        s.chlorine *= math.exp(-p["chlorine_decay_per_hr"] * dt / 3600)
        s.tank_level = min(100.0, max(0.0, s.tank_level + (q_in - q_out) / 60 * dt / p["capacity_gal"] * 100))
        s.flow_out = q_out
        return s

    def steady(self, raw: Raw, sp: dict, level: float = 60.0) -> ProcessState:
        """Long-run state for constant inputs (for initialising)."""
        a, c, cl = self.inlet(raw, sp)
        tau_h = level / 100 * self.params["capacity_gal"] / max(self.params["intake_gpm"], 1) / 60
        return ProcessState(level, a, c, cl / (1 + self.params["chlorine_decay_per_hr"] * tau_h))

    def estimate(self, meas: dict, raw: Raw) -> ProcessState:
        """Estimate the hidden tank state from sensors (what the twin does in the field).

        CT isn't measured, so assume the clearwell holds the same total carbonate
        as the raw water (NaOH doesn't change CT). Then alkalinity follows from
        the measured finished-water pH. Errors in this assumption show up in the
        twin's live accuracy score.
        """
        ct = ct_from_ph_alk(raw.ph, mgl_caco3_to_eq(raw.alkalinity), *self.pk())
        alk = alk_from_ph(meas["ph"], ct, *self.pk())
        return ProcessState(meas["tank_level"], alk, ct, meas["chlorine_residual"], meas.get("flow_out", 0))
