# Aegis architecture

```
                         ┌────────────────────────── Aegis ──────────────────────────┐
 Operator HMI (unit 1) ─┐│  modbus.serve ──► Guard.handle                              │
 AI copilot   (unit 2) ─┼┤     │  parse (fuzz-safe)          ┌──────────────────────┐  │
 anything else         ─┘│     │  unknown FC? block          │ Twin (process model) │  │
                         │     │  write? decode targets ─────►│ estimate state from  │  │      ┌─────┐
                         │     │  (FC 22: read current,       │ sensors, forecast    │  │      │ PLC │
                         │     │   apply mask)                │ with vs without      │  │─────►│     │
                         │     │  checks 1..8 ───────────────►└──────────────────────┘  │      └─────┘
                         │     │  all ok? forward raw PDU ──────── modbus.Client ───────┼──────►
                         │     │  record → AuditLog (HMAC chain), Alerter (SMS/call)    │
                         └─────┴────────────────────────────────────────────────────────┘
```

| File | Role |
|---|---|
| `aegis/modbus.py` | Modbus TCP codec, async server (idle timeout, client cap), async client (reconnect, timeouts, source-IP binding) |
| `aegis/guard.py` | The proxy and the checks. Modes enforce/monitor/off. Latency metrics. Permits. |
| `aegis/process.py` | Carbonate chemistry + clearwell model, shared by simulator and twin |
| `aegis/twin.py` | State estimation + forecasts + the predict decision rule |
| `aegis/plant.py` | Simulated plant and its PLC (coils, holding, input registers), weather scenarios, noise |
| `aegis/audit.py` | Hash-chained SQLite log, optional HMAC key, head checkpoint, time-range queries |
| `aegis/alerts.py` | Twilio SMS + voice call, throttled, honest when not configured |
| `aegis/proposals.py` | AI propose → human approve, dry-run pre-check, re-check at apply time, permits on approval |
| `aegis/copilot.py` | LLM with tools: status, trend, work orders, `simulate_change`, `propose_setpoint` (or `set_setpoint` in direct mode) |
| `aegis/learn.py` | Suggest rules from observed traffic |
| `aegis/integrity.py` | Is the PLC telling the truth? Setpoint drift, physics shadow (alkalinity space), lab grab samples |
| `aegis/forewarn.py` | Early warnings when the twin's forecast crosses an alarm limit |
| `aegis/calibrate.py` | Fit the twin to the plant's own history, with anti-poisoning checks |
| `aegis/evaluate.py` | Randomized attack/operator episodes with ground truth; static vs twin |
| `aegis/auth.py` | Accounts, roles, scrypt hashes, signed sessions, CSRF, lockout |
| `aegis/supervisor.py` | Restart the gateway if it dies; `deploy/aegis.service` for systemd |
| `aegis/report.py` | Incident report (markdown + HTML) from the audit log |
| `aegis/gateway.py` | Guard-only deployment in front of a real PLC |
| `aegis/server.py` | All-in-one demo: plant + PLC + guard + dashboard API |
| `config/*.json` | Register map, safety policy, process parameters |

## The chemistry (aegis/process.py)

**Carbonate system** (25 °C, closed: no CO2 exchange with air)

- Total carbonate CT = [H2CO3*] + [HCO3⁻] + [CO3²⁻]
- Fractions: α1 = K1·H / (H² + K1·H + K1·K2), α2 = K1·K2 / (…), pK1 = 6.35, pK2 = 10.33
- Alkalinity (eq/L) = CT·(α1 + 2·α2) + Kw/H − H

Raw water is described by measured pH and alkalinity, which gives CT. NaOH adds 1 eq of alkalinity per mole and doesn't change CT. pH is then the root of the charge balance (bisection; alkalinity is monotonic in pH).

`naoh_feed_strength` (config/process.json) converts the feed setpoint (ppm of feed solution, like the Oldsmar HMI) into mg/L NaOH added. It's a calibration constant, chosen so the normal setpoint gives pH ≈ 7.3 for the normal raw water.

**Disinfection.** Free chlorine splits into HOCl (strong disinfectant) and OCl⁻ (weak), pKa ≈ 7.54. At pH 9 only ~3% is HOCl, so a lye attack also quietly guts disinfection. The dashboard shows this as "Disinfecting (HOCl)".

**Clearwell.** `baffling_cells` continuously stirred tanks in series (1 = unbaffled). Utilities know their baffling from the tracer studies required for disinfection credit. For each constituent x in each cell, dx/dt = (Q/V_cell)(x_upstream − x), solved exactly per step. Chlorine decays first-order and loses an instantaneous, turbidity-dependent demand at the inlet. Optional CO2 exchange with air (`kla_per_hr`) lowers total carbonate toward atmospheric equilibrium and nudges pH up. Carbonate constants follow the measured water temperature (tabulated pK1, pK2, pKw at 0/15/25 °C, interpolated).

**Solver.** pH is the root of the charge balance. With a guess (each cell's previous pH), Newton converges in 2–3 iterations; otherwise bisection. They agree to 3×10⁻¹⁰ pH over 3,000 random cases.

## The twin's decision rule (aegis/twin.py)

1. Estimate the hidden state from sensors: CT from raw pH and alkalinity; tank alkalinity from measured finished pH and that CT; chlorine and level as measured.
2. Simulate `horizon_min` (default 360) twice: with the candidate command and without it.
3. Measure each trajectory's worst excursion outside the bands (pH 6.5–8.5, chlorine 0.2–4.0), normalised by band width.
4. Block if *with* leaves the band and is worse than *without*. Allow (as "corrective") if *without* is already bad and *with* is better.

Multi-register writes are evaluated together. If the PLC doesn't expose the sensors the twin needs, the twin turns itself off and the static checks still run.

**Robustness.** Every decision runs across an ensemble (nominal + four corners: lye feed ±10%, chlorine decay ±30%, demand ±25%) and checks the long-run steady state as well as the 6 h forecast. The worst case decides. Tank level has its own shorter horizon (3 h), because this plant can't hold the tank steady forever by design.

**Corrective override.** If step/ramp limits would block a change but the twin computes that it improves an unsafe forecast, it's allowed and logged as a corrective override.

**Known limitations:** sensors are trusted for the forecast (the integrity monitor is the check on them); the model is textbook chemistry, tested against our own simulators (one of which deliberately has physics the twin gets wrong), not against a real plant; no lime/soda ash, phosphate, or chloramine chemistry.

## Integrity monitor (aegis/integrity.py)

A shadow copy of the process runs open-loop, driven by the setpoints *Aegis approved* and the raw-water sensors. Each minute, the measured pH is converted to the alkalinity it implies (using the shadow's carbonate), and compared with the shadow's alkalinity. Alkalinity space matters: on the steep part of the titration curve a 3% model error is 0.4 pH but still 3% of alkalinity. Alarm when the error exceeds 4% (or chlorine 0.3 mg/L) for 3 consecutive checks. While consistent, the shadow re-anchors hourly by *shifting* its cell profile to match the outlet, so a dose change still travelling through the baffles isn't flattened away.

Measured (20 × 10 h runs each, operator changes, storms, blooms): **0 false alarms** on the standard simulator and on the high-fidelity simulator (4 cells vs the twin's 3, faster degassing, 15 °C, quantized lye pump, analyzer lag). Hidden 100 → 200 ppm lye attack: **detected in all 20 runs, 77–84 simulated minutes after it starts.** A creeping attack kept under ~2% per hour could be absorbed by re-anchoring; a full replay (setpoints and readings faked) is invisible without a lab grab sample.

## Authentication (aegis/auth.py)

viewer < operator < engineer. scrypt (n=2¹⁴, r=8, p=1) password hashes; HMAC-SHA256-signed session tokens in HttpOnly SameSite=Strict cookies, 8 h expiry, invalidated if the user's role changes; `X-Aegis: 1` header required on every write (CSRF); 5 failures per user or IP per 5 min → locked out. Engineer actions also need the PIN. Every action is logged with the user's name.

## Why this design

- **Deterministic guard, AI outside it.** The model that can be prompt-injected never sits in the decision path. AI helps humans (explanations, what-ifs, proposals); physics and rules decide.
- **Fail safe.** If the PLC or state read fails, writes are rejected with 0x0B and an alert, never passed unchecked.
- **Never block correction.** A safety system that stops the operator fixing a problem is itself a hazard.
- **Labels aren't identity.** Unit IDs only label the log; rate limits also count per IP; critical commands need a permit created out-of-band.
