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

**Clearwell.** One continuously stirred tank: for each constituent x, dx/dt = (Q_in/V)(x_in − x), solved exactly per time step for constant inputs. Chlorine also decays first-order (k per hour) and loses an instantaneous demand at the inlet that grows with turbidity.

## The twin's decision rule (aegis/twin.py)

1. Estimate the hidden state from sensors: CT from raw pH and alkalinity; tank alkalinity from measured finished pH and that CT; chlorine and level as measured.
2. Simulate `horizon_min` (default 360) twice: with the candidate command and without it.
3. Measure each trajectory's worst excursion outside the bands (pH 6.5–8.5, chlorine 0.2–4.0), normalised by band width.
4. Block if *with* leaves the band and is worse than *without*. Allow (as "corrective") if *without* is already bad and *with* is better.

Multi-register writes are evaluated together. If the PLC doesn't expose the sensors the twin needs, the twin turns itself off and the static checks still run.

**Known limitations:** one well-mixed tank (real clearwells have baffles, so short-circuiting makes changes arrive sooner); no CO2 degassing (real open basins drift up in pH); constant temperature; sensors trusted (a spoofed pH sensor fools the twin). Accuracy is measured live against a simulator built with *different* parameters, but not against a real plant.

## Why this design

- **Deterministic guard, AI outside it.** The model that can be prompt-injected never sits in the decision path. AI helps humans (explanations, what-ifs, proposals); physics and rules decide.
- **Fail safe.** If the PLC or state read fails, writes are rejected with 0x0B and an alert, never passed unchecked.
- **Never block correction.** A safety system that stops the operator fixing a problem is itself a hazard.
- **Labels aren't identity.** Unit IDs only label the log; rate limits also count per IP; critical commands need a permit created out-of-band.
