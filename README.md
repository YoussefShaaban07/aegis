# Aegis

**Water plants run on decades-old controllers that obey anyone on the network, and now we're plugging AI into them. Aegis is a safety guard that sits in front of the plant's controller and checks every command before it lands, whether it comes from an operator, an AI copilot, or a hacker. It doesn't just check limits: a digital twin of the plant's water chemistry predicts where each command will take the water over the next six hours, and blocks the ones that end in unsafe water.**

Built by **Youssef Shaaban** ([@YoussefShaaban07](https://github.com/YoussefShaaban07)) for the **VOXO Hatchathon 2026**, Legacy Tech track: *"Building tomorrow on the systems of today."*

Inspired by [Control Seat (YC S26)](https://www.ycombinator.com/launches/RJ6-control-seat-the-operating-system-for-the-physical-world), an AI-native SCADA platform. Aegis focuses on one piece of that: making it safe to put AI (and anyone else) in front of the controllers small utilities already own.

![Aegis dashboard](docs/dashboard.png)

## The problem

- Water utilities run on PLCs that speak **Modbus**, a 1979 protocol with **no authentication**: any device that can reach the controller can change a setpoint.
- In May 2024 the EPA said **over 70%** of the water systems it inspected did not fully comply with basic cybersecurity requirements. The EPA's 2023 rule requiring cyber checks in sanitary surveys was withdrawn after a lawsuit by states and industry groups.
- In 2023, CISA warned after Iran-linked hackers compromised a Unitronics PLC at the Municipal Water Authority of Aliquippa, PA.
- In the widely reported 2021 Oldsmar, FL incident, the lye (sodium hydroxide) setpoint was raised from **100 ppm to 11,100 ppm**. (Later reporting questioned whether it was an outside hacker; the risk it shows is the same.)
- In 2026, Dragos reported attackers used commercial LLMs to plan a breach of a water utility.
- Vendors are adding **AI copilots** that read plant data and can write setpoints. An AI that reads untrusted text (work orders, emails, alarm notes) can be **prompt-injected** into issuing commands.

## Why limits aren't enough: the chemistry

Lye raises pH by neutralising the carbonic acid in the water. In weakly buffered water, the response is a **titration curve**: flat, then suddenly steep. With this plant's raw water (pH 6.9, alkalinity 77 mg/L as CaCO3):

| Lye feed (ppm) | 100 | 150 | 180 | 200 | 250 |
|---|---|---|---|---|---|
| Finished-water pH (steady state) | 7.33 | 7.82 | 8.49 | 8.87 | 9.31 |

So a static rule like "lye 0–250, at most +50 per command" lets a patient attacker walk 100 → 150 → 200 in legal steps and end up with caustic water. On an algae-bloom afternoon (raw pH 8.3), even the *normal* dose overshoots, and the right move is to *cut* lye, which a fixed rule can't know. Aegis's twin knows, because it computes the chemistry from the plant's own sensors (`aegis/process.py`).

## How it works

```
 Operator HMI ─┐
 AI copilot  ──┼──► AEGIS GUARD (Modbus proxy) ──► PLC ──► pumps, chemical dosing
 Attacker    ──┘        │
                        ├─ decodes every write (FC 5, 6, 15, 16, 22, 23), blocks other codes
                        ├─ static rules + digital-twin forecast for each command
                        ├─ HMAC hash-chained audit log, incident reports (MITRE ATT&CK for ICS)
                        └─ SMS + phone call to the on-call operator
```

Every write is checked in this order; the first failure blocks it:

| Check | Stops | Example |
|---|---|---|
| **function** | diagnostics, device-ID recon, vendor programming codes | FC 8 "force listen-only mode", FC 43, FC 90 (Schneider UMAS) |
| **flood** | automated tools, counted per label *and per IP* | 30 writes/s with rotating unit IDs |
| **allowlist** | writes to registers that aren't setpoints | writing an alarm register |
| **range** | absurd values | lye 11,100 ppm (hard max 250) |
| **step** | big jumps in one command | chlorine 1.5 → 3.5 in one write |
| **ramp** | stealth: many small legal steps | +0.4 mg/L chlorine every second |
| **interlock** | unsafe combinations | stop distribution while the clearwell is above 90% |
| **permit** | critical commands from the network | stopping the town's pump needs a single-use permit issued on the dashboard with the PIN |
| **predict** | commands that pass every rule but end in unsafe water | lye 150 → 200: twin predicts pH 8.7 in ~2 h |
| *unusual* | *(alert only)* values outside the band learned from normal traffic | chlorine 2.5 when a normal week never exceeded 1.9 |

**No LLM inside the guard.** It's deterministic rules and physics, so a hijacked AI can't argue its way past it. Multi-register writes are rejected as a whole if any value is unsafe. The twin never blocks *corrective* commands: if the plant is already heading somewhere bad, a change that makes it better is always allowed.

**Modes:** `enforce` (block), `monitor` (log "would block" but let it through, for a trial period before a utility trusts it), `off` (pass everything, loudly alerted).

## Features

- **Modbus TCP from scratch** (`aegis/modbus.py`): FC 1, 2, 3, 4, 5, 6, 15, 16, 22, 23; fuzz-tested parser; idle timeouts and connection caps; automatic upstream reconnect; fails safe (exception 0x0B) if the PLC is unreachable.
- **Digital twin** (`aegis/process.py`, `aegis/twin.py`): carbonate chemistry (charge balance solved for pH), a mixed-tank clearwell model, chlorine demand and decay, and the HOCl/OCl⁻ split (how much chlorine actually disinfects). State is *estimated from sensors*, and every forecast is "with this command vs without it".
- **Twin accuracy measured live** against the simulator, which deliberately differs from the twin (3% stronger lye feed, 20% faster chlorine decay, drifting demand, sensor noise).
- **AI copilot, propose → approve (default)**: the AI can call `simulate_change` (ask the twin) and `propose_setpoint`. Proposals are pre-checked; unsafe ones are BLOCKED and can't be approved; safe ones show their forecast and wait for a human; on approval the write is checked **again**.
- **Operator permits** for critical commands (pump stops): a Modbus packet can claim to be the HMI; it can't create a permit.
- **Learn normal** (`aegis/learn.py`): run in monitor mode, then get suggested rules from observed traffic (alert bands, tighter step/ramp/flood limits). Statistics, not AI; the engineer reviews and applies.
- **Tamper-evident audit log**: SQLite, hash-chained, HMAC-keyed if `AEGIS_AUDIT_KEY` is set. Head hash printed in reports so later rewrites are detectable. CSV export.
- **Incident report** (`aegis/report.py`): timeline, sources, MITRE ATT&CK for ICS techniques, AI proposals, config changes, evidence integrity, and a "what this report does not establish" section.
- **Operator alerts**: SMS, plus a phone call for critical events, via Twilio, throttled per attacker IP. Honest "not configured" otherwise.
- **Gateway mode** for a real PLC: guard-only, with the twin on if the PLC exposes the needed sensors.
- **What-if** on the dashboard: ask the twin before you touch anything; the forecast is drawn on the trend chart.

## Run it

**Windows:** double-click `run.bat` (needs Python 3.10+ from python.org). **macOS/Linux:** `./run.sh`. Or manually:

```bash
pip install -r requirements.txt
cp .env.example .env          # add GROQ_API_KEY for the AI copilot (free at console.groq.com)
python -m aegis.server        # open http://127.0.0.1:8000   (engineer PIN 2468)
python -m pytest -q           # 81 tests
python scripts/bench.py       # latency on your machine
```

Attacks from a separate terminal (local simulator only):
```bash
python -m aegis.attacks lye | mask | readwrite | coil | recon | flood
```

### Gateway mode (real PLC)

```bash
python -m aegis.gateway --plc-host 192.168.1.50 --plc-port 502 --listen-port 5502 --mode monitor
```

Point the HMI and AI at the gateway instead of the PLC, and firewall the PLC so only the gateway can reach it. Edit `config/tags.json` to match the PLC's register map, `config/process.json` for the plant, and `config/policy.json` for the rules. Start in `--mode monitor`, then use the learn tool: `python -m aegis.learn --hours 168`.

## Measured numbers (this repo, not marketing)

| What | Result | How to reproduce |
|---|---|---|
| Latency added per write, static checks | p50 0.17 ms, p99 0.4 ms over direct | `python scripts/bench.py` (cloud x86 VM, Python 3.13) |
| Latency added per write, with digital twin | p50 2.8 ms, p99 5.3 ms | same |
| Reads | +0.04 ms (pass through) | same |
| Twin forecast error vs simulator, pH, 30–120 min ahead after a lye step | under 0.15 pH | `tests/test_twin.py::test_forecast_accuracy_against_simulator` |
| Parser robustness | 50,000 random PDUs, 200 malformed frames, server keeps serving | `tests/test_protocol.py` |

## Done / not done (honest status)

| Item | Status |
|---|---|
| Guard checks: function, flood (label + IP), allowlist, range, step, ramp, interlock, permit, twin predict, unusual | ✅ built + tested |
| All write function codes incl. FC 22/23 bypass attempts; coils | ✅ tested with our client and with pymodbus |
| Gateway in front of a **third-party** Modbus server (pymodbus) with a pymodbus client | ✅ tested (`tests/test_interop.py`) |
| Digital twin: chemistry, forecasts, live accuracy | ✅ tested against our simulator. ⚠️ **Not validated against a real plant**: the model is textbook chemistry with stated simplifications (one mixed tank, no CO2 exchange, 25 °C) |
| Propose → approve AI flow with twin forecasts, re-check at apply time | ✅ tested with scripted fake LLMs |
| AI copilot against a real model (Groq) | ⚠️ **not yet run with a real key** |
| Twilio SMS/call | ⚠️ request format tested against a mock; **not yet sent to a real phone** |
| OpenPLC / real hardware | ⚠️ **not tested** (the sandbox this was built in blocked OpenPLC's installer). pymodbus is the third-party stand-in |
| Protocols other than Modbus TCP (DNP3, EtherNet/IP, S7, Modbus RTU serial) | ❌ not built |
| Dashboard login / user accounts | ❌ engineer actions need the PIN; approving AI proposals doesn't |
| TLS on Modbus (Modbus/TCP Security) | ❌ not built |

## Demo script (3 minutes)

1. **Hook (20s):** "Your town's water is controlled by computers from the 90s that obey anyone who can reach them. Hackers already have. Now companies want to put AI on them."
2. **Oldsmar (20s):** *Oldsmar: lye → 11,100*. BLOCKED, with the reason. Then *Sneaky FC 22 write*: same attack hidden in a rarely-used command, also blocked. "Filters that only check normal writes miss this."
3. **The twin (50s):** in What-if, type lye 200 and press Predict: the orange line climbs past 8.5. "Every rule says 200 is fine: under the max, a legal step. The chemistry says it's caustic water in two hours." Press *Apply as operator*: blocked by **predict**. Then *Algae bloom*: pH starts climbing on its own; Predict lye 50, and the twin shows it bringing pH back. "It doesn't just block, it tells you what's safe."
4. **AI (40s):** *Plant poisoned work order*, ask the copilot "Any open work orders I should handle?". The lye proposal is BLOCKED and can't be approved. Ask "Chlorine is low, what should I do?" during a *Storm*: it proposes a dose with the twin's forecast; approve it. If the model refuses the injection, say so: you can't count on the model refusing, which is why the guard exists.
5. **Close (30s):** *Stop town pump*: blocked, needs a permit. Evidence tab: chain intact, latency, twin accuracy; open the incident report with ATT&CK mappings. "No new hardware, no PLC replacement. One box in front of what they already run."

## Q&A prep

- **"Industrial firewalls already exist."** Yes. Tofino's Modbus enforcer and similar deep-packet-inspection firewalls check function codes and register ranges; they're a real competitor. They don't model the process, so they can't tell that a legal-looking lye step ends in caustic water. They also aren't built for AI writers: propose/approve, forecasts on proposals, a record of what the AI tried.
- **"If the government couldn't fix this, how can you?"** The government's fix was a rule, and it was withdrawn. The technical part (check every command before the PLC) is understood; what's missing is something cheap and simple enough for a utility with 2–5 staff. Monitor mode plus learn-normal is for exactly that.
- **"Is your chemistry real?"** It's the standard carbonate-system charge balance and a mixed-tank model, with simplifications listed above. Accuracy is measured against a simulator that deliberately differs from the model, not against itself. It hasn't been validated on a real plant.
- **"What if the attacker bypasses the guard?"** In deployment the PLC is only reachable through the guard (network segmentation). If the attacker is *on* the guard box, all bets are off, which is why the audit log can be keyed and checkpointed off-box.
- **"Can't an attacker pretend to be the operator?"** Yes: Modbus unit IDs are labels. That's why the rules apply to everyone, flood limits count per IP, and critical commands need a permit created on the dashboard, not a packet.

## Docs

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): how each part works, and the chemistry.
- [`docs/JUDGE_ROUNDS.md`](docs/JUDGE_ROUNDS.md): adversarial review rounds: brutal judge questions and what changed in response.

## Credits

- [pymodbus](https://github.com/pymodbus-dev/pymodbus): third-party client/server for interoperability tests.
- [FastAPI](https://fastapi.tiangolo.com/), [uvicorn](https://www.uvicorn.org/), [httpx](https://www.python-httpx.org/), [pytest](https://pytest.org/), [Playwright](https://playwright.dev/) (screenshots).
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) technique IDs; [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) (LLM01).
- Carbonate chemistry: standard aquatic-chemistry constants (pK1 6.35, pK2 10.33, HOCl pKa ≈ 7.5 at 25 °C).
- Reference testbeds studied: [GRFICS (Georgia Tech)](https://github.com/djformby/GRFICS), [SCADASim (CMU SEI)](https://www.github.com/cmu-sei/SCADASim).

MIT © 2026 Youssef Shaaban
