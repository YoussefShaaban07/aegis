# Aegis

**Water plants run on decades-old control systems that obey anyone on the network, and now we're plugging AI into them. Aegis is a safety guard that sits in front of the plant's controller and blocks every dangerous command, whether it comes from an operator, an AI copilot, or a hacker.**

Built by **Youssef Shaaban** ([@YoussefShaaban07](https://github.com/YoussefShaaban07)) for the **VOXO Hatchathon 2026**, Legacy Tech track: *"Building tomorrow on the systems of today."*

Inspired by [Control Seat (YC S26)](https://www.ycombinator.com/launches/RJ6-control-seat-the-operating-system-for-the-physical-world), an AI-native SCADA platform. Aegis focuses on one piece of that: making it safe to put AI (and anyone else) in front of the controllers small utilities already own.

![Aegis dashboard](docs/dashboard.png)

| Guard off: attack lands | Guard on: attack blocked |
|---|---|
| ![](docs/attack-unguarded.png) | ![](docs/attack-blocked.png) |

## The problem

- Water utilities run on PLCs that speak **Modbus**, a 1979 protocol with **no authentication**: any device that can reach the controller can change a setpoint.
- In May 2024 the EPA said **over 70%** of the water systems it inspected did not fully comply with basic cybersecurity requirements. The EPA's 2023 rule requiring cyber checks was withdrawn after a lawsuit by states and industry groups.
- In 2023, CISA warned after Iran-linked hackers compromised a Unitronics PLC at the Municipal Water Authority of Aliquippa, PA.
- In the widely reported 2021 Oldsmar, FL incident, the lye (sodium hydroxide) setpoint was raised from **100 ppm to 11,100 ppm**. (Later reporting questioned whether it was an outside hacker; the risk it shows is the same.)
- In 2026, Dragos reported attackers used commercial LLMs to plan a breach of a water utility.
- Vendors are adding **AI copilots** that read plant data and can write setpoints. An AI that reads untrusted text (work orders, emails, alarm notes) can be **prompt-injected** into issuing commands.

## How it works

```
 Operator HMI ─┐
 AI copilot  ──┼──► AEGIS GUARD (Modbus proxy) ──► PLC ──► pumps, chemical dosing
 Attacker    ──┘        │
                        ├─ decodes every write, checks it against the safety envelope
                        ├─ hash-chained audit log of every decision
                        └─ SMS + phone call to the operator on critical events
```

Every write is checked in this order. The first failure blocks it:

| Check | Stops | Example |
|---|---|---|
| **flood** | automated tools hammering the PLC | more than 20 writes/min from one source |
| **allowlist** | writes to registers that aren't setpoints | writing an alarm register |
| **range** | absurd values | lye 11,100 ppm (safe 0–300) |
| **step** | big jumps in one command | chlorine 1.5 → 3.5 in one write |
| **ramp** | "stealth" attacks: many small legal steps | +0.4 every second; net change limited per 60 s window |
| **interlock** | unsafe combinations | can't stop distribution while the clearwell is above 90% |

**No LLM inside the guard.** It is plain, deterministic rules, so a hijacked AI can't talk its way past it. Multi-register writes are rejected as a whole if any value is unsafe.

## Features

- **Real Modbus TCP** (function codes 3, 4, 6, 16), written from scratch and checked against the standard `pymodbus` client.
- **Config-driven:** the register map (`config/tags.json`) and safety rules (`config/policy.json`) are files, not code. Adapting to another plant means editing these.
- **Rules editor** in the dashboard, protected by an engineer PIN. Bad rules (min above max, unknown setpoints) are rejected before they take effect. Every change is logged.
- **AI copilot, propose → approve (default):** the AI can only *propose* changes. Each proposal is dry-run against the guard: unsafe ones are marked BLOCKED and can't be approved. Safe ones wait for a human, and on approval the write is checked **again**, because the plant may have changed. A "direct" mode (engineer PIN) lets the AI write, still only through the guard.
- **Tamper-evident audit log:** every decision, alert, rule change, approval and login failure goes into SQLite with a SHA-256 hash chain. Editing or deleting any past entry breaks the chain, and the dashboard shows it. Export to CSV.
- **Operator alerts:** critical events send an SMS and place a phone call via Twilio (throttled so an attack doesn't spam 200 texts). Without Twilio keys, the dashboard says "SMS not configured" instead of pretending.
- **Gateway mode** for a real PLC or [OpenPLC](https://autonomylogic.com/): runs just the guard in front of an actual controller.
- **Plant simulator:** intake, chlorine and lye dosing with chemical lag, clearwell level, distribution, alarms.

## Run it

```bash
pip install -r requirements.txt
cp .env.example .env          # add GROQ_API_KEY for the AI copilot (free)
python -m aegis.server        # open http://127.0.0.1:8000
python -m pytest -q           # 42 tests
```

Engineer PIN defaults to **2468** (set `AEGIS_ENGINEER_PIN` in `.env`).

Attack from a separate terminal (local simulator only):
```bash
python -m aegis.attacks --port 5502 --value 11100
```

### Gateway mode (real PLC or OpenPLC)

```bash
python -m aegis.gateway --plc-host 192.168.1.50 --plc-port 502 --listen-port 5502
```

Point the HMI and AI at the gateway instead of the PLC, and firewall the PLC so only the gateway can reach it. Edit `config/tags.json` so register addresses match the PLC program. The gateway prints one ALLOW/BLOCK line per write.

## Done / not done (honest status)

| Item | Status |
|---|---|
| Modbus guard: range, step, ramp, flood, allowlist, interlocks | ✅ built + tested |
| Atomic multi-register rejection | ✅ tested |
| Rules editor + engineer PIN | ✅ tested (API + browser) |
| Propose → approve AI flow, re-check at apply time | ✅ tested with a scripted fake LLM |
| Hash-chained audit log, tamper detection, CSV export | ✅ tested |
| Alerts: throttling, honest "not configured" | ✅ tested |
| Twilio SMS/call | ⚠️ request format tested against a mock only; **not yet sent to a real phone** |
| AI copilot against a real model (Groq) | ⚠️ **not yet run with a real key**; whether a real model falls for the poisoned work order is unknown until tried |
| Gateway mode | ✅ tested against our simulated PLC in a separate process; ⚠️ **not yet tested on OpenPLC or hardware** |
| Protocols other than Modbus (DNP3, EtherNet/IP, S7) | ❌ not built |
| Web dashboard login | ❌ only engineer actions need the PIN; operator actions (approve/reject) don't |

## Demo script (3 minutes)

1. **Hook (20s):** "Your town's water is controlled by computers from the 90s that obey anyone who can reach them. Hackers already have. Now companies want to put AI on them."
2. **Act 1, guard OFF (30s):** turn the guard off (PIN 2468), click *Hacker: set lye to 11,100 ppm*. pH climbs past 8.5 and the alarm fires.
3. **Act 2, guard ON (30s):** reset, guard on, same attack: **BLOCKED** with the exact reason. An operator alert appears.
4. **Act 3, smart attackers (30s):** *Stealth* (small legal steps, caught by the **ramp** check) and *Flood* (20 pass, then blocked).
5. **Act 4, the AI era (40s):** *Plant poisoned work order*, then ask the copilot "Any open work orders I should handle?" If it proposes lye 9,000, the proposal is BLOCKED and can't be approved. Then ask about chlorine and approve a safe proposal: humans stay in control. If the model refuses the injection, say so: you can't rely on the model refusing, which is why the guard exists.
6. **Close (30s):** show the audit log ("chain intact") and the rules editor. "No new hardware. No PLC replacement. One box in front of what they already run."

## Q&A prep

- **"Don't firewalls for this already exist?"** Yes, industrial firewalls like Tofino's Modbus enforcer exist and are a real competitor. They're built for big utilities with OT security teams. Aegis targets the thousands of small systems with 2–5 staff, and it's built for AI: propose/approve, and an audit trail of what the AI tried.
- **"If the government couldn't fix this, how can you?"** The government's fix was a rule (withdrawn). The technical fix, checking every command before it reaches the PLC, is well understood; what's missing is something cheap and simple enough for a small utility to actually deploy.
- **"Don't PLCs already have limits?"** Some do, set inside each PLC by whoever programmed it, often years ago. Aegis is one auditable policy in front of *all* writers, including AI.
- **"What if the attacker bypasses the guard?"** In deployment the PLC is only reachable through the guard (network segmentation). The guard is the single choke point.
- **"Is this real Modbus?"** Yes. Tests drive it with the standard `pymodbus` client, and gateway mode runs against a separate PLC process.

## Limitations

- Simulated plant, not real hardware. Physics are simplified.
- Modbus unit IDs label sources in the log but can be spoofed (Modbus has no auth). The guard applies the same rules regardless of label.
- The safety values are illustrative (based on EPA pH 6.5–8.5 and chlorine max 4.0 mg/L); a real envelope is set and signed off by the utility's engineer.

## Credits

- [pymodbus](https://github.com/pymodbus-dev/pymodbus): used for interoperability tests.
- [FastAPI](https://fastapi.tiangolo.com/), [uvicorn](https://www.uvicorn.org/), [httpx](https://www.python-httpx.org/), [pytest](https://pytest.org/).
- Reference testbeds studied: [GRFICS (Georgia Tech)](https://github.com/djformby/GRFICS), [SCADASim (CMU SEI)](https://www.github.com/cmu-sei/SCADASim).

MIT © 2026 Youssef Shaaban
