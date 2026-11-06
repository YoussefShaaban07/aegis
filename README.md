# Aegis

**Water plants run on decades-old control systems that anyone on the network can command, and now we're plugging AI into them. Aegis is a safety guard that sits in front of the plant's controller and blocks every dangerous command, whether it comes from an operator, an AI copilot, or a hacker.**

Built by **Youssef Shaaban** ([@YoussefShaaban07](https://github.com/YoussefShaaban07)) for the **VOXO Hatchathon 2026**, Legacy Tech track: *"Building tomorrow on the systems of today."*

Inspired by [Control Seat (YC S26)](https://www.ycombinator.com/launches/RJ6-control-seat-the-operating-system-for-the-physical-world), an AI-native SCADA platform that can run as an intelligence layer on top of existing control systems.

| Guard off: attack lands | Guard on: attack blocked |
|---|---|
| ![](docs/attack-unguarded.png) | ![](docs/attack-blocked.png) |

## The problem

- Water utilities run on PLCs and SCADA systems that speak **Modbus**, a 1979 protocol with **no authentication**: any device that can reach the controller can change a setpoint.
- In 2023, CISA warned after Iran-linked hackers ("CyberAv3ngers") compromised a Unitronics PLC at the Municipal Water Authority of Aliquippa, PA.
- In the widely reported 2021 Oldsmar, FL incident, the sodium hydroxide (lye) setpoint was raised from **100 ppm to 11,100 ppm**. (Later reporting questioned whether it was an outside hacker; the risk it illustrates is the same.)
- In 2026, Dragos reported attackers used commercial LLMs to plan a breach of a water utility, including SCADA-targeted scripts.
- Meanwhile, vendors are adding **AI copilots** that can read plant data *and write setpoints*. An AI that reads untrusted text (work orders, emails, alarm notes) can be **prompt-injected** into issuing commands.

## What Aegis does

```
 Operator HMI ─┐
 AI copilot  ──┼──► AEGIS GUARD (Modbus proxy, port 5502) ──► PLC (port 5020) ──► plant
 Attacker    ──┘         │
                         └─ decodes every write, checks it against a deterministic
                            safety envelope, blocks + logs anything unsafe
```

- **Real protocol:** our PLC and guard speak Modbus TCP (function codes 3, 4, 6, 16), written from scratch and verified against the standard `pymodbus` client.
- **Safety envelope** (`aegis/guard.py`): per-setpoint min/max, max change per command, interlocks (e.g. can't stop distribution while the tank is above 90%), and a write allowlist. Limits reference EPA values: pH 6.5–8.5, chlorine max 4.0 mg/L.
- **Same rules for everyone:** operator, AI, and unknown devices all go through the guard. **No LLM in the guard**, so a hijacked AI can't argue its way past it.
- **Atomic rejection:** a multi-register write with one bad value is rejected entirely.
- **AI copilot** (`aegis/copilot.py`): answers plain-English questions using live data and history, and can adjust setpoints, but only through the guard.
- **Plant simulator** (`aegis/plant.py`): intake, chlorine and lye dosing with chemical lag, clearwell level, distribution, alarms.

## Run it

```bash
pip install -r requirements.txt
cp .env.example .env              # add GROQ_API_KEY for the AI copilot
python -m aegis.server            # open http://127.0.0.1:8000
python -m pytest -q               # 12 tests
```

Attack from a separate terminal (local simulator only):
```bash
python -m aegis.attacks --port 5502 --value 11100
```

## Demo script (3 minutes)

1. **Hook (20s):** "Your town's water is controlled by computers from the 90s that will obey anyone who can reach them. Hackers already have. Now companies want to put AI on them."
2. **Act 1, guard OFF (40s):** click *Hacker: set lye to 11,100 ppm*. Lye jumps, pH climbs past 8.5, the water turns purple, alarm: *caustic water heading to town*.
3. **Act 2, guard ON (40s):** reset, flip the guard on, same attack: **BLOCKED**, with the exact reason. The operator's normal change still goes through.
4. **Act 3, the AI era (50s):** click *Plant poisoned work order* (hidden instructions for the AI). Ask the copilot: *"Any open work orders I should handle?"* If it falls for it and tries to raise lye to 9,000 ppm, the guard blocks the AI too. If it refuses, say so: you can't rely on the model refusing, which is why the guard exists.
5. **Close (30s):** "No new hardware. No PLC replacement. One box in front of the systems they already run."

## Q&A prep

- **"Don't PLCs already have limits?"** Some do, configured inside each PLC by whoever programmed it, often years ago. Aegis is one independent, auditable policy in front of *all* writers, including AI, with a live log of every decision.
- **"What if the attacker bypasses the guard?"** In deployment the PLC is only reachable through the guard (network segmentation). The guard is the single choke point.
- **"Why put AI on a water plant at all?"** Small utilities have tiny staffs; a copilot that explains trends helps one operator run more. Aegis makes that safe to try.
- **"Is this real Modbus?"** Yes. The tests drive our PLC with the standard `pymodbus` client.

## Limitations

- Simulated plant, not real hardware. Physics are simplified.
- Modbus unit IDs label sources in the log; Modbus has no auth, so labels can be spoofed. The guard applies the same rules regardless.
- The safety envelope values are illustrative; a real one is set and signed off by the utility's engineer.
- The AI copilot needs a Groq key. Its hijack test uses a scripted fake LLM (`tests/test_copilot.py`).

## Credits

- Modbus client used for interoperability tests: [pymodbus](https://github.com/pymodbus-dev/pymodbus).
- Reference testbeds studied: [GRFICS (Georgia Tech)](https://github.com/djformby/GRFICS), [SCADASim (CMU SEI)](https://www.github.com/cmu-sei/SCADASim).

MIT © 2026 Youssef Shaaban
