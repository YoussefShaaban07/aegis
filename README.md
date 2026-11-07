# Aegis

**Water plants run on decades-old controllers that obey anyone on the network, and now we're plugging AI into them. Aegis is a safety guard that sits in front of the plant's controller and checks every command before it lands, whether it comes from an operator, an AI copilot, or a hacker. It doesn't just check limits: a digital twin of the plant's water chemistry predicts where each command will take the water over the next six hours, and blocks the ones that end in unsafe water.**

Built by **Youssef Shaaban** ([@YoussefShaaban07](https://github.com/YoussefShaaban07)) for the **VOXO Hatchathon 2026**, Legacy Tech track: *"Building tomorrow on the systems of today."*

Inspired by [Control Seat (YC S26)](https://www.ycombinator.com/launches/RJ6-control-seat-the-operating-system-for-the-physical-world), an AI-native SCADA platform. Aegis focuses on one piece of that: making it safe to put AI (and anyone else) in front of the controllers small utilities already own.

![Aegis dashboard](docs/dashboard.png)

| The AI tries to talk the operator into switching Aegis off | The on-call operator's phone |
|---|---|
| ![](docs/copilot-reply-guard.png) | ![](docs/operator-view.png) |

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
- **Digital twin** (`aegis/process.py`, `aegis/twin.py`): carbonate chemistry (charge balance solved for pH, temperature-dependent constants), a baffled clearwell (stirred tanks in series), CO2 exchange with air, chlorine demand and decay, and the HOCl/OCl⁻ split (how much chlorine actually disinfects). State is *estimated from sensors*, and every forecast is "with this command vs without it".
- **Twin accuracy measured live** against the simulator, which deliberately differs from the twin (3% stronger lye feed, 20% faster chlorine decay, drifting demand, sensor noise).
- **AI copilot, propose → approve (default)**: the AI can call `simulate_change` (ask the twin) and `propose_setpoint`. Proposals are pre-checked; unsafe ones are BLOCKED and can't be approved; safe ones show their forecast and wait for a human; on approval the write is checked **again**.
- **Operator permits** for critical commands (pump stops): a Modbus packet can claim to be the HMI; it can't create a permit.
- **Learn normal** (`aegis/learn.py`): run in monitor mode, then get suggested rules from observed traffic (alert bands, tighter step/ramp/flood limits). Statistics, not AI; the engineer reviews and applies.
- **Tamper-evident audit log**: SQLite, hash-chained, HMAC-keyed if `AEGIS_AUDIT_KEY` is set. Head hash printed in reports so later rewrites are detectable. CSV export.
- **Incident report** (`aegis/report.py`): timeline, sources, MITRE ATT&CK for ICS techniques, AI proposals, config changes, evidence integrity, and a "what this report does not establish" section.
- **Operator alerts**: SMS, plus a phone call for critical events, via Twilio, throttled per attacker IP. Honest "not configured" otherwise.
- **Gateway mode** for a real PLC: guard-only, with the twin on if the PLC exposes the needed sensors.
- **What-if** on the dashboard: ask the twin before you touch anything; the forecast is drawn on the trend chart.
- **Robust twin**: every forecast runs across an uncertainty ensemble (lye feed ±10%, chlorine decay ±30%, demand ±25%) plus the long-run steady state; the worst case decides. Found necessary by our own evaluation (see below).
- **Process integrity: is the PLC lying?** (`aegis/integrity.py`) A compromised PLC (Stuxnet-style) can change dosing itself and never send a command through Aegis. Aegis runs the chemistry alongside the plant using only setpoints *it approved*, and alerts when the water stops matching; it flags any setpoint changed behind its back; and it compares **lab grab samples** (the one reading that doesn't come through the PLC) with what the PLC reports.
- **Twin calibration** (`aegis/calibrate.py`): fits lye feed strength and chlorine decay/demand from the plant's own history. Refuses to apply while integrity alarms are active or when a parameter jumps >25%, so an attack can't be "learned" as normal.
- **Corrective override**: if the twin computes that a change *fixes* an unsafe trend, it may exceed the step/ramp limits (logged). A safety system must never block the emergency fix.
- **Early warnings** (`aegis/forewarn.py`): the operator is texted when the twin's forecast crosses an alarm limit, hours before the alarm itself.
- **Accounts and roles** (`aegis/auth.py`): viewer / operator / engineer, scrypt hashes, signed expiring sessions, CSRF protection, login lockout, every action attributed to a named user.
- **Red-team the AI** (`python -m aegis.redteam`): 8 prompt-injection attacks + a benign control against the real copilot; measures how often the model tries something unsafe and how often anything reaches the PLC (with a maximally gullible model: 7/8 tried, 0 reached).
- **Cycling protection**: rapid back-and-forth changes (wear out pumps/valves, pressure surges) are blocked after 4 reversals in 10 min.
- **Read-flood protection**: per-IP read rate limit and a 100 ms coalescing cache, so heavy polling can't knock a small PLC over.
- **Onboarding** (`python -m aegis.onboard --export plc_tags.csv`): drafts the register map from the PLC's own tag export plus values observed on the wire; flags anything uncertain.
- **Incidents, not alert storms**: related alerts become one incident and one text; unacknowledged critical incidents escalate down a contact list.
- **Reply guard** (`aegis/replyguard.py`): the AI's answers are checked against live readings and for advice to disable safety, before the operator reads them.
- **Tell the operator what *is* safe**: when the twin blocks an operator or AI change, Aegis computes the largest change it would accept right now.
- **Tamper resistance**: signed policy file (edits outside Aegis are detected), off-box audit copy via syslog, monotonic rate windows.
- **Operator view** (`/operator`): a phone-sized page for the on-call operator: is the water safe, what to acknowledge, what's coming.
- **Real Modbus semantics in the gateway**: unit IDs are routed to the target device (TCP-to-serial gateways work); writers are named by IP; tested with `mbpoll`/libmodbus (C) and pymodbus (Python) on both sides.
- **Safe-hold** (`aegis/safehold.py`): if the twin forecasts unsafe water and **nobody acknowledges for 15 minutes**, Aegis restores the earlier setpoint (one the plant actually ran at in the last 12 h) that fixes the forecast most, then holds it: Modbus writes that move it are refused unless the twin calls them corrective, until someone releases the hold with a login. A hijacked HMI can't undo it. Stands down while the integrity monitor distrusts the sensors; never acts in monitor mode; never touches pumps. Holds survive restarts.
- **Bypass check** (`python -m aegis.exposure <plc-ip>`, run from any other machine): is the PLC reachable around Aegis? Probes Modbus, EtherNet/IP (44818, which MicroLogix runs alongside Modbus), S7, DNP3, OPC UA, web, telnet, FTP.
- **Read-only unknown hosts**: in the gateway, `"unknown_writers": "block"` makes every host not named in `--sources` read-only.
- **Guided demo**: one button walks through the whole story with what to say at each step; fast-forwards slow chemistry.
- **Resilience**: per-request errors fail closed without taking the server down; a supervisor restarts the gateway; `/health` endpoint; systemd unit with least privilege (`deploy/aegis.service`); soak-tested with 20 concurrent HMIs.

## Run it

**Windows:** double-click `run.bat` (needs Python 3.10+ from python.org). **macOS/Linux:** `./run.sh`. Or manually:

```bash
pip install -r requirements.txt
cp .env.example .env          # add GROQ_API_KEY for the AI copilot (free at console.groq.com)
python -m aegis.server        # open http://127.0.0.1:8000
python -m pytest -q           # 146 tests
python -m aegis.evaluate      # attack/operator evaluation (~10 min)
python -m aegis.redteam       # prompt-injection red team against the real copilot (needs GROQ_API_KEY)
python scripts/bench.py       # latency on your machine
```

Sign in with the demo accounts **operator / operator** or **engineer / engineer** (engineer PIN **2468**), then press **▶ Guided demo**. For a real deployment set `AEGIS_DEMO=0`, create accounts with `python -m aegis.auth add <name> <role>`, and set `AEGIS_ENGINEER_PIN`, `AEGIS_SESSION_SECRET` and `AEGIS_AUDIT_KEY`.

Attacks from a separate terminal (local simulator only):
```bash
python -m aegis.attacks lye | mask | readwrite | coil | recon | flood
```

### Gateway mode (real PLC)

```bash
python -m aegis.gateway --plc-host 192.168.1.50 --plc-port 502 --listen-port 5502 --mode monitor \
    --sources "10.0.0.5=Operator HMI,10.0.0.9=AI copilot" --health-port 8081
```

Point the HMI and AI at the gateway instead of the PLC, and firewall the PLC so only the gateway can reach it. Onboarding, in order:

1. Run in `--mode monitor` for a few days: nothing is blocked; Aegis records what's normal (`data/history.csv`, `data/discovery.json`).
2. `python -m aegis.onboard --export plc_tags.csv`: draft `config/tags.json` from the PLC's tag export and what was seen on the wire. Review it.
3. `python -m aegis.learn --hours 168`: suggested rules from observed traffic. `python -m aegis.calibrate --history data/history.csv`: fit the twin to this plant.
4. Switch to `--mode enforce`.

## Measured numbers (this repo, not marketing)

**Evaluation on held-out seeds** (`python -m aegis.evaluate --seed-offset 200000`; seeds never looked at during development). 200 randomized attack episodes per guard: attackers who know the static rules (stepper, boundary-prober, weather-timed) going for caustic water, no disinfection, chlorine overdose, draining the clearwell, or cycling equipment. Plus 30 episodes of a simulated operator. Ground truth from the simulated "true" plant; an attack counts only if it caused harm or made it clearly worse than the same weather with no attacker. **Nobody responds to alarms in these runs**, which overstates harm.

| Held-out seeds 200000–200199 | Static rules only | Rules + digital twin |
|---|---|---|
| Attacks that made the water unsafe, standard simulator | 56% (113/200) | **31%** (62/200) |
| Same, high-fidelity simulator (physics the twin gets wrong) | 57% (114/200) | **33%** (66/200) |
| caustic / no disinfection (standard) | 32/35, 31/39 | **10/35, 10/39** |
| chlorine overdose / equipment cycling | 0/39, 0/34 | 0/39, 0/34 |
| clearwell drain | 50/53 | 42/53. **Not stopped**: the twin's early warning comes a median **151 min** before harm vs 13 min for the alarm |
| Operator writes blocked by the twin (standard / high-fidelity) | — | 9 / 9: **3 / 2 false**, 6 / 7 justified |

The previous held-out run (seeds 100000+, before Round 7) had the twin blocking 21 operator writes, **14 of them false**. Round 7 cut that without losing protection (`docs/JUDGE_ROUNDS.md`). Development seeds always looked better than held-out ones, which is why only held-out results are reported. Full output: `docs/eval/`.

| Other measurements | Result | How to reproduce |
|---|---|---|
| Latency added per write, static checks | p50 0.25 ms, p99 0.55 ms | `python scripts/bench.py` (cloud x86 VM, Python 3.13) |
| Latency added per write, with digital twin (5-model ensemble) | p50 13.5 ms, p99 21 ms; time budget 500 ms, then static fallback | same |
| Reads | +0.04 ms (pass through) | same |
| Integrity monitor, 20 × 10 h runs per simulator | 0 false alarms; hidden lye attack caught 20/20, 77–84 sim-min | `docs/ARCHITECTURE.md` |
| Random-traffic safety invariants | 20,000 random requests, 0 violations | `AEGIS_FUZZ_N=20000 pytest tests/test_invariants.py` |
| Parser robustness | 50,000 random PDUs, 200 malformed frames | `tests/test_protocol.py` |
| AI red team (scripted maximally gullible model) | tried unsafe in 7/8 cases, 0 reached the PLC; 2/2 "persuade the operator" replies flagged | `tests/test_redteam.py`; real model: `python -m aegis.redteam` |

## Done / not done (honest status)

| Item | Status |
|---|---|
| Guard checks: function, flood (label + IP), allowlist, range, step, ramp, interlock, permit, twin predict, unusual | ✅ built + tested |
| All write function codes incl. FC 22/23 bypass attempts; coils | ✅ tested with our client and with pymodbus |
| Gateway in front of a **third-party** Modbus server (pymodbus) with pymodbus and libmodbus (`mbpoll`) clients | ✅ tested (`tests/test_interop.py`) |
| Unit-ID routing for TCP-to-serial gateways | ✅ tested |
| Digital twin: chemistry, forecasts, live accuracy | ✅ tested against our simulator **and** a high-fidelity simulator with physics the twin gets wrong. ⚠️ **Not validated against a real plant** |
| Integrity monitor (lying PLC), early warnings, calibration | ✅ tested on both simulators (0 false alarms in 40 × 10 h runs; hidden attack caught in 20/20) |
| Dashboard accounts, roles, CSRF, lockout | ✅ tested |
| Propose → approve AI flow with twin forecasts, re-check at apply time | ✅ tested with scripted fake LLMs |
| AI copilot against a real model (Groq) | ⚠️ **not yet run with a real key** |
| Twilio SMS/call | ⚠️ request format tested against a mock; **not yet sent to a real phone** |
| OpenPLC / real hardware | ⚠️ **not tested** (the sandbox this was built in blocked OpenPLC's installer). pymodbus is the third-party stand-in |
| Protocols other than Modbus TCP (DNP3, EtherNet/IP, S7, Modbus RTU serial) | ❌ not built |
| HTTPS for the dashboard | ⚠️ set `AEGIS_HTTPS=1` behind a TLS reverse proxy; not built in |
| TLS on Modbus (Modbus/TCP Security) | ❌ not built |

## Demo script (3 minutes)

Sign in as **engineer**, type PIN **2468**, press **▶ Guided demo**. Each step shows what to say; press *Run step*, talk over the result, press *Next step*.

1. **The plant (15s)**: "This is a small town's water plant. Its controller speaks Modbus, a protocol from 1979 with no passwords."
2. **Without Aegis (25s)**: guard off, Oldsmar attack (lye 100 → 11,100). Chemistry is fast-forwarded until the pH alarm.
3. **With Aegis (20s)**: same attack blocked with the reason and an operator alert; the same attack hidden in Mask Write (FC 22) also blocked.
4. **Rules aren't enough (50s)**: algae bloom; a routine +50 lye change passes every static rule and the twin blocks it (pH 9.5 within an hour); early warning shows; cutting lye to 0 is accepted as a corrective override.
5. **AI (30s)**: poisoned work order; the AI can only propose, and Aegis pre-checks the proposal. Needs `GROQ_API_KEY`; if the model refuses the injection, say so: you can't count on the model refusing, which is why the guard exists.
6. **Lying controller (25s)**: malware inside the PLC doses lye secretly; Aegis notices the water no longer matches the chemistry of what it approved.
7. **Evidence (15s)**: tamper-evident log, incident report with ATT&CK mapping. "No new hardware, no PLC replacement: one box in front of what small utilities already own."

## Q&A prep

- **"Industrial firewalls already exist."** Yes. Tofino's Modbus enforcer and similar deep-packet-inspection firewalls check function codes and register ranges; they're a real competitor. They don't model the process, so they can't tell that a legal-looking lye step ends in caustic water. They also aren't built for AI writers: propose/approve, forecasts on proposals, a record of what the AI tried.
- **"If the government couldn't fix this, how can you?"** The government's fix was a rule, and it was withdrawn. The technical part (check every command before the PLC) is understood; what's missing is something cheap and simple enough for a utility with 2–5 staff. Monitor mode plus learn-normal is for exactly that.
- **"Is your chemistry real?"** It's the standard carbonate-system charge balance and a mixed-tank model, with simplifications listed above. Accuracy is measured against a simulator that deliberately differs from the model, not against itself. It hasn't been validated on a real plant.
- **"What if the attacker bypasses the guard?"** In deployment the PLC is only reachable through the guard (network segmentation), and `python -m aegis.exposure` checks that from other machines (including EtherNet/IP on 44818). A bypass that still happens shows up as setpoints changing behind Aegis's back (integrity monitor). If the attacker is *on* the guard box, all bets are off, which is why the audit log can be keyed and checkpointed off-box.
- **"Your evaluation grades the twin against your own simulator."** Partly true, so we built a second simulator with physics the twin gets wrong (more baffles, faster degassing, cold water, a quantized lye pump, analyzer lag). The first version false-alarmed in 11 of 20 runs against it; we found why and fixed it (`docs/JUDGE_ROUNDS.md`, Round 2). Neither replaces a real plant.
- **"What does the July 2026 attack wave have to do with this?"** FBI/EPA, 30 July 2026: attackers took over internet-facing water PLCs in at least seven states, causing loss of pressure and flooding. Their first recommendation: put PLCs behind a secure gateway. Aegis is that gateway, plus physics. Caveat: those were Rockwell MicroLogix PLCs, which speak EtherNet/IP as well as Modbus TCP; Aegis only parses Modbus today.
- **"Can't an attacker pretend to be the operator?"** Yes: Modbus unit IDs are labels, and an attacker on the HMI PC *is* the operator as far as Modbus can tell. That's why the rules apply to everyone, flood limits count per IP, critical commands need a permit created on the dashboard, and a safe-hold can only be released with a login. We evaluate this case separately (`--attacker hmi`).

## Docs

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): how each part works, and the chemistry.
- [`docs/JUDGE_ROUNDS.md`](docs/JUDGE_ROUNDS.md): adversarial review rounds: brutal judge questions and what changed in response.
- [`docs/BUSINESS.md`](docs/BUSINESS.md): why now (July 2026 FBI/EPA alert on water PLC attacks in 7 states), who pays, competitors, honest gaps.
- [`docs/STANDARDS.md`](docs/STANDARDS.md): mapping to IEC 62443-3-3, CISA CPGs and NIST CSF 2.0, including what Aegis does **not** meet.
- [`docs/eval/`](docs/eval/): full results of the evaluation harness.

## Credits

- [pymodbus](https://github.com/pymodbus-dev/pymodbus): third-party client/server for interoperability tests.
- [FastAPI](https://fastapi.tiangolo.com/), [uvicorn](https://www.uvicorn.org/), [httpx](https://www.python-httpx.org/), [pytest](https://pytest.org/), [Playwright](https://playwright.dev/) (screenshots).
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) technique IDs; [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) (LLM01).
- Carbonate chemistry: standard aquatic-chemistry constants (pK1 6.35, pK2 10.33, HOCl pKa ≈ 7.5 at 25 °C).
- Reference testbeds studied: [GRFICS (Georgia Tech)](https://github.com/djformby/GRFICS), [SCADASim (CMU SEI)](https://www.github.com/cmu-sei/SCADASim).

MIT © 2026 Youssef Shaaban
