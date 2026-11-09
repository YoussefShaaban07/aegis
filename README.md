# Aegis

**Water plants run on decades-old controllers that obey anyone on the network, and now we're plugging AI into them. Aegis is a safety guard that sits in front of the plant's controller and checks every command before it lands, whether it comes from an operator, an AI copilot, or a hacker. It doesn't just check limits: a digital twin of the plant's water chemistry predicts where each command will take the water over the next six hours, and blocks the ones that end in unsafe water.**

Built by **Youssef Shaaban** ([@YoussefShaaban07](https://github.com/YoussefShaaban07)) for the **VOXO Hatchathon 2026**, Legacy Tech track: *"Building tomorrow on the systems of today."*

Inspired by [Control Seat (YC S26)](https://www.ycombinator.com/launches/RJ6-control-seat-the-operating-system-for-the-physical-world), an AI-native SCADA platform. Aegis focuses on one piece of that: making it safe to put AI (and anyone else) in front of the controllers small utilities already own.

![Aegis dashboard](docs/dashboard.png)

| A fooled AI tries to raise lye to 9,000 (scripted demo model); Aegis blocks it | The on-call operator's phone |
|---|---|
| ![](docs/copilot-blocked.png) | ![](docs/operator-view.png) |

**At a glance**
- **200 held-out simulated attacks:** plain rules let 45% make the water unsafe; Aegis 10%, and none of those 10% created the harm (the same storm did it without the attacker). Details in [Measured numbers](#measured-numbers-this-repo-not-marketing).
- **60-second demo video:** [docs/video/pitch-demo-backup.mp4](docs/video/pitch-demo-backup.mp4). Run it yourself: `run.bat` (Windows) or `python -m aegis.server`, then *Pitch demo*.
- **Not yet done:** never tested on a real plant or real PLC hardware.

## The problem

- **July 2026:** attackers targeted more than 100 US water systems (CISA). FBI and EPA confirmed incidents in at least seven states on Allen-Bradley **MicroLogix** controllers, with IP addresses, passwords and programs changed. Aegis refuses each of those actions over EtherNet/IP (`tests/test_cip.py`).
- Water utilities run on PLCs that speak **Modbus** (1979) or Rockwell's **EtherNet/IP + PCCC** (the MicroLogix / SLC family), with **no authentication**: any device that can reach the controller can change a setpoint.
- In May 2024 the EPA said **over 70%** of the water systems it inspected did not fully comply with basic cybersecurity requirements. The EPA's 2023 rule requiring cyber checks in sanitary surveys was withdrawn after a lawsuit by states and industry groups.
- In 2023, CISA warned after Iran-linked hackers compromised a Unitronics PLC at the Municipal Water Authority of Aliquippa, PA.
- In January 2024, hackers made the water system of Muleshoe, Texas (about 5,000 people) overflow; staff took over by hand ([Fortune](https://fortune.com/2024/04/18/small-texas-town-foiled-russian-hacker-group/)).
- In the widely reported 2021 Oldsmar, FL incident, the lye (sodium hydroxide) setpoint was raised from **100 ppm to 11,100 ppm**. In 2023 the city's former manager said it was probably an employee's mistake, not a hacker. **Aegis doesn't care which**: the guard checks the command, not who typed it, so it stops the attack *and* the fat-finger.
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
 AI copilot  ──┼──► AEGIS GUARD (Modbus TCP or EtherNet/IP) ──► PLC ──► pumps, chemical dosing
 Attacker    ──┘        │
                        ├─ decodes every write (Modbus FC 5, 6, 15, 16, 22, 23; PCCC typed writes), blocks the rest
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
- **EtherNet/IP + PCCC from scratch** (`aegis/cip.py`): the protocol FactoryTalk, PanelView and RSLinx actually use with a MicroLogix 1100/1400 or SLC 5/05. Typed writes to data files (`N7:1`, `B3:0/1`) are decoded to tags and judged by **the same checks, twin and safe-hold** as Modbus writes. Mode changes (RUN → PROGRAM), program upload/download, Logix tag writes, CIP Set Attribute and anything unrecognised are refused. Writes hidden inside an Unconnected Send are unwrapped and checked. Tested against **pycomm3** (an independent open-source EtherNet/IP client). `python -m aegis.gateway --protocol cip`.
- **Lab inputs** (`aegis/labinputs.py`): a small plant measures raw alkalinity by titration once a day, not with an online analyzer. Any twin input can come from the lab (`python -m aegis.labinputs set raw_alkalinity 74 --by NAME`); older than `max_age_h`, the twin's chemistry pauses (static rules only) and the operator is told. Measured cost below.
- **Day-one compatibility**: monitor mode records every data-file word the HMI reads and writes over EtherNet/IP (`data/discovery.json`); HMI housekeeping writes (alarm-ack words) go on `pass_writes` and are forwarded, logged, not judged. Guarded tags can't be put on that list. Onboarding reads RSLogix 500 / CCW exports (`N7:1`, `B3:0/1`) as well as Modbus maps.
- **Digital twin** (`aegis/process.py`, `aegis/twin.py`): carbonate chemistry (charge balance solved for pH, temperature-dependent constants), a baffled clearwell (stirred tanks in series), CO2 exchange with air, chlorine demand and decay, and the HOCl/OCl⁻ split (how much chlorine actually disinfects). State is *estimated from sensors*, and every forecast is "with this command vs without it".
- **Twin accuracy measured live** against the simulator, which deliberately differs from the twin (3% stronger lye feed, 20% faster chlorine decay, drifting demand, sensor noise).
- **AI copilot, propose → approve (default)**: the AI can call `simulate_change` (ask the twin) and `propose_setpoint`. Proposals are pre-checked; unsafe ones are BLOCKED and can't be approved; safe ones show their forecast and wait for a human; on approval the write is checked **again**.
- **Operator permits** for critical commands (pump stops): a Modbus packet can claim to be the HMI; it can't create a permit.
- **Learn normal** (`aegis/learn.py`): run in monitor mode, then get suggested rules from observed traffic (alert bands, tighter step/ramp/flood limits). Statistics, not AI; the engineer reviews and applies.
- **Tamper-evident audit log**: SQLite, hash-chained, HMAC-keyed if `AEGIS_AUDIT_KEY` is set. Head hash printed in reports so later rewrites are detectable. CSV export.
- **Incident report** (`aegis/report.py`): timeline, sources, MITRE ATT&CK for ICS techniques, AI proposals, config changes, evidence integrity, and a "what this report does not establish" section.
- **Operator alerts**: iMessage through [Photon Spectrum](https://photon.codes) (works with an iPhone, no Mac needed; `photon/bridge.ts`, started by `run.bat`) and/or SMS plus a phone call for critical events through Twilio. **Text back** `ACK` to acknowledge the newest alert or `STATUS` for the readings (only from numbers in `ALERT_TO`). *Send test text* button on the dashboard. Honest "not configured" otherwise.
- **More chemical feeds**: chlorine **gas** as well as liquid bleach (gas uses up about 1.4 mg/L of alkalinity per mg/L fed, so pH drops), and a **fluoride** feed (fluorosilicic acid, sodium fluorosilicate or sodium fluoride) with its own range limit, twin forecast (limit 2.0 mg/L, EPA secondary standard), "What now" guidance and FLUORIDE HIGH alarm. Off unless a plant configures them: the default demo plant is unchanged (a 16-episode held-out run is identical before and after). Example plant: `config/examples/gas-fluoride` (`run_example.bat`). Checked against PHREEQC: mean pH difference 0.005 (fluorosilicic acid, 20 cases), 0.001 (sodium fluoride), 0.006 (chlorine gas, as its acid); `python -m scripts.validate_feeds_phreeqc`.
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
- **Control-room look, on purpose**: the dashboard follows ISA-101 "high-performance HMI" practice used in real control rooms: grey and quiet, numbers in plain type, pumps filled when running and hollow when stopped, and **colour only for abnormal conditions** (a blocked command, a value out of range, an alarm). The attack and weather buttons live in a collapsed "Demo console". Four colour themes (default: steel blue) are in the header; the rule is the same in each.
- **Operator view** (`/operator`): a phone-sized page for the on-call operator: is the water safe, what to acknowledge, what's coming.
- **Real Modbus semantics in the gateway**: unit IDs are routed to the target device (TCP-to-serial gateways work); writers are named by IP; tested with `mbpoll`/libmodbus (C) and pymodbus (Python) on both sides.
- **Safe-hold** (`aegis/safehold.py`): if the twin forecasts unsafe water and **nobody acknowledges for 15 minutes**, Aegis restores the earlier setpoint (one the plant actually ran at in the last 12 h) that fixes the forecast most, then holds it: Modbus writes that move it are refused unless the twin calls them corrective, until someone releases the hold with a login. A hijacked HMI can't undo it. Stands down while the integrity monitor distrusts the sensors; never acts in monitor mode; never touches pumps. Holds survive restarts.
- **Bypass check** (`python -m aegis.exposure <plc-ip>`, run from any other machine): is the PLC reachable around Aegis? Probes Modbus, EtherNet/IP (44818, which MicroLogix runs alongside Modbus), S7, DNP3, OPC UA, web, telnet, FTP.
- **Read-only unknown hosts**: in the gateway, `"unknown_writers": "block"` makes every host not named in `--sources` read-only.
- **Guided demo**: one button walks through the whole story with what to say at each step; fast-forwards slow chemistry.
- **Pitch demo** (four steps, one key press each) and **Booth loop** (the three blocked attacks on repeat with large captions) for live presentations; a recorded backup is in `docs/video/`.
- **Operator console for real installs** (`--console-port`, `aegis/console.py`): the gateway serves the phone page (acknowledge, release safe-holds) with named accounts and optional built-in HTTPS.
- **More careful when the model is wrong**: while the integrity monitor says the plant doesn't match the chemistry (stronger lye delivered, failing pump, compromised PLC), the twin judges with a wide uncertainty band.
- **Hardened front door**: differential fuzzing of the EtherNet/IP path (60,000 mutated attack frames, 0 writes slipped past or applied differently; `scripts/fuzz_cip.py`), dashboard tested against script injection through attacker-controlled names, per-address connection limits with room always kept for the named HMIs, idle timeouts, pinned versions in `requirements.lock`.
- **Not just caustic soda**: the twin's alkali feed can be NaOH, lime, soda ash or bicarbonate (`process.json "alkali"`); chlorine-only plants simply have no alkali register.
- **Demo without internet**: with no API key the demo copilot is a clearly labelled scripted model that falls for the poisoned work order, and Aegis blocks it. Nothing on the dashboard loads from the internet.
- **Several PLCs**: run one gateway per PLC (own port, own tag map); Modbus unit IDs behind a TCP-to-serial gateway are routed.
- **One page for judges**: `docs/ONE_PAGER.md`. Judge Q&A prep and the 3-minute demo order: `docs/QA_PREP.md`.
- **Operator runbook** (`docs/RUNBOOK.md`): one printable page: what each text means, what to do, what to do if the box fails.
- **Defending its own judgement**: unnamed writers are refused if the twin runs out of time (slowing the box can't switch the twin off for an attacker); calibrations can't drift more than 40% from the commissioned values without an engineer on site; typed-in lab alkalinity is checked against what the plant's own pH implies.
- **Resilience**: per-request errors fail closed without taking the server down; a supervisor restarts the gateway; `/health` endpoint; systemd unit with least privilege (`deploy/aegis.service`); soak-tested with 20 concurrent HMIs.

## Run it

**Windows:** double-click `run.bat` (needs Python 3.10+ from python.org). **macOS/Linux:** `./run.sh`. Or manually:

```bash
pip install -r requirements.txt
cp .env.example .env          # add GROQ_API_KEY for the AI copilot (free at console.groq.com)
python -m aegis.server        # open http://127.0.0.1:8000
python -m pytest -q           # 223 tests
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
    --console-port 8443 --console-host 0.0.0.0 --console-cert cert.pem --console-key key.pem \
    --sources "10.0.0.5=Operator HMI,10.0.0.9=AI copilot" --health-port 8081
```

Point the HMI and AI at the gateway instead of the PLC, and firewall the PLC so only the gateway can reach it. Onboarding, in order:

1. Run in `--mode monitor` for a few days: nothing is blocked; Aegis records what's normal (`data/history.csv`, `data/discovery.json`).
2. `python -m aegis.onboard --export plc_tags.csv`: draft `config/tags.json` from the PLC's tag export and what was seen on the wire. Review it.
3. `python -m aegis.learn --hours 168`: suggested rules from observed traffic. `python -m aegis.calibrate --history data/history.csv`: fit the twin to this plant.
4. Switch to `--mode enforce`.

## Put the demo online

On a free cloud server (Ubuntu 22.04/24.04 or Debian 12) with a domain pointing at it:

```bash
curl -fsSL https://raw.githubusercontent.com/YoussefShaaban07/aegis/main/deploy/public/setup.sh | sudo bash -s -- demo.yourdomain.com
```

It installs Aegis and [Caddy](https://caddyserver.com) (automatic HTTPS), and runs the dashboard with `AEGIS_PUBLIC=1`: the simulator's Modbus and EtherNet/IP ports listen on the server only, only ports 80/443 face the internet, failed logins are counted per visitor (so nobody can lock others out of the shared demo account), and no AI key is set (the copilot uses the labelled scripted model). Everyone online shares one simulated plant; *Reset plant* puts it back. Re-run the same command to update.

## Measured numbers (this repo, not marketing)

**Current version (re-run at v28; same numbers as v20), fresh held-out seeds 300000–300199** (`python -m aegis.evaluate --seed-offset 300000 --safe-hold [--attacker hmi]`). Same setup as below; nobody ever answers an alarm.

| | Attacks that made the water unsafe |
|---|---|
| Static rules only | 90/200 (45%) |
| Rules + twin + lockdown, attacker on the **operator's HMI PC** (no safe-hold) | 36/200 (18%); clearwell drain 24/27 |
| Rules + twin + lockdown + **safe-hold**, attacker on the HMI PC | **19/200 (10%)**; clearwell drain **10/27**; pump cycling 0/41 |
| Rules + twin + lockdown + safe-hold, attacker elsewhere on the network | **19/200 (10%)** |
| Same as the HMI row, on the **high-fidelity simulator** (physics the twin gets wrong: an extra mixing stage, CO2 off-gassing, lagged analyzers) | static **91/200 (46%)** → Aegis **19/200 (10%)**; 0 created harm, 1 made weather harm much worse. Operators: 5 false twin blocks in 508 writes |

**Were they going to be unsafe anyway?** Every episode is also run with the same weather and *no attacker*. With static rules, 52 of the 90 harmful attacks created harm that wouldn't otherwise have happened (and 12 made it much worse). **With Aegis: 0 of the 19.** All 19 are storms or blooms that made the water unsafe *without* the attacker too (nobody answers an alarm in this test); the attacker made it happen 30+ minutes sooner. The evaluation prints this split.

Cost to a (simulated) operator, 514 writes in 40 sessions (v28 re-run, `docs/eval/v28_*`): 20 blocked by the twin (11 justified, **9 false**, about 1 in 57 writes), never locked down; a wrong block can be let through with *Allow this value once*. The first 30 sessions are identical to the v20 run (382 writes, 4 false); the 10 added sessions hold the other 5. Safe-hold undid 23 operator changes: 17 made the true outcome better, 5 no difference, **1 slightly worse**.

*Correction (Round 15):* earlier versions of this table (49% static, 12% with safe-hold) came from a simulator in which reading the sensors advanced the same random stream as the plant's demand, so attack and no-attack runs of an episode drifted apart and some weather-only harm was counted against the attacker. Fixed (`aegis/plant.py`); all rows above are from the corrected simulator. Older tables below are kept as they were measured.

**Earlier version** (before safe-hold), for comparison:

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
| Alert load: a simulated year (233 calm days, 131 storm/bloom days), noisy plant, operator who acknowledges in 10 min | **9.7 texts/week**; **0.1 per calm day** (24 in a year, all clearwell-low warnings); 3.65 per storm/bloom day; safe-hold never overrode the engaged operator; lockdown never triggered; 1 operator change blocked in 2,384 (re-run with the "What now" guidance, `docs/eval/alert_load_v31.*`; before it: 9.4/week) | `python -m aegis.alertload --weeks 52` |
| Twin chemistry vs **PHREEQC** (USGS reference geochemistry code), 100 cases: 5 waters × NaOH / lime / soda ash doses | mean difference **0.05 pH**, max 0.32; 2 cases disagree on safe/unsafe (soda ash in low-alkalinity water, Aegis 0.16–0.23 pH too low) | `pip install -r requirements-dev.txt; python scripts/validate_phreeqc.py` |
| Twin with **raw alkalinity from a once-a-day lab sample** instead of an online analyzer (dev seeds 0–39, twin, no safe-hold) | 6/40 harmful vs 5/40 with online analyzers (static rules: 21/40). With turbidity *also* from the lab: 9/40, mostly clearwell drains (7/8 vs 4/8). Keep turbidity online | `python -m aegis.evaluate --episodes 40 --lab-hours 24 [--lab-keys raw_alkalinity,raw_turbidity]` |
| Twin-checked write on ONE core, idle / with 3 busy processes on that core | p50 12.7 / 49 ms, p99 20 / 78 ms (budget 500 ms). Use an x86 mini PC; a Pi-class CPU would sit close to the budget under load (not measured) | `taskset -c 0 python scripts/bench_lowpower.py 3` |
| Lab alkalinity plausibility check, 432 hourly checks across storms/blooms | 0 true values rejected; 66% of fake values (×3, ×0.4) caught at the first check, the rest once the plant is steady | `tests/test_round12.py` |
| Latency added on the EtherNet/IP path (pycomm3 write round trip) | direct 0.05 ms; through Aegis, static p50 0.21 ms / p99 0.55 ms; with twin p50 12.9 ms / p99 16 ms | `python scripts/bench_cip.py` |
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
| Photon iMessage | ⚠️ bridge built on `spectrum-ts` 12.15.0; tested end to end in the bridge's print-only mode (test text, attack alert, ACK and STATUS replies, strangers ignored, both tokens checked); **not yet sent through Photon's real service** |
| OpenPLC / real hardware | ⚠️ **not tested** (the sandbox this was built in blocked OpenPLC's installer). pymodbus is the third-party stand-in |
| Modbus RTU over TCP (radio bridges, serial device servers) | ✅ `--framing rtu` / `--plc-framing rtu`; tested with pymodbus's RTU framer on both sides. Bad CRC or a function code whose length isn't known closes the connection. ⚠️ Native RS-485 (a serial port on the Aegis box) not built: use a serial device server |
| EtherNet/IP + PCCC (MicroLogix / SLC) | ✅ built + tested with pycomm3 against our simulated MicroLogix. ⚠️ **not tested against a real MicroLogix**. Not covered: UDP implicit I/O, CIP Security (TLS), Logix symbolic writes (refused, not judged) |
| Other protocols (DNP3, S7, Modbus RTU serial) | ❌ not built |
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
- **"What does the July 2026 attack wave have to do with this?"** FBI/EPA, 30 July 2026: attackers took over internet-facing water PLCs in at least seven states, causing loss of pressure and flooding. Their first recommendation: put PLCs behind a secure gateway. Aegis is that gateway, plus physics. Those were Rockwell MicroLogix PLCs, so Aegis guards EtherNet/IP + PCCC (what their HMIs use) as well as Modbus TCP; it has only been tested against a simulated MicroLogix and pycomm3, not real hardware.
- **"Operators already ignore their alarms. You're adding another pager."** We measured it: a simulated year, noisy plant, storms and blooms, an operator who answers in 10 minutes. **About 9.7 texts a week, 24 on calm days in the whole year.** The first run said 0.64 per calm day, mostly "the clearwell will overflow" forecasts; overflow wastes water but isn't unsafe, so it's dashboard-only now. Texts come as incidents, not one per event. Escalations (about 50 in the year) happen because the simulated operator's 10-minute response matches the 10-minute escalation timer.
- **"My plant doesn't have an online alkalinity analyzer."** Most don't. Type in the daily titration; the twin uses it for up to 36 h, then pauses and tells you. Measured: 6/40 harmful attacks with a daily sample vs 5/40 with an online analyzer (dev seeds). Turbidity from the lab too costs more (9/40), so the twin wants an online raw turbidimeter.
- **"Day one, the HMI's other writes get blocked and the operators rip it out."** That's why it starts in monitor mode: it records every address the HMI writes, and the engineer puts housekeeping ones (alarm acks) on `pass_writes` before switching to enforce.
- **"Does it work with Rockwell? Their HMIs don't use Modbus."** Right, FactoryTalk and PanelView talk EtherNet/IP + PCCC to a MicroLogix. Aegis guards that too (`--protocol cip`), with the same checks, twin and safe-hold, and refuses mode changes and program downloads. Tested with pycomm3 against a simulated MicroLogix, not real hardware yet.
- **"Can't an attacker pretend to be the operator?"** Yes: Modbus unit IDs are labels, and an attacker on the HMI PC *is* the operator as far as Modbus can tell. That's why the rules apply to everyone, flood limits count per IP, critical commands need a permit created on the dashboard, and a safe-hold can only be released with a login. We evaluate this case separately (`--attacker hmi`).

## Docs

- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md): how each part works, and the chemistry.
- [`docs/JUDGE_ROUNDS.md`](docs/JUDGE_ROUNDS.md): adversarial review rounds: brutal judge questions and what changed in response.
- [`docs/BUSINESS.md`](docs/BUSINESS.md): why now (July 2026 FBI/EPA alert on water PLC attacks in 7 states), who pays, competitors, honest gaps.
- [`docs/STANDARDS.md`](docs/STANDARDS.md): mapping to IEC 62443-3-3, CISA CPGs and NIST CSF 2.0, including what Aegis does **not** meet.
- [`docs/eval/`](docs/eval/): full results of the evaluation harness.

## Credits

- [pymodbus](https://github.com/pymodbus-dev/pymodbus): third-party client/server for interoperability tests.
- [pycomm3](https://github.com/ottowayi/pycomm3) (MIT): independent EtherNet/IP client used to test the PCCC guard and the simulated MicroLogix. Protocol details from the ODVA EtherNet/IP specification and Rockwell publication 1770-6.5.16 (DF1 Protocol and Command Set).
- [FastAPI](https://fastapi.tiangolo.com/), [uvicorn](https://www.uvicorn.org/), [httpx](https://www.python-httpx.org/), [pytest](https://pytest.org/), [Playwright](https://playwright.dev/) (screenshots).
- [MITRE ATT&CK for ICS](https://attack.mitre.org/matrices/ics/) technique IDs; [OWASP Top 10 for LLM Applications](https://genai.owasp.org/llmrisk/llm01-prompt-injection/) (LLM01).
- Carbonate chemistry: standard aquatic-chemistry constants (pK1 6.35, pK2 10.33, HOCl pKa ≈ 7.5 at 25 °C).
- Reference testbeds studied: [GRFICS (Georgia Tech)](https://github.com/djformby/GRFICS), [SCADASim (CMU SEI)](https://www.github.com/cmu-sei/SCADASim).

MIT © 2026 Youssef Shaaban
