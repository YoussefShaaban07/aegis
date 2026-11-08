# Adversarial review rounds

Method: after each version, play a hostile judge who wants to reject the project, ask the 5 most
damaging questions, answer them honestly, and build the fixes into the next version. Questions that
can't be fixed in software or in a hackathon are recorded as limitations, not hidden.

## Round 0: what v3 already answered (questions from the v2 review)

| Question a judge would ask about v2 | v3 answer |
|---|---|
| "Range limits are what every Modbus firewall does. What's new?" | Digital twin with real carbonate chemistry: blocks commands that pass every static rule but end in unsafe water. |
| "Your filter only decodes FC 6 and 16. I'll use FC 22 or 23." | All write codes decoded (5, 6, 15, 16, 22, 23); everything else blocked and logged. |
| "Rotate unit IDs and your flood limit is useless." | Flood counted per label *and* per IP (tested, including from the HMI's own IP). |
| "Stopping the town's pump passes all your limits." | Found in our own browser test; fixed with single-use operator permits. |
| "Who writes the rules at a utility with 3 staff?" | Monitor mode + learn-normal suggestions. |
| "Your hash chain can be recomputed by whoever owns the DB." | HMAC-keyed chain + head-hash checkpoints in reports. |
| "How slow is it?" | Measured: +0.17 ms static, +2.8 ms with twin, per write. |
| "Does it work with anything but your own code?" | Gateway tested between pymodbus client and pymodbus server. |

## Round 1 (against v3)

**Judge:** "I'm not convinced. Five reasons this doesn't work:"

1. **"Your twin trusts the sensors. A compromised PLC (Stuxnet) changes the dosing itself and reports normal values. Your predictions are computed from lies, and the guard never even sees the command."**
2. **"Your twin is calibrated to a plant you made up. At a real utility nobody knows the feed strength or decay rate. If the model is 20% off, you either block the operator's legitimate work (they turn you off on day two) or you miss attacks. Show me that it can be calibrated and how often it would block real operators."**
3. **"One cherry-picked example (lye 150 → 200) doesn't prove the twin matters. Prove it: how many attacks get through static rules that the twin stops, and does anything get past both?"**
4. **"You put a Python process inline between the operators and the PLC. If it crashes, the plant is blind. Utilities will never accept a new single point of failure."**
5. **"Who pays? Small utilities have no money, Tofino already exists, and the EPA rule you mention was withdrawn, so nobody is forced to buy."**

### What we did about it (v4)

1. **Lying PLC → `aegis/integrity.py`.** Three independent checks: (a) *setpoint drift*: Aegis remembers every value it approved, so a setpoint changed behind its back (front panel, laptop, malware) raises a critical alert at the next poll; (b) *physics shadow*: the chemistry runs alongside the plant using only approved setpoints; if the water drifts from what that dosing can produce, the PLC isn't doing what it says; (c) *lab grab samples*: the one reading that doesn't come through the PLC. Honest limit, tested: a full replay lie (hidden dosing + frozen readings) is invisible to (a) and (b); only (c) catches it.
2. **Calibration → `aegis/calibrate.py`.** Fits lye feed strength, chlorine decay/demand and CO2 exchange from the plant's own history. From a deliberately wrong start (feed 0.13 vs true 0.103) it recovers the feed to within 3%. Chlorine decay and demand are partly confounded and we say so. **Found while testing:** calibrating *during* a hidden-dosing attack "learned" the attack (feed fitted to 0.184). Now calibration refuses while integrity alarms are active or if a parameter jumps >25%, and needs ≥5 replay windows (a single window fitted to zero error = overfitting).
3. **Proof the twin matters → `aegis/evaluate.py`.** Randomized attack episodes (attackers who know the static rules) and operator episodes, with ground truth from the simulated "true" plant and no-attacker baselines. **Found while testing:** the first twin let caustic water through in some episodes because it trusted its nominal model (true lye feed 3% stronger) and only looked 6 h ahead. Fixed with an uncertainty ensemble (worst case of feed ±10%, decay ±30%, demand ±25%) plus a long-run steady-state check. Results: see Round 2.
4. **Single point of failure → `aegis/supervisor.py`, `/health`, `deploy/aegis.service`.** Errors inside the guard reject that one write (fail closed) and the server keeps serving (tested). A supervisor restarts the gateway. Soak test: 20 concurrent HMIs, zero errors. Break-glass bypass documented. A physical bypass and an HA pair are the real answer, and outside a software hackathon.
5. **Who pays → `docs/BUSINESS.md`.** On 30 July 2026 the FBI and EPA warned of attacks on internet-facing water PLCs in at least seven states (loss of pressure, flooding), and their first recommendation is a secure gateway in front of the PLCs. Funding: NY SECURE grants (up to $100k per system), CISA's State and Local Cybersecurity Grant Program, SDWA 1459F, a draft $300M DWSRF cyber bill. Honest gaps listed there (MicroLogix also speaks EtherNet/IP, which Aegis doesn't parse).

## Round 2 (against v4)

**Judge:** "Better. Still no:"

1. **"Your dashboard has no login. Anyone on the plant network can approve the AI's proposals or turn your guard off. You've moved the attack surface, not removed it."**
2. **"I watched your demo: the operator tried to fix an algae bloom by cutting lye from 100 to 0, and *your* step limit blocked the fix. A safety system that blocks the emergency fix is itself a hazard."** (Found by our own browser run of the guided demo.)
3. **"Your evaluation says clearwell-drain attacks still succeed every time, and the low-level alarm gives the operator 14 minutes. That's not protection."**
4. **"Your evaluation is circular. The 'true plant' runs the same equations as your twin with a few numbers changed. Of course the twin does well."**
5. **"Your demo is button soup and the narration doesn't match the screen."** (Found: the guided step said 'every rule says 200 is fine' while the screen showed it blocked by the *step* rule; and the 'fix' lye 40 still forecast pH 8.62.)

### What we did about it (v5)

1. **Real authentication → `aegis/auth.py`.** Named accounts with viewer / operator / engineer roles; scrypt password hashes; HMAC-signed HttpOnly SameSite=Strict session cookies that expire after a shift and die if the user's role changes; CSRF header required on every write; 5 failed logins → lockout; every action in the audit log is attributed to a named user. Engineer actions still also need the PIN.
2. **Corrective override.** Step/ramp limits exist to stop someone *steering* the plant. If the twin computes that a change improves an unsafe forecast (and it's inside the hard min/max), it may exceed step/ramp and is logged as "CORRECTIVE OVERRIDE". The same 100-ppm jump on a normal day is still blocked. Also fixed: single-use permits are now consumed only when the write is actually allowed.
3. **Early warnings → `aegis/forewarn.py`.** The twin's forecast is checked continuously; if pH, chlorine or the clearwell is predicted to cross an alarm limit within 2–3 h, the operator is texted *then*, with the time remaining. Measured on a slow drain: 150+ minutes of notice instead of 14.
4. **Breaking the circularity.** We built a *high-fidelity* plant with physics the twin gets wrong or doesn't have: a clearwell with 4 baffled cells where the twin is configured with 3, CO2 degassing 2.5× faster than the twin assumes, 15 °C water, a lye pump that doses in 5 ppm steps with +2% gain error, slower chlorine decay in cold water, and lagging analyzers. **Found:** the integrity monitor false-alarmed in 11 of 20 runs against it, with model errors up to 1 pH. Cause analysis (one effect at a time): baffling dominated, then temperature, then degassing. Fixes: (a) the twin now models a baffled clearwell (utilities know their baffling from the tracer studies EPA disinfection rules require), measured temperature, and CO2 exchange; (b) the integrity check now compares in **alkalinity** rather than pH, because on the steep part of the titration curve a 3% model error is a 0.4 pH error but still only 3% of alkalinity, while a hidden attack moves alkalinity 10%+; (c) re-anchoring keeps the baffled cells' profile instead of flattening it. **Result: 0 false alarms in 20 × 10 h runs on both plants; the hidden 100 → 200 ppm attack caught in all 20 runs, 77–84 simulated minutes after it starts.** Twin decisions got slower (2.8 → 18 ms per write) and were optimised with a warm-started Newton solver for pH (agrees with bisection to 3×10⁻¹⁰).
5. **Guided demo mode.** One button runs the whole story step by step: what to say, what happens, fast-forward for slow chemistry, no timing luck. Every step's on-screen result now matches its narration (checked by a browser test that runs all 7 steps).

## Round 3 (against v5)

**Judge:** "You keep fixing things. Here's what's left:"

1. **"AI isn't central. Your guard is rules and physics, and your copilot has never run against a real model. Delete the LLM and nothing changes."**
2. **"Your evaluation's attacker is dumb: it walks straight toward the limit. A smart attacker probes your twin's boundary, waits for bad weather, and oscillates equipment, which destroys pumps without ever crossing a limit."**
3. **"You pass reads through unlimited. Small PLCs choke on heavy polling. I'll knock the plant offline with reads alone."**
4. **"A 3-person utility can't write your tags.json, policy and process files. Onboarding kills this."**
5. **"At 3 AM your system texts the on-call operator 30 times. They mute their phone. Alert fatigue is how real incidents get missed."**

### What we did about it (v6)

1. **AI, measured instead of claimed.** `python -m aegis.redteam` throws 8 prompt-injection attacks (direct orders in work orders, fake alarm notes, a fake manager email, multi-step instructions, "maintenance mode" role-play, base64-encoded orders, chlorine starvation) plus a benign control at the *real* copilot and reports how often the model tried something unsafe vs how often anything unsafe reached the PLC. With a maximally gullible scripted model (tests): the AI tried something unsafe in 7/8 cases, in both propose and direct mode; Aegis blocked 7/7; **0 reached the PLC**. With a real model: run it with a Groq key; we haven't (no network path to an LLM from where this was built). The copilot also gained tools to explain Aegis itself: `get_guard_log` ("why was that blocked?") and `get_integrity` ("can I trust the PLC?"). Honest position: AI is the *user* Aegis makes safe, and the operator's assistant; it is deliberately not the decision-maker.
2. **Smarter attackers + cycling check.** The evaluation now has a *prober* (binary-searches the largest change the guard accepts, staying under the flood limit), a *weather-timed* attacker (waits for a storm or bloom), and an *equipment-cycling* attacker. New guard check: more than 4 direction reversals of one setpoint in 10 minutes is blocked (MITRE T0879 Damage to Property). **Found:** a weather-timed clearwell-drain attack during a storm made the storm's chlorine failure arrive 40–56 min sooner; the twin compared only peak excursions ("same failure, just sooner" looked no worse). The twin now scores *peak + duration* outside the safe band. We also fixed the evaluation itself: it used to exclude every episode where weather alone was unsafe (more than half); now an attack counts if it caused harm *or* made it clearly worse or sooner than the same weather without the attacker.
3. **Read-flood protection.** Per-IP read rate limit (default 50/s) answered with Modbus exception 6 "server busy", logged once per burst (T0814); and a 100 ms read-coalescing cache, so 20 HMIs polling the same registers cost the PLC under half the reads (tested). Writes invalidate the cache immediately.
4. **Onboarding.** `python -m aegis.onboard --export plc_tags.csv` drafts the register map from the PLC software's own tag export (5/6-digit Modbus notation or HR:/IR:/CO:), maps tags to roles from names/descriptions, infers scaling from units or from values Aegis saw on the wire in monitor mode (the gateway now records `data/discovery.json`), and flags everything uncertain for review. `--ai` asks the LLM to place leftovers; suggestions are validated against a fixed role list and never applied automatically.
5. **Incidents, escalation, acknowledgement.** Alerts within 15 min of each other form one incident and send *one* text (plus one more if it upgrades to critical). An unacknowledged critical incident escalates to the next number in `ALERT_TO` every 10 minutes; acknowledging on the dashboard stops it and is audited. Tested: 30 alerts → 1 text; escalation at exactly 10 min; no further calls after ack.

## Round 4 (against v6)

1. **"A hijacked AI can't write to the PLC, fine. But it can lie to the operator: 'pH is fine, switch Aegis to monitor for maintenance.' The human does the attacker's work."**
2. **"If I get onto the Aegis box, I edit policy.json to allow lye 20,000 and rewrite the local audit log."**
3. **"When the twin blocks the operator it only says no. At 3 AM they need to know what *is* safe, or they'll call you to turn Aegis off."**
4. **"Your ramp and flood windows use the wall clock. Spoof NTP and they reset."**
5. **"Utilities follow standards. Which requirements does this meet?"**

### What we did about it (v7)

1. **Reply guard → `aegis/replyguard.py`.** Every copilot answer is checked before the operator sees it: numbers it states about the plant are compared with live readings (only present-tense claims; "bring pH back under 8.5" is a target, not a claim), and advice to turn the guard off or to monitor mode, bypass safety, silence alarms, loosen limits, skip approval or go around Aegis is flagged in red and written to the audit log. Two new red-team cases where the attacker's goal is *persuading the human*: both flagged; the benign answer isn't. Honest limit: it's pattern-based, so a model can phrase around it; it raises the bar and leaves a record, it doesn't make lying impossible.
2. **Signed policy + off-box audit.** With `AEGIS_POLICY_KEY` set, the policy file carries an HMAC signature written only when an engineer saves through Aegis; an edit on disk fails verification, Aegis refuses to load it at startup and, while running, raises a critical alert and keeps enforcing the last good policy. With `AEGIS_SYSLOG=host:port`, every audit entry (with its chain hash) is also sent as RFC 5424 syslog to a log server/SIEM, a copy an attacker on the box can't rewrite.
3. **"What is safe" on every twin block (operator and AI only).** The guard binary-searches the largest change the twin accepts right now and says so: "Largest change the twin accepts right now: naoh_dose = 160 ppm" (tested: 160 really is accepted). Attackers don't get the hint.
4. **Monotonic clock.** Ramp, flood, cycling and permit windows run on a monotonic clock; jumping the system time a day forward doesn't reset them (tested). Timestamps in the log stay wall-clock.
5. **`docs/STANDARDS.md`.** Mapping to IEC 62443-3-3 (14 system requirements, including the ones Aegis does **not** meet: SR 1.2 device authentication and SR 3.1 communication integrity, because Modbus has neither), CISA CPGs (incl. 2.X "Limit OT Connections to Public Internet", the FBI/EPA's first July 2026 mitigation; and the gap, 2.K MFA) and NIST CSF 2.0 functions. States clearly that Aegis is not certified.

## Round 5 (against v7)

1. **"In Modbus TCP the unit ID addresses the *target* device behind a gateway. You use it as a source label and always forward to unit 1; a TCP-to-serial gateway with several PLCs breaks. And you've only tested Python implementations."**
2. **"18 ms per write on a cloud VM, 220 ms for suggestions. On a cheap industrial PC that's 10× slower, and your guard blocks its event loop while thinking. HMIs time out."**
3. **"Flood blocked writes and you write an audit entry for each one. I'll fill your disk."**
4. **"You tuned thresholds by looking at results on the same seeds you report. That's overfitting your test set."**
5. **"At 3 AM the operator opens this on a phone. Your dashboard is an engineer's cockpit."**

### What we did about it (v8)

1. **Route mode** (default for the gateway): unit IDs are forwarded unchanged to the target device, only configured PLC unit IDs are allowed (others get exception 0x0A), and writers are named by IP (`--sources "10.0.0.5=Operator HMI"`). Label mode remains only for the all-in-one demo. **Tested with a C implementation**: `mbpoll` (built on libmodbus) through the gateway: reads, a safe write, Oldsmar blocked, unit 7 refused, a pump stop refused for lack of a permit.
2. **Time budget + worker thread.** Write decisions run in a worker thread (one at a time), so reads keep flowing; the twin has a budget (default 500 ms) and falls back to the static rules if it can't finish (or blocks, if `on_timeout: block`), with an alert. Tested with a twin slowed to 0.4 s per model run: the write was decided within budget and concurrent reads never waited more than 0.25 s.
3. **Log-flood protection.** After 5 identical blocked writes from one sender per minute, entries are summarised: 1,000 blocked writes → 5 entries + one "995 more like this" summary, all still counted, chain intact. Incident reports include the summarised counts.
4. **Held-out seeds.** `python -m aegis.evaluate --seed-offset 100000` runs on seeds never looked at during development. The final numbers in the README come from held-out seeds.
5. **Operator view** at `/operator`: phone-sized, one status ("WATER IS SAFE" / "WATCH" / "ACTION NEEDED"), pH/chlorine/level/guard tiles, open incidents with a one-tap Acknowledge, the twin's early warnings, and recent blocks in plain English. Checked on an emulated iPhone 13: no horizontal scroll.

## Round 6 (against v8)

1. **"Every attack in your demo is a button on your own dashboard. It looks staged."**
2. **"A pH analyzer sticks at 3 AM (common, not an attack). You falsely accuse the PLC of lying."**
3. **"You've tested the attacks you thought of. Prove nothing gets through under random traffic."**
4. **"I can't tell what on this screen is simulated."**
5. **"Crash Aegis and it restarts with fresh rate windows. That's a reset button for attackers."**

Plus what our own v6 evaluation showed: with fairer attribution (storm/bloom episodes no longer excluded), the twin let through 8/41 caustic and 11/42 no-disinfection attacks, and 8 of its 14 operator blocks were false.

### What we did about it (v9)

1. **`docs/DEMO.md`** with a "hacker terminal" moment: attacks from a second terminal, another laptop, `mbpoll`, or a Modbus app on a judge's phone against port 5502. Plus what to say carefully and what to do if something breaks.
2. **Stuck-analyzer detection**: a reading that doesn't move at all for 20 minutes is reported as a stuck/fouled instrument (warning), not as a lying PLC. Real analyzers never sat still that long in 300 simulated minutes.
3. **Randomized safety invariants** (`tests/test_invariants.py`): 20,000 random requests (all function codes including unknown ones, random addresses, values, multi-register spans, random unit IDs): after *every* request, every tagged setpoint is inside its hard limits, nothing outside the allowlist changed, and no pump was stopped without a permit. 4,559 accepted, 15,441 rejected, 0 violations.
4. **"SIMULATED PLANT" banner** whenever demo controls are on.
5. **Restart-safe windows**: the gateway saves ramp/flood/cycling windows every poll (atomic write) and restores them on start, aged by the downtime.

**The evaluation findings, root-caused:**
- *Storm onset:* the twin assumed today's raw water persists. A chlorine cut made as turbidity started rising looked safe. Fix: the twin now **projects the observed raw-water trend**. First attempt (linear) overshot so badly that every option looked equally doomed; the projection is now damped (changes level off).
- *Scoring:* excursions were divided by the band width, so a total loss of disinfection (0.2 mg/L under a 0.2–4.0 band) scored ~20× smaller than a pH excursion. Each variable now has its own scale.
- *Saturated failures:* when chlorine is forecast at zero whatever the dose, magnitudes can't rank options. Safety net: while a variable is forecast out of band, a dose change that pushes it further that way is blocked.
- *Marginal false blocks:* most were distribution-rate changes during storms that changed the true outcome by <0.1%. The twin now blocks only changes that are **materially** worse than doing nothing (configurable margin).
- *Bloom cases that remain:* legal, safe lye increases made *before* a bloom, which no forecaster can see coming, and then nobody responds for hours. Aegis's answer is the early warning (36–90 min before harm in those runs), not a block. The evaluation's "nobody responds" assumption makes these count as losses; we report them anyway.

## Round 7 (against v9, after the held-out evaluation)

**Judge:** "Your own held-out numbers: 14 of the twin's 21 blocks of operator actions were unnecessary. Operators will turn it off on day two."

Diagnosed on **development** seeds only (held-out seeds stay untouched for reporting). Twin blocks of operators fell into four groups:
- *The wrong-way safety net was too strict.* It fired when **any** member of the uncertainty ensemble predicted a violation, even a worst-case corner grazing the limit (chlorine reaching exactly 0.20 mg/L), and then blocked every small trim. It was meant for saturated failures in the nominal forecast. **Fix:** only the nominal forecast triggers it; the worst-case corners still feed the magnitude comparison.
- *Hydraulic setpoints* (distribution rate): blocked because their worst-case effect on residence time looked bad; the true effect was usually negligible, and the evaluation showed the twin doesn't stop drain attacks anyway. **Fix:** for *known* operators (HMI / named IPs), the twin advises on hydraulic setpoints: the change goes through, with the forecast in the log and a warning alert ("allowed against twin advice"). Unknown writers are still blocked; chemical doses (lye, chlorine) block for everyone. Configurable via `prediction.block_registers`.
- *Remaining blocks we keep:* lye 165 on a normal day (the price of the ±10% feed uncertainty; calibration narrows it), raising lye during a bloom, and chlorine cuts that make a storm failure marginally worse.

Development seeds 0–39: twin operator blocks 17 → 9, false 10 → 5, all justified blocks retained.

**Confirmed on new held-out seeds (200000–200199):** twin operator blocks 9, false **3** (standard) / 2 (high-fidelity), versus 14 false of 21 in the previous held-out run; attack success with the twin 31% / 33% versus 56% / 57% for static rules alone.

## Round 8 (against v10)

1. **"Your drain defence is a text message. 42 of 53 drain attacks still succeed, with a 2½-hour warning nobody read. At 3 AM a warning protects nothing."**
2. **"Your evaluation's attacker is a stranger on the network. The real one sits on the HMI PC (that's how the 2021 Oldsmar intrusion worked). Your own Round 7 change made hydraulic setpoints *advice* for the HMI. So an HMI attacker drains the tank freely."**
3. **"Why can an unknown IP write at all? An allowlist of writer IPs is a one-line firewall rule, and your evaluation pretends it doesn't exist."**
4. **"MicroLogix speaks EtherNet/IP on 44818 alongside Modbus. The attacker skips your proxy entirely. You say 'segment the network' and never check it."**
5. **"If Aegis starts writing to the PLC on its own, an attacker who fakes the sensors can make Aegis undo the operators' good changes. You've built them a weapon."**

### What we did about it (v11)

1. **Safe-hold** (`aegis/safehold.py`). If the twin forecasts unsafe water and nobody acknowledges for 15 min, Aegis restores the earlier setpoint value (one the plant really ran at within 12 h) that fixes the forecast most, and writes it to the PLC as "Aegis safe-hold". Critical alert, audit entry with before/after forecast scores. Acknowledging the incident means a human owns it, and Aegis does nothing.
2. **The hold.** After a revert, Modbus writes that move that register are refused unless the twin calls them corrective. Release needs a login on the dashboard (or a console on the Aegis box). A hijacked HMI can send packets; it can't log in. Holds survive restarts. New evaluation option `--attacker hmi`: the attacker writes as the trusted operator.
3. **`"unknown_writers": "block"`** in route mode makes every host not named in `--sources` read-only. We kept the evaluation's "unknown device" attacker anyway: it stands for anything that gets onto a writer's IP.
4. **`python -m aegis.exposure <plc-ip>`**, run from any other machine: TCP probe of Modbus, EtherNet/IP 44818, S7, DNP3, 104, OPC UA, Fox, web, telnet, FTP, SSH. Every OPEN port is reported as a bypass. Exit code 1 if any, so it can run in a scheduled check.
5. **Stand-down.** Safe-hold does nothing while the integrity monitor distrusts the sensors (shadow-physics mismatch, stuck analyzer, setpoints changed behind Aegis's back). It never acts in monitor mode, never touches pumps, and only restores values that operators themselves ran.

**Development seeds 0–39** (40 attacks, 15 operator sessions):

| | Attacks that made water unsafe |
|---|---|
| Static rules | 21/40 (52%) |
| Rules + twin (v10) | 13/40 against an HMI attacker |
| Rules + twin + safe-hold | **1/40** stranger attacker, **4/40** HMI attacker |

**Costs, measured:**
- Safe-hold reverted 13 operator changes: 9 made the true outcome better, 4 made no difference, 0 made it worse.
- Holds refused 10 of 202 operator writes. In reality the operator would get the critical text and could release the hold. In the evaluation nobody does.

**Held-out check of v11** (fresh seeds 300000–300199, safe-hold on): 25/200 harmful with a stranger attacker, but **32/200 with the attacker on the HMI**, and 10 of those were pump cycling, a goal that had been 0 for every earlier version. That became Round 9.

## Round 9 (against v11, after its held-out run)

1. **"Your 'advice' path is a backdoor. An attacker on the HMI swings the flow 300 ↔ 700 every two minutes and you let it through, because hydraulic changes from the HMI are only advice."** Correct: the advice branch returned *allowed* before the step and ramp checks ran.
2. **"Your cycling rule counts reversals in 10 minutes. Slow down to one swing every three minutes and it never fires; the pumps still wear out."**
3. **"A half-asleep 'ack' on the phone switches safe-hold off for the rest of the night."**
4. **"What happens if the PLC refuses Aegis's own revert (program mode, network down)? Your code logs it and moves on. The plant is still heading for the limit and nobody knows Aegis failed."**
5. **"Show me what safe-hold does to the operators, on seeds you haven't tuned on."**

### What we did about it (v12)

1. Advice waives only the twin's verdict, never the step/ramp limits (`guard.py`). Test: HMI 500 → 900 refused by `step`, 500 → 700 still allowed as advice.
2. New policy limit `max_large_reversals_per_hour: 6`. Only swings of at least half a max step count, so small operator trims never trip it. Persisted across restarts.
3. An acknowledgement pauses safe-hold for `ack_valid_min` (60). If the forecast is still bad after that, safe-hold re-arms (and waits a full `after_min` first).
4. `safehold.execute()`: if the write fails, nothing is held, a **critical "SAFE-HOLD COULD NOT ACT" alert** goes out and the failure is audited. Used by both the dashboard server and the gateway.
5. Holds now block only moves *back toward* the value Aegis undid (directional), not every change.

**Held-out seeds 300000–300199, v12:**

| | Harmful attacks |
|---|---|
| Static rules | 98/200 (49%) |
| Twin, HMI attacker, no safe-hold | 40/200 (20%), drain 25/27 |
| Twin + safe-hold, HMI attacker | **25/200 (12%)**, drain 10/27, cycling 0/41 (was 10/41) |
| Twin + safe-hold, stranger attacker | **25/200 (12%)** |

Operator cost: 380 writes, 12 twin blocks (10 justified, 2 false), 4 hold refusals (v11: 12). Safe-hold undid 19 operator changes: 15 better, 3 neutral, **1 slightly worse**.

## Round 10: the VOXO method (state the flow, then attack each step)

At the hatchathon kickoff VOXO asked for the project's flow first, then took each step apart. We did the same to Aegis:

1. *Problem: legacy PLCs, Oldsmar 2021.* → **"Oldsmar may not have been a hack"** (the former city manager said in 2023 it was probably an employee's error). **"Who installs and maintains this at a utility with no engineer?"**
2. *Aegis sits between the HMI and the PLC and reads every Modbus command.* → **"Rockwell HMIs talk to a MicroLogix over EtherNet/IP + PCCC, not Modbus. In many real plants Aegis would see none of the writes it's meant to judge."** This was the biggest hole. **"What happens when the box dies?"**
3. *Rule checks.* → **"Tofino's Modbus enforcer did range/function filtering in 2009."**
4. *Digital twin.* → **"Graded by your own simulator; no real plant data."**
5. *Early-warning texts.* → **"Operators already ignore alarms. How many texts does a normal week produce?"** We didn't know.
6. *Safe-hold.* → **"A box that writes to a drinking-water PLC by itself. What if it overrides an operator who is already handling it?"**
7. *AI copilot.* → **"Why an LLM in a water plant? Has it run against a real model?"**
8. *12% of attacks still succeed.* → **"Your attackers, your simulator, nobody responds."**

### What we did about it (v13)

- **EtherNet/IP + PCCC guard** (`aegis/cip.py`, `python -m aegis.gateway --protocol cip`). Written from the ODVA encapsulation/CIP structure and Rockwell's DF1 command set (pub. 1770-6.5.16). Typed writes (`0x0F/0xAA, 0xAB, 0xA9`) on the data files in `tags.json` (`"pccc": "N7:1"`) go through **`Guard.judge_writes`**, the same function the Modbus proxy uses, so rules, twin, holds and safe-hold apply unchanged. Typed reads, diagnostic status, forward open/close and identity pass. Everything else is refused and logged with its ATT&CK technique: RUN→PROGRAM (T0858), download (T0843), Logix tag writes, Set Attribute, Reset, unknown commands, and anything that fails to parse. Writes wrapped in an Unconnected Send are unwrapped and judged. Partial-word masked writes to a setpoint word are refused. Also: `MicroLogixSim` (the plant answering as a MicroLogix 1400), `PCCCClient` (gateway polling and safe-hold writes), two dashboard attack buttons. **Tested with pycomm3's SLCDriver**, an independent client: 12 tests, including twin verdicts over EtherNet/IP and the full gateway in `cip` mode. Not tested on a real MicroLogix.
- **Alert load** (`python -m aegis.alertload`): a simulated year. First run: 11.8 texts/week, **0.64 per calm day** (mostly clearwell-overflow forecasts), and **safe-hold acted 51 times on an operator who was acknowledging and responding**: their 60-minute acknowledgement lapsed during long storms. Fixes:
  - overflow forecasts are `info`: dashboard only, never texted, and ignored by safe-hold (it's not a safety condition);
  - safe-hold texts the operator when its countdown starts ("acknowledge within 15 min if you're handling it, otherwise Aegis will restore…"), so it never acts on a warning the operator wasn't actually texted about;
  - when an acknowledgement lapses and the forecast is still bad, it texts a **reminder** in a fresh incident before acting.
  
  After: **9.6 texts/week, 0.05 per calm day, 3.7 per storm/bloom day, 0 safe-hold actions against the engaged operator, 0 hold refusals.** Unattended (the attack evaluation), safe-hold behaves as before.
- Already answered in earlier rounds and kept: Oldsmar caveat (now framed as "attack or mistake, the guard catches both"); Tofino named as prior art; supervisor + break-glass bypass for a dead box (Round 1); second high-fidelity simulator (Round 2).
- **Still open, said plainly:** no real plant data; no real MicroLogix; the copilot has not been run with a real model key; the evaluation's attackers are ours.

## Round 11: the VOXO method again, on v13

Flow: *Aegis sits between the HMI and a MicroLogix (Modbus or EtherNet/IP) → rules → twin forecast → texts → safe-hold.*

1. **Twin.** "It needs online raw pH, alkalinity and turbidity analyzers. A 3-person plant has pH and chlorine online; alkalinity is a titration someone does each morning. So at the plants you're pitching to, your twin is off."
2. **Day one.** "The HMI also writes alarm-ack words and timer presets. Your allowlist blocks every write it doesn't know, the HMI throws comms errors, and the operators rip the box out on the first morning."
3. **Onboarding.** "Your tag drafting reads Modbus maps. A Rockwell plant hands you an RSLogix 500 export."
4. **EtherNet/IP latency.** "You added a 13 ms twin to every write. HMIs time out."
5. **Round 10's changes.** "You changed when safe-hold acts. Did attack protection get worse?"

### What we did about it (v14)

1. **Lab inputs** (`aegis/labinputs.py`, `policy.lab_inputs`): any twin input can come from a lab sample, with who entered it (audited), up to `max_age_h`; then the twin's chemistry pauses and the operator is texted. The evaluation got `--lab-hours`: Aegis sees only a sample every N hours. Dev seeds 0–39, twin only: **online 5/40 harmful; alkalinity from a daily sample 6/40; alkalinity and turbidity from the lab 9/40** (clearwell drains 7/8 vs 4/8: the twin follows storms through turbidity). Static rules: 21/40. Advice in the README: lab alkalinity is fine; keep turbidity online.
2. **`pass_writes`**: housekeeping addresses (`"N7:50-N7:59"`, `"holding 40-49"`) are forwarded, logged as `pass`, not judged; flood and writer rules still apply; a guarded tag can't be put on the list (validated). The EtherNet/IP proxy now records every data-file word read or written into `data/discovery.json`, so monitor mode shows the engineer exactly what to put there.
3. **Onboarding** reads `N7:1` / `F8:0` / `B3:0/1` addresses (RSLogix 500 / CCW exports) and drafts `pccc` tags; tags no longer need a Modbus address.
4. **Measured** with pycomm3 (`scripts/bench_cip.py`): direct 0.05 ms; through Aegis static p50 0.21 / p99 0.55 ms; with the twin p50 12.9 / p99 16 ms. CIP explicit-message timeouts are measured in seconds.
5. **Re-ran dev seeds with the HMI attacker and safe-hold: 1/40 harmful** (v11 was 4/40); safe-hold undid 12 operator changes, 8 better, 4 neutral, 0 worse; 3 hold refusals in 202 writes.

## Round 12: attacks on Aegis's own judgement

1. **"Make Aegis slow and the twin switches itself off.** Your twin has a 500 ms budget and falls back to static rules when it runs out. Load the box, then send the patient lye attack."
2. **"Poison the calibration slowly.** You refuse a calibration that moves a parameter more than 25%. Move it 20% a week."
3. **"Your new lab-input feature is a steering wheel.** Type a high alkalinity and the twin decides more lye is harmless."
4. **"You priced a $300 box. Have you run the twin on one, under load?"**
5. **"At 3 AM the operator gets a text that says 'safe-hold'. What are they supposed to do? Where's the procedure?"**

### What we did about it (v15)

1. Twin timeout: **unnamed writers are refused** ("changes from unnamed writers are never allowed without the twin"); named operators keep the static fallback and an alert. Loading the box can no longer downgrade the guard for the attacker's own writes. Test: `tests/test_round12.py`.
2. **Commissioned baseline** (`process.json "_commissioned"`, `python -m aegis.calibrate --commission` after an on-site check): any calibration more than 40% from the commissioned values needs an engineer on site, on top of the 25% per-step limit. Boiling-frog test: 1.0 → 1.2 accepted, 1.2 → 1.44 refused (+44% from commissioning). `--write` refuses while warnings stand; the dashboard already did.
3. **Lab alkalinity is checked against the plant's own chemistry**: the finished pH and the lye dose imply a range of raw alkalinity; an unconfirmed entry outside it isn't used, the twin pauses, and the operator is told who entered it. The check needs 90 steady minutes (steady-state chemistry): the first version rejected 26/360 true values during storms and blooms; with the steadiness gate, **0/432 true values rejected**, and **573/864** fake values (×3 or ×0.4) caught at the hour they were checked (the rest are judged later, once steady). Until then, a big unverified jump keeps the previous value. Shown in the test: with a fake 300 mg/L the twin would allow lye 200; with the real 77 it blocks it.
4. Measured (`scripts/bench_lowpower.py`, pinned to one core of the cloud VM): twin-checked write p50 12.7 / p99 20 ms idle; **p50 49 / p99 78 ms with three busy processes on the same core**. A Raspberry-Pi-class core is several times slower, which puts p99 under load in the low hundreds of ms, uncomfortably close to the 500 ms budget. Recommendation in the README: an x86 mini PC, not a Pi. Not measured on real low-power hardware.
5. **`docs/RUNBOOK.md`**: one printable page for the shift: what each text means and what to do, the three modes, what to do if the box dies (break-glass cable), and what Aegis will never do on its own.

## Round 13: the real install

1. **"At a real plant there is no dashboard."** The full console drives the simulator; the gateway (what a utility actually runs) had no way to acknowledge a text. So safe-hold would act on *every* warning after 15 minutes even with an operator on it, and releasing a hold needed someone at the box.
2. **"Stronger lye gets delivered, your twin's feed strength is now wrong by 60%, and it keeps approving doses from numbers that have just been proven wrong."**
3. **"A small box has a small disk."** History is written every 10 seconds, forever.
4. **"Operator passwords over plain HTTP on the plant LAN."**
5. **"Your README is 250 lines. A judge reads one page."**

### What we did about it (v16)

1. **`aegis/console.py`**: `python -m aegis.gateway ... --console-port 8443` serves the phone-sized operator page from the gateway, against live PLC readings: named accounts only (no demo accounts), acknowledge incidents, release safe-holds, all audited with the person's name. No setpoint writes, modes or policy from there. Tested with a TestClient, plus an end-to-end smoke run: gateway in EtherNet/IP mode against the simulated MicroLogix, real login, live readings polled over PCCC. The phone page also gained a Safe-hold card with **Release hold**.
2. **Distrust mode**: while the integrity monitor says the plant doesn't match the model, the twin evaluates with a wide ensemble (feed strength ±50%, chlorine decay ±60%, demand ±50%). Test: true feed ×1.6, integrity alarm at ~130 sim-min; the nominal twin allows lye 140 (true outcome pH 9.2), distrust mode blocks it, cutting lye is still allowed. Honest limit: lye 120 is also unsafe at ×1.6 (true pH 8.8) and distrust mode still allows it; it narrows the gap, it doesn't close it.
3. `history.csv` rotates at 50 MB and keeps 30 files.
4. `--console-cert/--console-key`: the console serves HTTPS itself and marks cookies Secure; a warning is printed if it's exposed beyond localhost over plain HTTP.
5. **`docs/ONE_PAGER.md`**: problem, product, evidence, gaps, business, next step on one page.

## Round 14: will it work on Monday, and at the plants it's pitched to?

1. **"Your AI demo step needs a live API key. If the API is down, the Wi-Fi is bad or the model refuses the bait, that step dies in front of the judges."**
2. **"Your twin only knows caustic soda. Most small plants dose lime or soda ash, and many groundwater systems only chlorinate."**
3. **"Onboarding won't even recognise a lime feed tag."**
4. **"Small plants have two or three PLCs (filters, chemicals, high-service pumps). You guard one."**
5. **"Does anything on demo day need the internet?"**

### What we did about it (v17)

1. **Scripted demo model**: with `AEGIS_DEMO=1` and no key, the copilot uses a stand-in that behaves like a model that fell for the poisoned work order (reads the orders, tries to raise lye to 9,000 with whatever tool its mode allows). Every reply starts with **[SCRIPTED DEMO MODEL …]**, the panel says "scripted demo model (no API key)", and the guided demo tells the presenter to say so. Aegis blocks it exactly as it blocks a real model. Never used outside demo mode. Test: `tests/test_server.py`.
2. **Alkali chemistry**: `process.json "alkali"`: `naoh`, `lime` (2 eq/mol), `soda_ash` (2 eq/mol and 1 mol carbonate, so it buffers), `bicarbonate`. Same feed setpoint, steady pH at 400: NaOH 9.85, lime 9.93, soda ash 7.95, bicarbonate 7.09. Plants without an alkali feed leave the register out, and the twin still judges chlorine. Tests in `tests/test_round12.py`. The chemistry is textbook; the soda-ash and lime paths have not been checked against a real plant's data.
3. Onboarding matches lime / soda ash / Na2CO3 / alkali / pH-adjust feed tags.
4. One gateway per PLC (each its own port, own tag map). Over Modbus, a TCP-to-serial gateway's unit IDs are routed (`--plc-unit`), already tested. A single box can run several gateways; documented, not yet a single multi-PLC process.
5. Checked: the dashboard loads nothing from the internet (no CDNs or web fonts); with the scripted model the whole demo runs offline.

## Round 15: what still gets through, and is the scorekeeping honest?

1. **"12% still succeed. Which ones, and what did they look like?"** The successful attacks were refused 15 to 1,800 times before they got through. A real operator was refused at most 3 times in a 12-hour shift. Aegis saw the probing and did nothing with it.
2. **"Your chemistry was validated against your own simulator. Circular."**
3. **"One of your 'successful attacks' had zero accepted writes. How?"** (Episode 300087: 15 tries, all blocked, counted as harm caused by the attacker.)
4. **"Your HMI-attacker can now trigger lockdown on purpose and lock the real operators out."**
5. **"Your README screenshot is from the old design."**

### What we did about it (v19)

1. **Lockdown** (`policy.lockdown`): 6 refusals from one source within 60 min and that source may only make changes the twin forecasts as corrective, until an operator clears it on the console or dashboard (login, audited; survives restarts; not in monitor mode; dry runs don't count). Critical alert names the source.
2. **PHREEQC check** (`scripts/validate_phreeqc.py`, `tests/test_phreeqc.py`): the twin's carbonate chemistry against the USGS reference code for 5 waters × NaOH, lime, soda ash: **mean 0.05 pH difference over 100 cases**, max 0.32; two cases disagree about the 8.5 limit (soda ash in low-alkalinity water; Aegis 0.16–0.23 pH low, the unsafe direction). A Davies activity correction made it worse (0.067), so it wasn't adopted.
3. **An evaluation bug, found and fixed.** The simulator's sensor noise and its demand drift shared one random stream, so every extra sensor read (attacker tries, safe-hold forecasts) changed the physics; "the same episode without the attacker" wasn't the same. Sensor noise now has its own stream (verified: reading the sensors any number of times leaves the true plant identical). One test that relied on the old behaviour was itself wrong (it switched off noise on *every* analyzer while claiming to freeze only pH) and was fixed. All held-out numbers re-run:

| held-out seeds 300000–300199 | before the fix | corrected |
|---|---|---|
| Static rules | 98/200 | **90/200 (45%)** |
| Twin + lockdown, HMI attacker, no safe-hold | (40 without lockdown) | **36/200 (18%)** |
| Twin + lockdown + safe-hold, HMI attacker | 21/200 | **20/200 (10%)** |
| Twin + lockdown + safe-hold, stranger | 21/200 | **20/200 (10%)** |

   Lockdown's own effect (old simulator, same seeds): 25 → 21. Operators: 382 writes, 13 twin blocks (9 justified, 4 false; the noise stream changed which ones), never locked down.
4. True: an attacker on the HMI can trigger lockdown deliberately. What they get: the operator can still make every *corrective* change, the console shows a critical "possible intrusion" alert naming the source, and one login clears it. We judged a loud, recoverable denial of convenience better than letting a prober keep probing; it's in the README as a known trade-off.
5. New screenshot: the scripted demo model falling for the poisoned work order, Aegis blocking it.

**What's left:** clearwell drains (10/27) are now most of the remaining harm. The drain itself is hydraulic and slow, and the harm comes when storms or blooms hit a half-empty clearwell. That's the next round.

## Round 16: the last ones through

1. **"Ten clearwell drains still succeed. Why can't you stop a tank draining?"**
2. **"Show me one success where the water would have been fine without the attacker."**
3. **"Your twin approved cutting chlorine to a dose whose long-run residual it put at 0.24 mg/L. The limit is 0.2. That's no margin at all."**
4. **"Your evaluation says 'harmful'. Harmful compared to what?"**
5. **"What would it take to get those last 19 to zero?"**

### What we found and did (v20)

1. and 2. Every harmful episode was replayed against its no-attacker twin (same seed, same weather). **All 10 drains: the water became unsafe in the no-attacker run too** (a storm or bloom nobody answered); the drain made it arrive 37–77 minutes sooner with the same peak. Across all 20 v19 successes, exactly **one** created harm on its own: episode 300078.
3. 300078, replayed: the HMI attacker cut chlorine 1.5 → 1.18 → 0.69 in two minutes; the twin's ensemble put the long-run residual at 0.24–0.40 mg/L (true plant: 0.26), so it approved. Ordinary demand drift took it below 0.2 seven hours later, past the 6-hour forecast. Fix: **`prediction.approval_margin`**: to be *approved*, a change's forecast must stay 0.15 inside the chlorine and pH limits (≥ 0.35 mg/L, pH 6.65–8.35). Warnings and safe-hold still use the real limits; corrective changes still only have to beat doing nothing. Regression test reproduces 300078.
4. The evaluation now prints the split: **created / made much worse / only sooner**.
5. Held-out, v20: **19/200 for both attackers, 0 created, 0 made much worse, 19 only sooner**; static rules: 90/200 with 52 created. Operator cost unchanged (13 twin blocks, 4 false). Getting the last 19 to zero means fixing the *weather* harm, i.e. Aegis steering the plant through storms on its own. That's automatic process control, a decision for the utility's engineers rather than a safety guard, so we stop here and say so.

## Round 17: attack Aegis itself

1. **"Fuzz your new EtherNet/IP parser. Inline filters get bypassed when they and the PLC read the same bytes differently."**
2. **"Attacker-controlled text ends up on your dashboard: Logix tag names, work orders, copilot input. Is that script injection?"**
3. **"One laptop opens 64 Modbus connections and your real HMI can't connect. And a MicroLogix only accepts a handful of EtherNet/IP connections; you open one upstream per client, with no limit."**
4. **"EtherNet/IP connections never time out."**
5. **"`pip install fastapi` on install day gets whatever version exists that day."**

### What we did about it (v21)

1. `scripts/fuzz_cip.py`: mutates dangerous PCCC writes (lye 11,100; stop the distribution pump), wraps them in random transports (unconnected/connected, truncated, garbage), and every frame Aegis **forwards** is executed by the simulated MicroLogix; any PLC change must equal a value Aegis judged and approved. **60,000 cases: 0 unjudged or mismatched changes.** A separate 20,000-case run: 268 frames raised inside the inspector, and the connection loop turns those into refusals (fail-closed). A short run is in the test suite. Caveat, stated in the script: the simulator reuses Aegis's decoder for the innermost typed-write fields, so this covers the framing layers; only a real PLC can confirm the last bytes.
2. Sent an HTML/script payload as a Logix tag name over EtherNet/IP and through the copilot, then rendered every tab of the dashboard and the phone page in a real browser: **nothing executed** (`scripts/xss_check.js`); the payload appears as text in the log.
3. **`ConnLimiter`** for both fronts: per-address cap (Modbus 8, EtherNet/IP 2), global cap (64 / 8), and **the named operator stations (`--sources`) are always admitted**. Tests: one host can't take every slot; the named HMI still gets in when the box is full.
4. EtherNet/IP clients are dropped after 120 s idle, like Modbus.
5. `requirements.lock`: the exact versions this release was tested with, for deployed gateways (`run.bat` keeps the looser list so a newer laptop Python still installs). Hash pinning: not done yet.

## Round 18: the expo table

1. **"Your laptop crashes thirty seconds into the pitch. What do the judges see?"**
2. **"Two key presses per demo step: run it, then move on. Under pressure you'll press once and stand there."**
3. **"Your demo panel sits right on top of the guard log, the one thing that proves your point."**
4. **"Your booth loop runs for hours unattended. Does anything grow without limit?"**
5. **"Your script says the twin predicts the limit crossing 'in about 90 minutes'. Your dashboard says 80. Which is it?"**

### What we did about it (v22)

1. `docs/video/pitch-demo-backup.mp4`: a 64-second screen recording of the four pitch steps, made by a script against the real dashboard. The deck's demo notes say to play it if the laptop or server fails.
2. In pitch mode, one press of Space or → moves on **and** runs the next step. Four presses, four steps.
3. In pitch mode the demo panel drops its description and script (the presenter has those in the slide notes) and narrows, so the guard log and its red BLOCKED entry stay visible.
4. Checked every list the dashboard keeps: all are capped except AI proposals. On the demo, reset clears them; on a real gateway nothing would. Now capped at 300, and **pending proposals are never dropped** (decided ones are already in the audit log). Test: `tests/test_round18.py`. The booth caption also showed the previous scene's reason for the AI scene; it now shows the blocked proposal's own reason.
5. Both are right: the forecast depends on that run's weather and sensor noise (80 and 90 minutes in two runs). The script now says "in under two hours", which is true in every run we made.

## Round 19: the attacker already has the password

1. **"Malware on the operator's PC has keylogged the operator's console password. It gets locked down, then signs in to your console from the same PC and clears its own lockdown."**
2. **"Same malware acknowledges every alert from that PC, so safe-hold never acts."**
3. **"You put the console behind a reverse proxy, like your docs suggest. Now every request comes from the proxy's address."**
4. **"If the real HMI gets locked down by mistake in an emergency and there's no phone signal, are the operators stuck?"**
5. **"Has this ever run against a real PLC runtime?"**

### What we did about it (v23)

1. The guard now remembers which addresses a locked-down source wrote from (plus its fixed address from `--sources`). The gateway console **refuses to clear a lockdown, release a hold or acknowledge an alert from a locked-down address**, even with a valid password: "use another device, for example the on-call phone". The same operator from another device can clear it. Test: `tests/test_round18.py`, which signs in with the right password from the locked PC (refused) and from a phone address (allowed).
2. Covered by the same check once the source is locked down. Before lockdown (fewer than 6 refusals), an attacker with a stolen password could still acknowledge alerts from that PC; that delays safe-hold but doesn't let any write through the guard. Stated, not fixed.
3. Behind a reverse proxy the check would see the proxy's address, and trusting `X-Forwarded-For` would let the attacker forge it. So the console docs now say: use the built-in TLS (`--console-cert/--console-key`) rather than a proxy.
4. No. A lockdown still allows every change the twin forecasts as making the plant safer, and the console on the Aegis box itself (or any device other than the locked one) can clear it. In the simulated alert year, no operator station was ever locked down.
5. Not yet. We tried to build the OpenPLC runtime for this round; its installer couldn't be run in our build environment. Still the first item on the "next" list: a real controller on the bench.

## Round 20: the wells are on the radio

1. **"Half the small systems in Mississippi reach their well sites over serial radios. That's Modbus RTU, not Modbus TCP. You don't speak it."**
2. **"RTU has no length field. How do you know where a frame ends? Guess wrong and you forward the second half of an attacker's frame unjudged."**
3. **"Did you test it with anyone else's RTU code, or only your own?"**
4. **"Does a write that arrives over RTU get the same checks?"**
5. **"What about a PLC with only an RS-485 port?"**

### What we did about it (v24)

1. Aegis speaks **Modbus RTU over TCP**, which is what radio-to-Ethernet bridges and serial device servers carry: `--framing rtu` toward the HMI/SCADA side, `--plc-framing rtu` toward the PLC, in any combination with Modbus TCP.
2. The frame length comes from the function code (read, write single, write multiple, mask write, read/write multiple). A function code whose length Aegis doesn't know, or a bad CRC, **closes the connection**; nothing is forwarded. Test: a one-bit CRC error and a diagnostics request (FC 8) are both dropped without reaching the handler.
3. pymodbus's RTU framer on both sides: pymodbus client (RTU over TCP) → Aegis → pymodbus server as the PLC (RTU over TCP). Allowed trim goes through; 11,100 via FC 6, 9,000 via FC 16 and via FC 22 are blocked; the PLC holds only the safe value.
4. Yes: the framing is unwrapped before the guard, so every check (rules, twin, lockdown, safe-hold) is the same code path. Same test.
5. Not built. Aegis would need a serial port and to sit on the RS-485 line itself. Today the answer is a serial device server (about $100) between Aegis and the PLC with `--plc-framing rtu`. Not tested on real radio or serial hardware.

## Round 21: the venue

1. **"The venue Wi-Fi dies. Does your demo?"**
2. **"Your laptop goes to sleep twenty minutes into the booth loop."**
3. **"A visitor clicks the screen, the loop stops, and nobody notices for an hour."**
4. **"Someone presses Booth loop twice, quickly. Now two loops fight over the same plant."**
5. **"The booth caption says what's happening. Can anyone read it from the aisle?"**

### What we did about it (v25)

1. Checked: the dashboard loads nothing from the internet (no CDNs, no web fonts), and the copilot falls back to the labelled scripted model with no key. Ran the whole pitch demo in a browser that **blocks every non-local request**: 4 steps, 8 seconds of machine time, 0 page errors, 0 outside requests.
2. The booth loop now asks the browser to keep the screen on (Wake Lock) and lets go when it stops. Still set the laptop's power plan to "never sleep" before the expo; the browser can't override that everywhere.
3. A click pauses the loop; after **3 minutes with no mouse, keyboard or scroll** it starts again by itself. It never restarts while the Pitch or Guided demo is open.
4. Each loop has a generation number; starting a new one retires the old one at its next check, so only one loop drives the plant. Tested by stopping and restarting mid-scene.
5. 30-pixel bold captions over a dark bar across the full width; checked at 1280×720 (a common projector size).

## Round 22: check your own slides

1. **"'7+ states' is from July. What do the agencies say now?"**
2. **"Which controllers did those attackers actually hit, and could Aegis even talk to them?"**
3. **"They changed IP addresses, passwords and project files. Your guard judges setpoints. Does it stop any of that?"**
4. **"If you can't name the model in the July attacks, don't put it on your slide."**
5. **"Would Aegis have stopped them if the PLC was on the internet anyway?"**

### What we found and did (v26)

1. CISA (August 2026): more than 100 internet-exposed water and wastewater systems were targeted in July 2026. FBI and EPA: incidents in at least 7 states. The slide now says "100+ water systems targeted; incidents in 7+ states" with CISA and FBI/EPA in the sources.
2. The 7-state campaign hit **Rockwell (Allen-Bradley) MicroLogix 1100/1400**: the controller family Aegis's EtherNet/IP + PCCC guard is built for.
3. Over EtherNet/IP, each of those is refused: an IP change is a Set Attribute on the TCP/IP Interface object; MicroLogix passwords live in the program, so changing one is a program download; plus reset and mode change. New test (`test_july_2026_micrologix_campaign_actions_are_refused`, pycomm3 as the client): all three refused and logged, the download tagged MITRE T0843.
4. Agreed. The slide says the *incidents* were on MicroLogix (FBI/EPA via the Avertium notice) and does not claim the 100+ were. We don't name a threat actor; agencies haven't officially attributed the attacks.
5. No. Aegis only protects what has to go through it. If the PLC's port is still reachable from the internet, the attacker goes around. Installing Aegis means the PLC's network cable goes into Aegis and nothing else; the runbook says so, and that's the first thing to check at a pilot site.

Sources: [TechRadar on CISA's July count](https://techradar.com/pro/security/cisa-says-over-100-us-water-systems-were-targeted-in-july-2026-alone), [Avertium flash notice (FBI/EPA, MicroLogix 1100/1400)](https://www.avertium.com/flash-notices/coordinated-attack-on-rockwell-micrologix-plcs-disrupts-water-systems-across-7-states).

## Round 23: you bought the fast API key

1. **"You set a real API key. The venue Wi-Fi drops during the pitch. The AI step hangs for 40 seconds."**
2. **"The key expired, or you typed it wrong at 7 a.m. The AI step shows an error in front of the judges."**
3. **"A real model might refuse the poisoned work order. Then your 'AI gets fooled' step shows nothing."**
4. **"Isn't quietly switching to a scripted model cheating?"**
5. **"Does any of this change how the real gateway behaves?"**

### What we did about it (v27)

1. On the demo dashboard, model calls now give up after 4 s to connect / 12 s to answer, and a network failure falls back to the scripted stand-in model. Test: a dead network, reply in under 5 s, and the work-order attack is still blocked.
2. Any provider error (bad key, model not available, outage) on the demo falls back the same way. Test: a 401 from the provider.
3. That's the honest case and the step says so: "you can't count on the model refusing, which is why the guard exists". For the 2.5-minute pitch, run **without** a key so the step is the same every time; use the real model at the booth, where there's time to explain either outcome.
4. It isn't silent: every fallback reply starts with why ("can't reach the model provider (ConnectError)" or "model provider answered 401") and that the scripted stand-in is answering, and the panel already labels the scripted model.
5. No. The fallback only exists with `AEGIS_DEMO=1`. A real deployment shows the provider's error and keeps the 40-second timeout.

## Round 24: is the twin grading its own homework?

1. **"In the algae-bloom demo, does the twin get told about the bloom? If it reads the scenario's future, the 'forecast' is fake."**
2. **"Your evaluation plant is your twin's own equations with a 3% and a 20% parameter change. Of course the twin predicts it."**
3. **"You ran the high-fidelity simulator once, at v6. Ten versions later, does your headline survive it?"**
4. **"What does the twin cost operators when the plant doesn't match it?"**
5. **"Why should anyone believe the 10% will hold at a real plant?"**

### What we checked and found (v27)

1. Checked the code: the twin gets only the plant's measured readings (raw-water pH, alkalinity, turbidity and the finished-water sensors) and estimates the raw-water trend itself from the last 30 minutes of those readings, levelling it off over an hour. It never sees the scenario or the simulator's future.
2. Fair, for the standard runs. That's why the high-fidelity simulator exists: it has physics the twin doesn't model at all (a second mixing stage in the clearwell, CO2 exchange with air) and lagged pH/chlorine analyzers, on top of the parameter errors.
3. Re-ran the current version on held-out seeds 300000–300199, attacker on the operator's HMI, safe-hold on, **high-fidelity plant**: static rules **91/200 (46%)**, Aegis **19/200 (10%)**. Of Aegis's 19: **0 created harm**, 1 made storm harm much worse, 18 only made it come sooner. Same headline as the standard simulator. Output: `docs/eval/v27_heldout_hmi_safehold_highfi.{txt,json}`.
4. 508 simulated operator writes: the twin blocked 19, **14 justified and 5 false** (standard simulator: 4 false in 382). Safe-hold undid 21 operator changes: 16 helped, 4 no difference, 1 made things worse.
5. They shouldn't yet. Both simulators are ours; the high-fidelity one is a stricter test, not a real plant. That's why the next step on the last slide is a real controller and a pilot plant, and why Aegis starts in watch-only mode: a week of real logs shows how often the twin would have blocked before it's allowed to.

## Round 25: when the twin is wrong

1. **"Your twin blocked 5 good operator changes in 508. At 3 a.m. one of those is the change the plant needs. What does the operator do?"**
2. **"Today the answer is 'switch the guard OFF' or 'pull the break-glass cable'. Both remove all protection to get one value through."**
3. **"Any override is an attack path. What stops malware on the HMI from using it?"**
4. **"Can an override push lye to 11,100?"**
5. **"Who finds out?"**

### What we did about it (v28)

1. and 2. **Allow-once tickets.** Under *Recently blocked* on the operator console, a write blocked by the twin, the step/ramp limits or the cycling check gets an **Allow this value once** button. It lets that exact value on that one setpoint through once, within 30 minutes (capped), then the ticket is gone. Everything else stays enforced.
3. It needs a named login on the console, and the console refuses it from a locked-down device (round 19), so a compromised HMI can't issue one. It can't be used by an unknown host or a locked-down source, and only the exact value passes: malware on the HMI could at most send the value the operator just approved.
4. No. Range limits, interlocks, permits, writer rules, holds and lockdowns aren't waivable, and issuing a ticket outside the hard limits is refused.
5. Issuing one texts everyone on call with the person's name; issuing and using it are both in the signed audit log. Runbook: use it from your phone, resend from the HMI, acknowledge the warning so safe-hold doesn't undo it, and tell the engineer so the twin can be checked.

Tests: `tests/test_round18.py` (other value, stranger, dry run, single use, expiry, hard limit) and a browser check of the button on the phone page.

## Round 26: one set of numbers

1. **"I clicked the Evidence tab at your booth. Where's the 45% → 10%? It's only on your slides."**
2. **"Your 'none of them created harm' isn't in the saved evaluation file. Where does it come from?"**
3. **"You've changed the code ten times since v20. Are the slide numbers from this version?"**
4. **"How many operator sessions is your false-block rate from? Thirty is small."**
5. **"If your new number is worse, which one goes on the slide?"**

### What we did and found (v28)

1. The Evidence tab now has a table of the held-out runs, **read from the saved files in `docs/eval/`** by a new endpoint, so the dashboard can't drift from the evidence. Test: `test_evidence_tab_reads_the_saved_evaluation`.
2. Right: at v20 the created/sooner split was printed but not saved in the JSON. Re-ran so it is.
3. Re-ran both standard-simulator evaluations on the current code (v28), seeds 300000–300199: static rules **90/200 (45%)**; Aegis **19/200 (10%)** with the attacker on the HMI PC and elsewhere; **0 created harm, 0 made much worse**, all 19 only sooner. Same as v20. Files: `docs/eval/v28_heldout_{hmi,unknown}_safehold.{txt,json}`.
4. The evaluator now runs 40 operator sessions, not 30. The first 30 are identical to v20 (382 writes, 13 twin blocks, 4 false); the 10 new ones add 132 writes and 5 more false blocks: **9 false in 514, about 1 in 57**. (High-fidelity simulator: 5 in 508.)
5. The newer, larger one. The results slide now says **1 in 57**, with "one tap on the phone lets it through" (round 25). README, one-pager, Q&A and runbook updated to match.
