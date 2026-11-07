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
