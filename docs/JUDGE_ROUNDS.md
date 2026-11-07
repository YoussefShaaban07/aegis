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
