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
