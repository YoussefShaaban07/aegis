# Aegis operator runbook

One page for the people on shift. Print it and keep it by the HMI.

## A text from Aegis arrives

| Text says | What it means | What to do |
|---|---|---|
| **Twin forecast: … will go above/below … in about N min** | At current settings the water leaves its safe range in N minutes. Nothing has gone wrong yet. | Open the Aegis console on your phone or PC (the address your engineer gave you), **Acknowledge** so Aegis knows a person is on it, and correct the trend: the console shows which reading is heading where, and when. |
| **Acknowledge within 15 min if you're handling it; otherwise Aegis will restore the earlier setting** | Safe-hold is counting down. | If you're handling it, **Acknowledge**. If you can't get to it, let it act: it only restores a setting the plant ran at in the last 12 h. |
| **Twin forecast still unsafe … 60 min after it was acknowledged** | Your acknowledgement ran out and the forecast is still bad. | Acknowledge again if you're still on it. |
| **Blocked … from setting …** | Someone or something sent a command Aegis refused. The plant didn't change. | If it was you, read the reason on the dashboard: it says what *is* allowed. If it wasn't anyone on shift, call your supervisor: treat it as a possible intrusion. Do not switch Aegis off to "make it work". |
| **Blocked …** and you're sure the change is right (Aegis's forecast is wrong) | The twin is sometimes wrong (about 1 in 100 operator changes in testing). | On the console, under *Recently blocked*, press **Allow this value once** from your phone or any device other than the one that was blocked. That exact value goes through once in the next 30 min; hard limits still apply; everyone on call is told. Send it again from the HMI, and **Acknowledge** the forecast warning so safe-hold doesn't undo it. Tell the engineer so the twin can be checked. |
| **SAFE-HOLD: … restored to …** | Aegis undid a change because nobody answered. That setting is held. | Check the plant. To change that setting again, log in and press **Release hold** (needs your login; it's logged). |
| **SAFE-HOLD COULD NOT ACT** | Aegis tried to fix the trend and the PLC refused or couldn't be reached. | **Go to the plant.** The water is heading out of range and nothing automatic is fixing it. |
| **Process alarm …** | The water is out of range now. | Your normal alarm procedure. |
| **Lab … is N h old** / **lab … disagrees with the plant** | The digital twin is paused (static rules still protect). | Run and enter today's titration (`python -m aegis.labinputs set raw_alkalinity VALUE --by NAME`). If the sample really is that unusual, an engineer can confirm it (`--confirm`). |
| **Integrity: … MISMATCH** | The water isn't behaving the way the approved settings say it should: a failed instrument, a chemical feed problem, or a compromised PLC. | Take a grab sample and compare (dashboard → *Take sample*). Call your supervisor. |

## The guard modes

- **ENFORCE**: normal. Unsafe commands are blocked.
- **MONITOR**: nothing is blocked; Aegis only records what it *would* block. For the trial period only.
- **OFF**: everything passes, and every on-call contact is alerted. Needs the engineer PIN.

## If the Aegis box itself fails

You lose the HMI's connection to the PLC; the plant keeps running on its last settings (the PLC doesn't need Aegis).

1. Check the box has power. It restarts itself within seconds after a crash.
2. Still down after 2 minutes: use the **break-glass cable** (labelled, in the cabinet). Unplug the PLC's cable from the Aegis box and plug it into the port labelled **BYPASS**. The HMI talks to the PLC directly again, **unprotected**.
3. Tell your supervisor and the engineer. Put the cable back once Aegis is fixed.

## Things Aegis will never do on its own

- start or stop a pump;
- set a value the plant hasn't run at in the last 12 hours;
- act while you've acknowledged, while the sensors look untrustworthy, or in MONITOR mode.

## At installation: make sure nothing can go around Aegis

Aegis only protects commands that pass through it. The July 2026 attacks reached controllers that were open to the internet; Aegis in front of a controller that is *also* still reachable some other way stops nothing.

1. The PLC's network cable goes into the Aegis box's PLC port, and nothing else is plugged into the PLC's network.
2. From the internet side and from the office network, check that the PLC's ports (502 for Modbus, 44818 for EtherNet/IP) answer only through Aegis. A free port scan from outside (or your integrator) will tell you.
3. Remote-access tools (TeamViewer, port forwards on the router, a vendor's cellular modem) that reach the PLC directly: remove them, or route them through Aegis.
4. Run Aegis in **monitor** mode for the first week. Every write it would have blocked shows up in the log without being blocked; read them with the integrator before switching to **enforce**.
