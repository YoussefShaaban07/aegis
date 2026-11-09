# Aegis: one page

**Problem.** About 50,000 US community water systems run on controllers (PLCs) that accept any command from anyone on the network: no password, no check. In July 2026 attackers targeted more than 100 water systems (CISA); FBI and EPA confirmed incidents in at least seven states, on Allen-Bradley MicroLogix controllers, changing IP addresses, passwords and programs. Most utilities serve small towns with 2–5 staff and no security team. Enterprise industrial-security products are built for big utilities; the EPA's 2023 attempt at a cybersecurity requirement was withdrawn after a lawsuit over cost and expertise.

**Product.** A small box between the operators' screens (HMI) and the PLC. Every command passes through it:
1. **Rules**: range, step, ramp, interlocks, permits for critical commands. It refuses PLC mode changes, program downloads and IP-address changes: the actions in the July attacks (tested).
2. **Digital twin**: a chemistry model of *this* plant forecasts where each command takes the water over the next 6 hours, and blocks commands that pass every rule but end in unsafe water (a legal-looking lye increase during an algae bloom).
3. **Early warning + safe-hold**: operators are texted hours before a limit is crossed; if nobody answers, Aegis restores the last setting that keeps the water safe and holds it until someone logs in.
4. **Is the PLC lying?** If the water stops matching the chemistry of what Aegis approved, it alarms (catches malware inside the PLC) and becomes more conservative.
5. **AI-safe**: an AI copilot can only propose; Aegis checks its proposals like any other command.
6. **Stolen passwords don't help**: a source refused 6 times is locked down, and a locked-down PC can't unlock itself even with the right password.

Speaks **Modbus TCP, Modbus RTU over TCP (radio links to well sites) and EtherNet/IP (Allen-Bradley MicroLogix/SLC)**, the PLC family in this year's attacks. Covers lye (or lime, soda ash), chlorine (bleach or gas) and fluoride feeds. Starts in watch-only mode; no PLC reprogramming.

**Evidence (simulated plant, measured, not assumed).**

| | Attacks that made water unsafe (200 held-out episodes, nobody answering alarms) |
|---|---|
| Static rules only | 45% |
| Aegis | **10%**, including attackers sitting on the operator's own HMI, and **none** of those created harm: in every one, the same storm or bloom made the water unsafe without the attacker too (the attacker only made it sooner). Static rules: 52 attacks created harm. |

- Operator cost: 9 false twin blocks in 514 simulated operator writes (about 1 in 57), each one can be let through with *Allow this value once*; no operator was ever locked down.
- A simulated year: **about 10 texts a week**, 24 on calm days in the whole year; 1 of 2,384 operator changes blocked.
- Adds ~0.2 ms per command (static rules), ~13 ms with the twin.
- 222 automated tests; tested against independent Modbus and EtherNet/IP clients (pymodbus, libmodbus, pycomm3).

**Not yet done (said plainly).** Not tested on a real plant or real PLC hardware; the twin's chemistry matches the USGS reference code PHREEQC (mean 0.05 pH over 100 cases) but has not been checked against real plant data; no utility has used it yet.

**Business.** Hardware + yearly subscription, priced by town size: about **$1,500 setup and $100/month** for a small system. It runs for about $50/year in electricity and texts. Reached through the Rural Water Association and the integrators who already service plant PLCs; free 60–90-day watch-only pilots; grant- and insurer-ready reporting.

**Next.** A bench test on a real MicroLogix; one pilot utility in Mississippi.

*Youssef Shaaban · Computer Engineering, University of Southern Mississippi · github.com/YoussefShaaban07/aegis*
