# Judge Q&A prep

Short answers in plain words. Say the **bold line** first; add the rest only if they ask more.

---

**1. What is it, in one sentence?**
**A box between a water plant's control screens and its controller that checks every command and blocks the ones that would make the water unsafe.**

**2. Why can't the plant just put limits in the PLC?**
**Most small plants run 20-year-old PLC programs nobody dares to edit.** The integrator who wrote them is gone, and a mistake stops the plant. Aegis protects them without touching the PLC.

**3. Isn't this just a firewall?**
**A firewall checks *who* is talking; Aegis checks *what the command will do to the water*.** Products like Tofino filter Modbus values and have done since 2009. What's new here is the digital twin: it blocks a change that's inside every limit but makes the water unsafe hours later.

**4. How does the digital twin "know" the water will be unsafe?**
**It's the textbook water chemistry (carbonate buffering, chlorine decay) fitted to this plant, run 6 hours ahead.** We checked its chemistry against PHREEQC, the U.S. Geological Survey's reference program: 0.05 pH apart on average over 100 cases. It runs several versions with different assumptions and blocks if the bad cases are bad.

**5. Does it work? What's the evidence?**
**200 simulated attacks on held-out test cases: plain rules let 45% make the water unsafe, Aegis 10%.** And none of Aegis's 10% created the problem: in every one, a storm or algae bloom made the water unsafe *without* the attacker too (nobody answers alarms in this test). With plain rules, 52 attacks created harm on their own.

**6. But it's all simulated.**
**Yes, and we say so.** It hasn't run at a real plant or on a real PLC yet. It is tested against independent Modbus and EtherNet/IP software (pymodbus, libmodbus, pycomm3) and the chemistry against PHREEQC. Next step: a bench test on a real MicroLogix, then one pilot utility.

**7. Was Oldsmar even a hack?**
**Maybe not; the city's former manager said in 2023 it was probably an employee mistake. Aegis doesn't care: it stops 11,100 ppm lye whether a hacker or a tired operator typed it.**

**8. What if the hacker is *on* the operator's PC?**
**We tested exactly that: the attacker sends commands as the real operator. Same 10%.** Aegis still checks every command, and the things that undo protection (releasing a hold, clearing a lockdown) need a login, which a network packet can't do.

**9. Won't it block the operators and annoy them?**
**In simulation, 4 wrong blocks out of 382 operator changes.** When it blocks, it says why and what *is* safe. Changes that fix a problem are always allowed. It starts in watch-only mode for weeks before it blocks anything.

**10. Won't it spam texts?**
**We simulated a full year: about 9 texts a week, and only 24 on calm days in the whole year, about one every two weeks.**

**11. What if the Aegis box breaks?**
**The plant keeps running on its last settings; the PLC doesn't need Aegis.** It restarts itself in seconds. If it stays down, there's a labelled break-glass cable that connects the screens straight to the PLC.

**12. What does it do if nobody answers at 3 AM?**
**Safe-hold: it texts first, waits 15 minutes, then puts back the last setting the plant actually ran at that keeps the water safe, and holds it until someone logs in.** It never invents new settings and never starts or stops pumps.

**13. Why is there AI in a water plant?**
**Utilities are starting to use AI assistants, and they can be tricked.** Our demo shows an AI that reads a poisoned work order and tries to raise lye to 9,000; Aegis blocks it like any other command. The AI can only *propose*.

**14. Why didn't the government do this?**
**It can't install equipment in 50,000 locally owned plants, and its 2023 attempt at just a cybersecurity *checklist* was withdrawn after a lawsuit over cost.** Its own advice is to put PLCs behind a secure gateway. Aegis is that gateway, cheap enough for a 3-person utility.

**15. How would you make money?**
**About $1,500 setup and $100 a month for a small town; it costs about $50 a year to run.** Sold through the Rural Water Association and the integrators who already service these plants, starting with free watch-only pilots.

**16. Did you use AI to build this?**
**Yes. I used Claude as a coding assistant; I designed the approach, directed every round of "what would a judge attack next", and checked the results.** *(Answer honestly and confidently; don't wait to be caught.)*

**17. What's the hardest thing you got wrong and fixed?**
**Our own evaluation was biased:** reading the simulated sensors changed the simulated weather, so some weather harm was blamed on attackers. We found it, fixed it, re-ran everything, and the README says so.

---

**18. Our wells are on serial radios, not Ethernet. Does it work?**
**Yes, if the radio link ends in an Ethernet bridge or serial device server: Aegis speaks Modbus RTU over TCP on either side.** Tested with a third-party library (pymodbus) on both sides. A PLC with only an RS-485 port needs a serial device server (about $100); native serial isn't built.

**19. What if the attacker steals the operator's password?**
**They still can't make the water unsafe: the guard doesn't care who's logged in, only what the command does.** After 6 refusals the source is locked down, and the locked-down PC can't unlock itself even with the right password; it has to be cleared from another device, like the on-call phone.

## The expo: 2.5-minute pitch with live demo
Before you start: dashboard open, signed in as **engineer**, PIN **2468** in the header, press **Pitch demo** once (it resets the plant and waits).
Slides: cover → problem → how → demo → results → ask. On the demo slide, Alt-Tab to the dashboard and press **Space once per step** (it moves on and runs the step):
1. Guard OFF → Oldsmar attack → lye box turns red.
2. Guard ON → same attack → BLOCKED.
3. Algae bloom → a small, legal-looking +50 lye change → BLOCKED by the twin's forecast; cutting lye still allowed.
4. The poisoned AI work order → BLOCKED.
Alt-Tab back to the slides. If the laptop or server fails, play `docs/video/pitch-demo-backup.mp4` and say the same lines.
Between pitches: press **Booth loop**. It repeats the three blocked attacks with big captions; any click stops it.

