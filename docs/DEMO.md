# Running the demo (for the presenter)

## The night before

1. On the laptop you'll present from: double-click `run.bat` (Windows) or run `./run.sh`. First run installs packages; afterwards it starts in seconds. Needs Python 3.10+.
2. Optional but strongly recommended: get a free key at console.groq.com, put `GROQ_API_KEY=...` in `.env`, restart, and run `python -m aegis.redteam` once. It prints how often the real model fell for the injections; that's a real number you can quote ("the model tried to raise the lye in X of 8 attacks; Aegis blocked every one").
3. Optional: Twilio trial account → fill the four `TWILIO_*` / `ALERT_TO` lines in `.env` with your own phone number. Then your phone really rings during the demo.
4. Rehearse with **▶ Guided demo** (sign in as `engineer` / `engineer`, PIN `2468`) until each step's line comes naturally. Whole run: ~3 minutes.
5. Have `docs/dashboard.png`, `docs/copilot-reply-guard.png`, `docs/operator-view.png` and an incident report open in a browser tab as a backup if the laptop misbehaves.

## Before a meeting (checklist)

1. The live site must run the latest `main`: open `https://aegis-srp7.onrender.com/api/agent/incidents`. "please log in" = new version; "Not Found" = an old deploy (Render dashboard -> the service -> Manual Deploy -> Deploy latest commit).
2. 10 minutes before: open the site (or run Actions -> **Keep demo awake** -> Run workflow), sign in as engineer, type the PIN, click **Pitch demo**, press Space through all 5 steps once. Idle time before the pitch is fine now (Nov 24 fix: the first command after 2 idle minutes used to fail).
3. Then **Pitch demo** again for the real run; it resets the plant. Step 5 scrolls to the Sentinel card; open the report link and the operator phone view from the guide, and approve the fix there to show the human-in-the-loop.
4. Backup: `run.bat` on the laptop (no network).

## Presenting from the public site (Render)

What went wrong at the expo: the Oldsmar step froze on the Render site and ate the pitch time; the pitch had never been rehearsed end to end there. Since then (branch `sentinel`): pitch steps fast-forward the simulation on the server instead of waiting on timers and show an error instead of hanging; the PIN is checked before step 1; and a presenter lock stops other visitors from changing the shared plant during your pitch.

1. **Open the site at least 2 minutes before you present.** The free plan sleeps after ~15 idle minutes; a cold start took ~30 s on Nov 19 (Render's loading screen, then the sign-in page). Keep the tab open so it stays awake.
2. Sign in as engineer, type the PIN in the **Eng. PIN** box, click **Pitch demo**. It must say **Ready**. If it says **Not ready**, the reason is on screen (sign-in or PIN), fix it before you start talking.
3. While your pitch runs, anyone else who opens the site (e.g. a judge scanning the QR code) can watch but not change anything; they see a banner. The lock ends when you close the guide, or after 15 minutes without your actions.
4. Backup, in this order: `run.bat` on the laptop (no network needed), then `docs/video/pitch-demo-backup.mp4`.
5. Do one full rehearsal on the live site after every deploy, watching Render's logs.

## The "hacker terminal" moment (makes it obviously not staged)

Aegis's guarded Modbus port is **5502 on every network interface**. Open a second terminal (or use a second laptop on the same Wi-Fi with the laptop's IP instead of 127.0.0.1):

```bash
python -m aegis.attacks lye                       # Oldsmar: lye -> 11,100 ppm
python -m aegis.attacks mask                      # the same, hidden in Mask Write (FC 22)
python -m aegis.attacks recon                     # device-ID recon + "force listen-only mode"
python -m aegis.attacks lye --host 192.168.1.23   # from another machine
```

Or with a standard third-party tool (Linux/macOS: `apt install mbpoll` / `brew install mbpoll`):

```bash
mbpoll -m tcp -a 66 -0 -1 -t 4 -r 1 -p 5502 127.0.0.1 11100     # write 11100 to the lye register
```

Any Modbus app on a phone works too (host = laptop IP, port 5502, holding register 1, unit 66). Letting a judge try it is the strongest moment you have. Windows may ask to allow Python through the firewall the first time: allow it on private networks.

## Things to say carefully (accuracy)

- Oldsmar 2021: the lye setpoint was raised from 100 to 11,100 ppm; **later reporting questioned whether it was an outside hacker**. Say "widely reported".
- July 2026: FBI/EPA PSA I-073026-PSA (Jul 30): utilities in at least seven states reported incidents since Jul 27, some degrading water operations; the targets were internet-facing **Rockwell MicroLogix 1100/1400** PLCs (source: https://www.ic3.gov/PSA/2026/PSA260730.pdf). Aegis also parses that PLC family's EtherNet/IP (PCCC) traffic, tested against the open-source pycomm3 client **on a simulated MicroLogix only**. Don't claim it would have stopped those attacks: reported activity included changing the PLCs' configuration (IP addresses, passwords), and what exactly was sent hasn't been published.
- EPA May 2024 enforcement alert: over 70% of community water systems inspected since Sept 2023 violated basic Safe Drinking Water Act §1433 requirements (source: https://www.epa.gov/enforcement/enforcement-alert-drinking-water-systems-address-cybersecurity-vulnerabilities). It's about compliance (risk assessments, emergency plans), not 70% being hacked.
- Everything Aegis measures was measured **on simulators**, one of them deliberately built with physics the twin gets wrong. **Not on a real plant.** Say that before a judge asks.
- The AI copilot: if you didn't run the red team with a real key, don't claim how often real models fall for injections.

## If something goes wrong

- Page asks you to sign in again: sessions last a shift; sign in as `engineer` / `engineer`.
- Something looks stuck: **↺ Reset plant** (keeps the audit log).
- Copilot says offline: no `GROQ_API_KEY`; skip the AI step and say what it would show.
- Port already in use: another copy is running; close it or restart the laptop.
