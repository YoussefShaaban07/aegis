# Who pays, and why now

Facts below are from the linked primary or news sources (checked November 2026). Opinions are marked as such.

## Why now

- **July 2026: attacks on water PLCs in at least seven states.** On 30 July 2026 the FBI and EPA warned that since 27 July, water and wastewater utilities in at least seven states had reported incidents in which attackers reached internet-facing Rockwell/Allen-Bradley MicroLogix 1100/1400 PLCs, changed IP addresses and passwords ("resulting in a loss of monitoring and control functionality") and, in at least one case, modified PLC project files. Reported effects included **loss of pressure and flooding**. The first recommended mitigation: *remove PLCs from direct internet exposure, using a secure gateway or jump host.* ([FBI/EPA PSA I-073026-PSA](https://www.ic3.gov/PSA/2026/PSA260730.pdf)) Braham, Minnesota's water treatment plant was taken offline. ([ES&E Magazine](https://esemag.com/water/fbi-epa-warn-of-cyberattacks-targeting-plcs-at-multiple-u-s-water-utilities/))
- **Congress is moving.** A Congressional Research Service brief (27 Aug 2026) lists the federal programs and pending bills, including S. 4949 (WRDA 2026), which would make "reducing cybersecurity vulnerabilities" an eligible activity in a small and disadvantaged communities grant program. ([CRS IF13298](https://www.everycrsreport.com/files/2026-08-27_IF13298_480f326cd65334eddbf95a3261d9219b6631c8ff.html))
- **States are moving.** New York announced first-in-nation water cybersecurity regulations and a $2.5M SECURE grant program (up to $100,000 per system for cybersecurity upgrades) on 11 March 2026. ([NY Governor](https://www.governor.ny.gov/news/governor-hochul-announces-first-nation-cybersecurity-regulations-and-grants-protect-new-york))

## Where the money comes from

| Source | What it is | Status |
|---|---|---|
| State grants (e.g. NY SECURE) | up to $100k per system for cyber upgrades | open in NY since March 2026 |
| State and Local Cybersecurity Grant Program (CISA/FEMA) | federal pass-through to states; water is a common priority | FY2025 round of over $100M announced Aug 2025 ([CISA](https://www.cisa.gov/news-events/news/dhs-launches-over-100-million-funding-strengthen-communities-cyber-defenses)) |
| SDWA Sec. 1459F resilience grants | cybersecurity eligible; systems serving ≥10,000 people | funded since FY2023 (CRS) |
| Water Cyber Shield Act (draft, Sen. Schiff) | +$300M to the Drinking Water SRF solely for cybersecurity, prioritising smaller systems | draft outline, Aug 2026, not law ([summary](https://www.schiff.senate.gov/wp-content/uploads/2026/08/Summary_Water-Cyber-Shield-Act.pdf)) |

## What it would cost to deploy (our estimate, not a quote)

- Hardware: any small industrial PC or mini PC that runs Python. The gateway's measured overhead is ~0.2 ms per write for static checks and ~11 ms with the twin on a cloud VM; slower hardware scales that up, and SCADA polling cycles are typically ≥100 ms. Not yet measured on a Raspberry Pi or industrial PC.
- Software: open source (MIT). A business would sell setup, register-map configuration, calibration and support, or a hosted dashboard. (Opinion: grant-funded "assessment + install" packages are the realistic first sale to small utilities.)

## Honest competitive picture

- **Industrial DPI firewalls** (e.g. Tofino Modbus enforcer, and similar products from large OT-security vendors) already filter Modbus function codes and register ranges. That's a real, mature market.
- **OT monitoring platforms** (Dragos, Claroty, Nozomi) detect anomalies passively, at enterprise price points.
- **Where Aegis differs:** it is physics-aware (the twin predicts the water, it doesn't just check numbers), it checks the PLC's honesty against chemistry, it is built for AI writers (propose → approve, forecasts on proposals), and it is aimed at systems too small for the platforms above. **Not yet proven** in a real plant.
- **Gap to state plainly:** the July 2026 attacks hit Rockwell MicroLogix PLCs, which mainly speak Rockwell's own protocols (EtherNet/IP/PCCC). Aegis speaks Modbus TCP today. Its gateway placement is what the FBI recommends; supporting EtherNet/IP would be the next protocol.
