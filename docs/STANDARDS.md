# How Aegis maps to the standards utilities use

**Read this first:** using Aegis does not make a system compliant with anything, and Aegis has not been assessed or certified against any standard. This page says which requirements Aegis *helps* a utility meet, how, and where it falls short, so an engineer or manager can judge it. Requirement names are quoted from the sources linked at the bottom; only requirements we could verify are listed.

## IEC 62443-3-3 (system security requirements for industrial control systems)

| Requirement | What Aegis does | Gap |
|---|---|---|
| SR 1.1 Human user identification and authentication | Named dashboard accounts; every action attributed to a user (`aegis/auth.py`) | No MFA; no directory (AD/LDAP) integration |
| SR 1.2 Software process and device identification and authentication | — | **Not met.** Modbus has no device authentication; Aegis labels writers by unit ID and IP, which can be spoofed. Its rules apply to every writer regardless of label |
| SR 1.7 Strength of password-based authentication | scrypt hashes, minimum length, lockout after 5 failures | No complexity or rotation rules |
| SR 2.1 Authorization enforcement | Roles (viewer/operator/engineer) + engineer PIN; every Modbus write authorized against the safety policy; single-use permits for critical commands | |
| SR 2.8 Auditable events | Every decision, login, failed login, denied action, rule change, mode change, permit, proposal, acknowledgement, calibration and integrity event | |
| SR 2.9 Audit storage capacity | Local SQLite + optional off-box syslog | No built-in rotation or size alarms |
| SR 3.1 Communication integrity | — | **Not met for Modbus** (no TLS / Modbus Security). The audit log's integrity is protected (HMAC chain), not the wire |
| SR 3.5 Input validation | Core function: every write is checked (function code, register allowlist, range, step, ramp, cycling, interlocks, permits, twin forecast); parser fuzz-tested with 50,000 random inputs | |
| SR 5.1 Network segmentation | Designed to sit at the boundary between the HMI/business network and the PLC network | Segmentation itself (firewall rules, VLANs) is the utility's job; Aegis assumes it |
| SR 5.2 Zone boundary protection | Aegis *is* a boundary device (a deep-inspection conduit) for Modbus TCP: default-deny on function codes and registers | Other protocols (EtherNet/IP, DNP3, S7) must be blocked at the firewall |
| SR 6.1 Audit log accessibility | Dashboard, CSV export, incident report, syslog | |
| SR 6.2 Continuous monitoring | Integrity monitor (is the PLC telling the truth?), twin early warnings, setpoint drift, read/write flood detection, health endpoint | |
| SR 7.1 Denial of service protection | Write flood limits (per label and per IP), read rate limits, connection caps, idle timeouts, read coalescing; fail-closed on internal errors | A volumetric network flood is the network's problem |
| SR 7.6 Network and security configuration settings | Policy, register map and process model are explicit config files; policy file signed (HMAC), edits outside Aegis detected and alerted | |

## CISA Cross-Sector Cybersecurity Performance Goals (CPG v1.0.1)

| Goal | What Aegis does | Gap |
|---|---|---|
| 2.X Limit OT Connections to Public Internet | The PLC sits behind the gateway instead of being reachable directly; this is the first mitigation in the FBI/EPA alert of 30 July 2026 | Only if the PLC is actually firewalled so that Aegis is the only path |
| 2.F Network Segmentation | Supports a segmented design (Aegis as the conduit) | Segmentation itself is the utility's job |
| 2.C Unique Credentials | Named accounts per person; no shared "operator" login in production (`AEGIS_DEMO=0`) | |
| 2.K Phishing-Resistant MFA | — | **Not met** |
| 2.T Log Collection | Every security-relevant event logged | |
| 2.U Secure Log Storage | HMAC-keyed hash chain; head hash in reports; off-box syslog copy | |
| 3.A Detecting Relevant Threats and TTPs | Detections mapped to MITRE ATT&CK for ICS (T0855, T0836, T0806, T0831, T0814, T0888, T0843, T0826, T0879) | Signatures for non-Modbus TTPs (e.g. ladder-logic changes) aren't visible to Aegis |
| 4.C Incident Reporting | Draft incident report generated from the audit log (timeline, ATT&CK, evidence integrity) | Reporting to authorities is a human decision |

## NIST Cybersecurity Framework 2.0 (by function)

- **Identify**: register discovery on the wire and onboarding from the PLC's tag export (`aegis/onboard.py`).
- **Protect**: the guard itself; roles and authentication; permits for critical commands; signed policy.
- **Detect**: integrity monitor, early warnings, unusual-value alerts, flood and read-flood detection, setpoint changes made outside Aegis.
- **Respond**: grouped incidents, SMS/call with escalation, acknowledgement, incident report.
- **Recover**: limited. Monitor/off modes and a documented break-glass bypass; Aegis doesn't restore PLC programs or backups.

## Sources

- IEC 62443-3-3 requirement names: [Open Security Architecture, IEC 62443](https://opensecurityarchitecture.org/frameworks/iec-62443)
- CISA CPGs: [CISA CPG Report v1.0.1](https://www.cisa.gov/sites/default/files/2023-03/CISA_CPG_REPORT_v1.0.1_FINAL.pdf). (CISA has since published CPG 2.0; IDs may differ there.)
- FBI/EPA alert: [PSA I-073026-PSA, 30 July 2026](https://www.ic3.gov/PSA/2026/PSA260730.pdf)
