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
