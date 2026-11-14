# Evaluation output

Everything here is generated; nothing is hand-edited.

- Plain JSON: the runs the README, the slides and the dashboard's Evidence tab use (v27, v28, alert_load_v31,
  PHREEQC validation). The dashboard reads the v27/v28 files directly.
- `*.json.gz`: earlier runs, kept for the record and compressed so they don't dominate the repo
  (they were about 400,000 of its 428,000 tracked lines). Read one with
  `python -c "import gzip,json;print(json.load(gzip.open('docs/eval/NAME.json.gz','rt'))['summary'])"`
  or `zcat docs/eval/NAME.json.gz | head`.
- `*.txt` / `*.md`: the human-readable summary of each run.
- `sentinel_v1` / `sentinel_v2`: the Sentinel agent's held-out evaluations (`python -m aegis.agent.eval`).
