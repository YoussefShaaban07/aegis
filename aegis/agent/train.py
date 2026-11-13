"""Rebuild Sentinel's case base from DEVELOPMENT seeds (never the held-out evaluation seeds).

  python -m aegis.agent.train                    # generate seeds 0-19 and train (about 10 minutes)
  python -m aegis.agent.train --rows rows.json   # train from features saved by a previous run
"""
from __future__ import annotations

import argparse
import json
import sys
import time

from . import dataset as D
from . import features as FT
from .casebase import DEFAULT_PATH, CaseBase

DEV_SEEDS = range(0, 20)        # held-out evaluation uses 300000+


def generate(seeds=DEV_SEEDS, noise=True) -> list[dict]:
    from ..config import Tags, load_policy
    pol = load_policy(Tags.load())
    s = list(seeds)
    gens = [(lambda x: D.attack_cases(x, "unknown", pol, noise), s), (lambda x: D.attack_cases(x, "hmi", pol, noise), s),
            (lambda x: D.operator_cases(x, pol, noise), range(s[0], s[0] + 6 * len(s))),
            (lambda x: D.plc_cases(x, pol, noise), s[: max(1, 3 * len(s) // 4)]),
            (lambda x: D.ai_cases(x, pol, noise), s[: max(1, len(s) // 2)])]
    rows, t0 = [], time.time()
    for fn, seeds_ in gens:
        for x in seeds_:
            for c in fn(x):
                rows.append({"cid": c.cid, "label": c.label, "meta": c.meta, "F": FT.extract(c.evidence())})
        print(f"  {len(rows)} cases, {time.time() - t0:.0f} s", file=sys.stderr)
    return rows


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--rows", help="JSON rows with label and F (feature values or {value, ids} dicts)")
    ap.add_argument("--save-rows", help="also save the generated rows here")
    ap.add_argument("--out", default=str(DEFAULT_PATH))
    a = ap.parse_args(argv)
    if a.rows:
        rows = json.load(open(a.rows))
        for r in rows:
            r["F"] = {k: (v if isinstance(v, dict) and "value" in v else {"value": v}) for k, v in r["F"].items()}
        src = a.rows
    else:
        rows = generate()
        src = f"dataset seeds {DEV_SEEDS.start}-{DEV_SEEDS.stop - 1}"
        if a.save_rows:
            json.dump([{**r, "F": {k: v["value"] for k, v in r["F"].items()}} for r in rows],
                      open(a.save_rows, "w"), default=str)
    cb = CaseBase.train(rows, meta={"source": src, "seeds": "development only (0-19)", "noise": True})
    cb.save(a.out)
    print(f"trained on {len(rows)} incidents: {cb.data['class_counts']} -> {a.out}")


if __name__ == "__main__":
    main()
