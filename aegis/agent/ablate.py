"""Ablations (spec section 13.4): which signals does Sentinel's decision actually rest on?

For each group of signals, the group is removed from EVERYTHING (the rule baseline sees it as absent, and the
learned classifier is retrained on the training rows without it), then both are scored on held-out rows.

  python -m aegis.agent.ablate --train rows_train.json --test rows_heldout.json --out docs/eval/sentinel_ablation

Rows come from `python -m aegis.agent.train --save-rows` (or the same format): {"cid", "label", "F": {name: value}}.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from . import baseline as B
from .casebase import CaseBase
from .eval import macro_f1
from .loop import combine

GROUPS = {
    "human presence": ("human_present", "human_actions"),
    "source identity (profile, IP vs label, hours)": ("source_known", "ip_matches_label", "registered_source",
                                                      "off_hours"),
    "behaviour (push, probe, rhythm, persistence, retries, typos)": (
        "regular_interval", "probing", "monotone_push", "push_length", "writes_after_block", "correction_follows",
        "flood_rate", "retry_after_block", "typo_like"),
    "twin forecasts (counterfactual, weather risk)": ("harm_forecast_without_writes", "writes_make_forecast_worse",
                                                      "reverses_trend", "weather_aligned"),
    "integrity alarm numbers": ("integrity_ph_predicted", "integrity_alk_err", "integrity_cl_err",
                                "mismatch_on_steep_curve"),
}
ATTACK = ("external_attack", "compromised_trusted_source", "ai_manipulation")


def _load(path):
    rows = json.load(open(path))
    for r in rows:
        r["F"] = {k: (v if isinstance(v, dict) and "value" in v else {"value": v}) for k, v in r["F"].items()}
    return rows


def _drop(rows, keys):
    return [{**r, "F": {k: v for k, v in r["F"].items() if k not in keys}} for r in rows]


def score(train, test) -> dict:
    cb = CaseBase.train(train)
    classes = sorted({r["label"] for r in test})
    out = {}
    preds = []
    for r in test:
        b = B.classify(r["F"])
        lm = cb.predict(r["F"])
        preds.append((r, b["primary"], lm["primary"], combine(b, lm, r["F"])[0]))
    for i, name in ((1, "rules"), (2, "learned"), (3, "sentinel")):
        pairs = [(r["label"], p[i]) for p in preds for r in [p[0]]]
        op = [(t, q) for t, q in pairs if t in ("operator_error", "benign_false_positive")]
        hmi = [(t, q) for t, q in pairs if t == "compromised_trusted_source"]
        out[name] = {"accuracy": round(sum(t == q for t, q in pairs) / len(pairs), 4),
                     "macro_f1": round(macro_f1(pairs, classes), 4),
                     "hmi_recall": round(sum(t == q for t, q in hmi) / max(1, len(hmi)), 4),
                     "operator_false_escalation": round(sum(q in ATTACK for _, q in op) / max(1, len(op)), 4)}
    return out


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--train", required=True)
    ap.add_argument("--test", required=True)
    ap.add_argument("--out", default="docs/eval/sentinel_ablation")
    a = ap.parse_args(argv)
    train, test = _load(a.train), _load(a.test)
    res = {"all signals": score(train, test)}
    for g, keys in GROUPS.items():
        res[f"without {g}"] = score(_drop(train, set(keys)), _drop(test, set(keys)))
    L = [f"# Sentinel ablations ({len(test)} held-out incidents, trained on {len(train)})", "",
         "Each group is removed from the rule baseline and from the learned classifier (retrained without it).", "",
         "| Signals | Sentinel accuracy | Macro-F1 | Compromised-HMI recall | Operator incidents called an attack | "
         "Rules accuracy |", "|---|---|---|---|---|---|"]
    for k, v in res.items():
        s = v["sentinel"]
        L.append(f"| {k} | {100 * s['accuracy']:.1f}% | {s['macro_f1']:.3f} | {100 * s['hmi_recall']:.0f}% | "
                 f"{100 * s['operator_false_escalation']:.1f}% | {100 * v['rules']['accuracy']:.1f}% |")
    md = "\n".join(L) + "\n"
    Path(a.out + ".md").write_text(md)
    Path(a.out + ".json").write_text(json.dumps(res, indent=1))
    print(md)


if __name__ == "__main__":
    main()
