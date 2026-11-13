"""Sentinel evaluation on HELD-OUT seeds (training used 0-19).

  python -m aegis.agent.eval --seed-offset 300000 --n 100 --out docs/eval/sentinel_v1

Compares, on the same incidents: the rule baseline, the learned classifier alone, and Sentinel's
deterministic decision (learned when confident, else rules). Also measures citation validity, how many
recovery steps the guard's own checks would block, and the AI-injection cases. Results are written as
JSON and Markdown; nothing is hand-edited.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path

from . import dataset as D
from .casebase import CaseBase
from .loop import Sentinel


def macro_f1(pairs, classes):
    f1s = []
    for c in classes:
        tp = sum(1 for t, p in pairs if t == c and p == c)
        fp = sum(1 for t, p in pairs if t != c and p == c)
        fn = sum(1 for t, p in pairs if t == c and p != c)
        if tp + fn == 0:
            continue
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn)
        f1s.append(2 * prec * rec / (prec + rec) if prec + rec else 0.0)
    return sum(f1s) / len(f1s) if f1s else 0.0


def guard_would_block(policy, step, state) -> bool:
    """Static guard checks (range/step/ramp/interlocks) on a proposed step, from the recorded readings."""
    from ..evaluate import Clock
    from ..guard import Guard
    g = Guard(None, lambda: state, policy=policy, clock=Clock(), twin=None)
    g.sync_commanded(state)
    d = g.check(step["register"], step["value"], state, "Sentinel", "proposal", dry_run=True)
    return not d.allowed


def run(seed_offset: int, n: int, noise: bool, progress=True) -> dict:
    from ..config import Tags, load_policy
    pol = load_policy(Tags.load())
    cb = CaseBase.load()
    seeds = range(seed_offset, seed_offset + n)
    jobs = ([("unknown", s) for s in seeds] + [("hmi", s) for s in seeds]
            + [("operator", s) for s in range(seed_offset, seed_offset + 6 * n)]
            + [("plc", s) for s in range(seed_offset, seed_offset + max(1, n * 3 // 4))]
            + [("ai", s) for s in range(seed_offset, seed_offset + max(1, n // 2))])
    rows, t0 = [], time.time()
    for k, (kind, s) in enumerate(jobs):
        if kind in ("unknown", "hmi"):
            cases = D.attack_cases(s, kind, pol, noise)
        elif kind == "operator":
            cases = D.operator_cases(s, pol, noise)
        elif kind == "plc":
            cases = D.plc_cases(s, pol, noise)
        else:
            cases = D.ai_cases(s, pol, noise)
        for c in cases:
            sen = Sentinel(c.audit, c.history, policy=pol, casebase=cb, mode="deterministic")
            r = asyncio.run(sen.investigate(c.incident, now=c.now))
            state = (c.history.at(c.now) or (0, {}))[1]
            steps = r["recovery"].get("steps") or []
            rows.append({"cid": c.cid, "label": c.label, "kind": kind, "meta": {k2: c.meta.get(k2) for k2 in
                                                                              ("goal", "strategy", "weather", "human",
                                                                               "kind", "injection")},
                         "baseline": r["baseline"]["primary"], "learned": (r["learned"] or {}).get("primary"),
                         "sentinel": r["verdict"]["classification"]["primary"],
                         "confidence": r["verdict"]["classification"]["confidence"],
                         "validity": r["validation"]["validity"], "claims": r["validation"]["checked"],
                         "removed": len(r["removed"]), "steps": [(x["register"], x["value"]) for x in steps],
                         "steps_guard_blocked": sum(guard_would_block(pol, x, state) for x in steps),
                         "elapsed_s": r["elapsed_s"]})
        if progress and (k % 20 == 0 or k == len(jobs) - 1):
            print(f"  {k + 1}/{len(jobs)} episodes, {len(rows)} incidents, {time.time() - t0:.0f} s", file=sys.stderr)
    return {"seed_offset": seed_offset, "n": n, "noise": noise, "rows": rows, "seconds": round(time.time() - t0)}


def summarise(res: dict) -> dict:
    rows = res["rows"]
    classes = sorted({r["label"] for r in rows})
    out = {"incidents": len(rows), "by_class": dict(Counter(r["label"] for r in rows)), "systems": {}}
    for sysname in ("baseline", "learned", "sentinel"):
        pairs = [(r["label"], r[sysname]) for r in rows]
        cm = defaultdict(Counter)
        for t, p in pairs:
            cm[t][p] += 1
        out["systems"][sysname] = {"accuracy": round(sum(t == p for t, p in pairs) / len(pairs), 4),
                                   "macro_f1": round(macro_f1(pairs, classes), 4),
                                   "per_class_recall": {c: round(cm[c][c] / max(1, sum(cm[c].values())), 3)
                                                        for c in classes},
                                   "confusion": {c: dict(cm[c]) for c in classes}}
    op = [r for r in rows if r["label"] in ("operator_error", "benign_false_positive")]
    attackish = ("external_attack", "compromised_trusted_source", "ai_manipulation")
    out["false_escalation_on_operator"] = {s: round(sum(r[s] in attackish for r in op) / max(1, len(op)), 4)
                                           for s in ("baseline", "learned", "sentinel")}
    ai = [r for r in rows if r["label"] == "ai_manipulation"]
    out["ai_cases"] = {"n": len(ai), "detected_as_ai_manipulation": sum(r["sentinel"] == "ai_manipulation" for r in ai),
                       "recovery_steps_filed": sum(len(r["steps"]) for r in ai)}
    out["citation_validity_min"] = min((r["validity"] for r in rows), default=1.0)
    out["claims_checked"] = sum(r["claims"] for r in rows)
    out["claims_removed"] = sum(r["removed"] for r in rows)
    out["recovery_steps"] = sum(len(r["steps"]) for r in rows)
    out["recovery_steps_guard_would_block"] = sum(r["steps_guard_blocked"] for r in rows)
    out["median_s_per_incident"] = sorted(r["elapsed_s"] for r in rows)[len(rows) // 2] if rows else None
    out["plc_episodes_undetected"] = sum(1 for p in D.PLC_STATS if p["incidents"] == 0)
    out["plc_episodes"] = len(D.PLC_STATS)
    return out


def markdown(res: dict, s: dict) -> str:
    L = [f"# Sentinel evaluation (held-out seeds {res['seed_offset']}+, noise={'on' if res['noise'] else 'off'})", "",
         f"{s['incidents']} incidents: {s['by_class']}. Generated by `python -m aegis.agent.eval`; "
         f"{res['seconds']} s.", "", "| System | Accuracy | Macro-F1 | False escalation on operator incidents |",
         "|---|---|---|---|"]
    for k, name in (("baseline", "Rule baseline"), ("learned", "Learned classifier"),
                    ("sentinel", "Sentinel (deterministic decision)")):
        m = s["systems"][k]
        L.append(f"| {name} | {100 * m['accuracy']:.1f}% | {m['macro_f1']:.3f} | "
                 f"{100 * s['false_escalation_on_operator'][k]:.1f}% |")
    L += ["", "Per-class recall:", "", "| Class | Baseline | Learned | Sentinel |", "|---|---|---|---|"]
    for c in sorted(s["by_class"]):
        L.append(f"| {c} | " + " | ".join(f"{100 * s['systems'][k]['per_class_recall'][c]:.0f}%"
                                         for k in ("baseline", "learned", "sentinel")) + " |")
    L += ["", f"- Citation validity (minimum over incidents): {100 * s['citation_validity_min']:.0f}%; "
          f"{s['claims_checked']} claims checked, {s['claims_removed']} removed.",
          f"- Recovery steps proposed: {s['recovery_steps']}; the guard's static checks would block "
          f"{s['recovery_steps_guard_would_block']}.",
          f"- AI-injection incidents: {s['ai_cases']['detected_as_ai_manipulation']}/{s['ai_cases']['n']} classified as "
          f"ai_manipulation; recovery steps filed for them: {s['ai_cases']['recovery_steps_filed']}.",
          f"- PLC/sensor episodes with no incident at all (nothing detected): {s['plc_episodes_undetected']}/"
          f"{s['plc_episodes']}.",
          f"- Median time per incident: {s['median_s_per_incident']} s (deterministic path, no model).", "",
          "Limitations: labels come from Aegis's own simulators; no real model was evaluated here (no API key); "
          "recovery steps are checked with the twin and the guard's static rules, not against the true plant.", ""]
    return "\n".join(L)


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--seed-offset", type=int, default=300000)
    ap.add_argument("--n", type=int, default=100)
    ap.add_argument("--no-noise", action="store_true")
    ap.add_argument("--out", default="docs/eval/sentinel_v1")
    a = ap.parse_args(argv)
    res = run(a.seed_offset, a.n, not a.no_noise)
    s = summarise(res)
    out = Path(a.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    import gzip
    with gzip.open(str(out) + ".json.gz", "wt") as f:          # compressed: eval output must not bloat the repo
        json.dump({"summary": s, **res}, f, default=str)
    Path(str(out) + ".md").write_text(markdown(res, s))
    print(markdown(res, s))


if __name__ == "__main__":
    main()
