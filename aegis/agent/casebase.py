"""What Sentinel learned from past incidents: a case library and a small learned classifier.

Training data are labelled incidents from the simulators (aegis/agent/dataset.py) on DEVELOPMENT seeds
only; evaluation uses held-out seeds. `python -m aegis.agent.train` rebuilds aegis/agent/data/casebase.json.

At run time, for a new incident Sentinel
  * retrieves the k most similar past incidents (standardised feature distance) with their true class and
    the response that was right for them, and shows them to the model as worked examples;
  * scores the incident with a multinomial logistic regression trained on the same features (pure Python,
    no new dependency), which the report shows next to the rule baseline.
Neither replaces the evidence: the model must still cite audit entries for every claim.
"""
from __future__ import annotations

import json
import math
import random
from pathlib import Path

from .features import vector, vector_names
from .recovery import CONTAIN

DEFAULT_PATH = Path(__file__).resolve().parent / "data" / "casebase.json"
SUMMARY_KEYS = ("primary_source", "source_known", "ip_matches_label", "human_present", "monotone_push", "probing",
                "regular_interval", "writes_after_block", "correction_follows", "recon_fc", "flood_rate", "n_blocked",
                "block_checks", "drift_without_decision", "physics_mismatch", "lab_disagrees", "ai_origin",
                "harm_forecast_without_writes", "writes_make_forecast_worse", "weather_aligned")


META_KEYS = ("seed", "goal", "strategy", "weather", "kind", "injection", "human")


def _softmax(z):
    m = max(z)
    e = [math.exp(x - m) for x in z]
    s = sum(e)
    return [x / s for x in e]


def fit_logreg(X, y, classes, l2=0.01, epochs=300, lr=0.5, seed=0):
    """Multinomial logistic regression by full-batch gradient descent with class-balanced weights."""
    k, d = len(classes), len(X[0])
    W = [[0.0] * d for _ in range(k)]
    b = [0.0] * k
    idx = {c: i for i, c in enumerate(classes)}
    counts = {c: sum(1 for t in y if t == c) for c in classes}
    wts = [len(y) / (k * max(1, counts[t])) for t in y]
    n = len(X)
    for ep in range(epochs):
        gW = [[0.0] * d for _ in range(k)]
        gb = [0.0] * k
        for x, t, w in zip(X, y, wts):
            p = _softmax([sum(Wc[j] * x[j] for j in range(d)) + bc for Wc, bc in zip(W, b)])
            p[idx[t]] -= 1.0
            for c in range(k):
                if p[c]:
                    g = w * p[c]
                    gb[c] += g
                    row = gW[c]
                    for j in range(d):
                        row[j] += g * x[j]
        step = lr / (1 + ep / 100)
        for c in range(k):
            b[c] -= step * gb[c] / n
            for j in range(d):
                W[c][j] -= step * (gW[c][j] / n + l2 * W[c][j])
    return W, b


class CaseBase:
    def __init__(self, data: dict):
        self.data = data
        self.names = data["feature_names"]
        self.mean, self.std = data["mean"], data["std"]
        self.classes = data["classes"]
        self.cases = data["cases"]
        self.W, self.b = data["model"]["W"], data["model"]["b"]

    # ------------------------------------------------------------------ persistence
    @classmethod
    def load(cls, path: str | Path | None = None) -> "CaseBase | None":
        p = Path(path or DEFAULT_PATH)
        if not p.exists():
            return None
        return cls(json.loads(p.read_text()))

    def save(self, path: str | Path | None = None):
        p = Path(path or DEFAULT_PATH)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.data, separators=(",", ":")))

    # ------------------------------------------------------------------ training
    @classmethod
    def train(cls, rows: list[dict], meta: dict | None = None, max_cases: int = 400, seed: int = 0) -> "CaseBase":
        """rows: [{"cid", "label", "F": features dict (as from features.extract)}]."""
        X = [vector(r["F"]) for r in rows]
        y = [r["label"] for r in rows]
        d = len(X[0])
        mean = [sum(x[j] for x in X) / len(X) for j in range(d)]
        std = [max(1e-6, math.sqrt(sum((x[j] - mean[j]) ** 2 for x in X) / len(X))) for j in range(d)]
        Z = [[(x[j] - mean[j]) / std[j] for j in range(d)] for x in X]
        classes = sorted(set(y))
        W, b = fit_logreg(Z, y, classes, seed=seed)
        # keep a class-balanced subset as the retrievable library
        rng = random.Random(seed)
        by = {}
        for r, z in zip(rows, Z):
            by.setdefault(r["label"], []).append((r, z))
        per = max(1, max_cases // max(1, len(by)))
        lib = []
        for lab, items in sorted(by.items()):
            rng.shuffle(items)
            for r, z in items[:per]:
                lib.append({"cid": r["cid"], "label": lab, "z": [round(v, 4) for v in z],
                            "summary": {k: (r["F"].get(k) or {}).get("value") for k in SUMMARY_KEYS},
                            "response": CONTAIN.get(lab, [])[:2],
                            "meta": {k: v for k, v in (r.get("meta") or {}).items() if k in META_KEYS}})
        return cls({"version": 1, "feature_names": vector_names(), "mean": mean, "std": std, "classes": classes,
                    "model": {"W": W, "b": b}, "cases": lib, "trained_on": meta or {},
                    "n_train": len(rows), "class_counts": {c: y.count(c) for c in classes}})

    # ------------------------------------------------------------------ inference
    def _z(self, F: dict) -> list[float]:
        x = vector(F)
        return [(x[j] - self.mean[j]) / self.std[j] for j in range(len(x))]

    def predict(self, F: dict) -> dict:
        z = self._z(F)
        p = _softmax([sum(w * v for w, v in zip(Wc, z)) + bc for Wc, bc in zip(self.W, self.b)])
        ranked = sorted(zip(self.classes, p), key=lambda t: -t[1])
        return {"primary": ranked[0][0], "p": round(ranked[0][1], 3),
                "probs": {c: round(v, 3) for c, v in ranked}}

    def nearest(self, F: dict, k: int = 5) -> list[dict]:
        z = self._z(F)
        scored = sorted(((math.sqrt(sum((a - b) ** 2 for a, b in zip(z, c["z"]))), c) for c in self.cases),
                        key=lambda t: t[0])
        return [{"cid": c["cid"], "label": c["label"], "distance": round(dist, 2), "summary": c["summary"],
                 "right_response": c["response"]} for dist, c in scored[:k]]

    def explain(self, F: dict, top: int = 5) -> list[dict]:
        """Which features pushed the predicted class up the most (weight x standardised value)."""
        z = self._z(F)
        cls = self.predict(F)["primary"]
        W = self.W[self.classes.index(cls)]
        contrib = sorted(((W[j] * z[j], self.names[j]) for j in range(len(z))), reverse=True)[:top]
        return [{"feature": n, "contribution": round(c, 3)} for c, n in contrib if c > 0]
