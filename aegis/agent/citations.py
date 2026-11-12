"""Citation validator (spec section 9.2). Deterministic; no model involved.

For every claim {"text", "cite": [ids]}:
  1. each cited id exists, is inside the incident window, and its row still verifies: own hash, link to the
     previous row, and unchanged since the evidence was frozen;
  2. every number in the sentence appears in, or is computable from, the cited entries (values, counts,
     minutes from the incident start, hour of day), within tolerance;
  3. every IP and every known source name in the sentence appears in a cited entry;
  4. technique ids are carried by a cited decision, or justified by a cited feature;
  5. claims with no citation fail (uncited text is only allowed in open_questions, phrased as questions).
"""
from __future__ import annotations

import re

from .schema import Verdict, claims
from .tools import Evidence, ip_of

IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
TECH = re.compile(r"\b(T0\d{3}|LLM\d{2})\b")
REF = re.compile(r"#\d+|\bentry\s+\d+|\bids?\s+\d+(?:\s*(?:,|and)\s*\d+)*", re.I)
NUM = re.compile(r"(?<![\w.])-?\d+(?:\.\d+)?(?![\w.]*\d)")
WORDNUM = {"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6, "seven": 7, "eight": 8, "nine": 9,
           "ten": 10, "once": 1, "twice": 2}
# features that justify a technique even when no cited decision carries it
FEATURE_TECH = {"T0888": ("recon_fc",), "T0806": ("flood_rate",), "T0814": ("recon_fc",),
                "T0836": ("monotone_push", "probing", "regular_interval"), "T0855": ("source_known", "ip_matches_label"),
                "LLM01": ("ai_origin", "untrusted_instructions", "ai_reply_flagged", "ai_proposal_blocked")}


def _nums_in(o, out: set):
    if isinstance(o, bool):
        return
    if isinstance(o, (int, float)):
        out.add(float(o))
    elif isinstance(o, str):
        s = IP.sub(" ", o)
        out.update(float(x) for x in re.findall(r"-?\d+(?:\.\d+)?", s))
    elif isinstance(o, dict):
        for v in o.values():
            _nums_in(v, out)
    elif isinstance(o, (list, tuple)):
        for v in o:
            _nums_in(v, out)


def _strings(o, out: list):
    if isinstance(o, str):
        out.append(o)
    elif isinstance(o, dict):
        for v in o.values():
            _strings(v, out)
    elif isinstance(o, (list, tuple)):
        for v in o:
            _strings(v, out)


def allowed_numbers(ev: Evidence, entries: list[dict]) -> set:
    s: set = set()
    for e in entries:
        _nums_in(e["data"], s)
        rel = (e["t"] - ev.incident.opened_t) / 60
        s.update({round(rel, 1), round(rel), round(rel / 60, 1), round(rel / 60), float(int(e["t"] // 3600 % 24)),
                  float(int(e["t"] // 60 % 60)), e["id"]})
        d = e["data"]
        if isinstance(d.get("new"), (int, float)) and isinstance(d.get("old"), (int, float)):
            s.update({round(abs(d["new"] - d["old"]), 4), round(d["new"] - d["old"], 4)})
    n = len(entries)
    s.update(float(k) for k in range(0, n + 1))           # counts of cited entries ("3 of these", "all 6")
    ts = sorted(e["t"] for e in entries)
    if len(ts) >= 2:
        span = (ts[-1] - ts[0]) / 60
        s.update({round(span), round(span, 1), round(span / 60, 1), round(span / 60)})
        gaps = [b - a for a, b in zip(ts, ts[1:])]
        s.update(round(g) for g in gaps)
        s.update(round(g / 60, 1) for g in gaps)
    return s


def _close(x: float, pool: set) -> bool:
    return any(abs(x - y) <= max(0.051, 0.02 * abs(y)) for y in pool)


def check_claim(ev: Evidence, text: str, cite: list[int], rows: dict, features: dict | None = None,
                known_sources: set | None = None) -> list[str]:
    errs: list[str] = []
    if not cite:
        return ["no citation"]
    entries = []
    for i in cite:
        snap = ev.by_id.get(i)
        r = rows.get(i)
        if snap is None:
            errs.append(f"#{i} does not exist in this incident's evidence" if not (r and r["exists"])
                        else f"#{i} is outside the incident window")
            continue
        if not (r and r["exists"] and r["hash_ok"] and r["link_ok"] and r.get("hash") == snap["hash"]):
            errs.append(f"#{i} fails chain verification (altered or removed since the evidence was frozen)")
            continue
        entries.append(snap)
    if not entries:
        return errs or ["no valid citation"]
    blob_parts: list[str] = []
    for e in entries:
        _strings(e["data"], blob_parts)
    blob = " ".join(blob_parts)
    ips_cited = {ip_of(e["data"].get("peer")) for e in entries} | set(IP.findall(blob))
    t = REF.sub(" ", text)
    for ip in IP.findall(t):
        if ip not in ips_cited:
            errs.append(f"IP {ip} is not in the cited entries")
    t = IP.sub(" ", t)
    for src in sorted(known_sources or (), key=len, reverse=True):
        if src and src.lower() in t.lower():
            if src not in blob:
                errs.append(f"source '{src}' is not in the cited entries")
            t = re.sub(re.escape(src), " ", t, flags=re.I)
    techs = set()
    for e in entries:
        for tq in e["data"].get("techniques") or []:
            techs.add(tq[0] if isinstance(tq, (list, tuple)) else tq)
    cited = set(cite)
    for tid in TECH.findall(t):
        ok = tid in techs or any(set((features or {}).get(f, {}).get("ids") or []) & cited
                                 and (features or {}).get(f, {}).get("value") for f in FEATURE_TECH.get(tid, ()))
        if not ok:
            errs.append(f"technique {tid} is not carried by a cited decision or justified by a cited feature")
    t = TECH.sub(" ", t)
    t = re.sub(r"\b[a-z]+_[a-z_]+\b", " ", t)            # register names like naoh_dose (no digits) are fine
    pool = allowed_numbers(ev, entries)
    for m in NUM.finditer(t):
        x = float(m.group(0))
        if not _close(x, pool):
            errs.append(f"number {m.group(0)} is not in or computable from the cited entries")
    for w, n in WORDNUM.items():
        if re.search(rf"\b{w}\b", t, re.I) and not _close(float(n), pool):
            errs.append(f"'{w}' ({n}) is not supported by the cited entries")
    return errs


def validate(ev: Evidence, v: Verdict, features: dict | None = None) -> dict:
    """Check every claim. Returns per-claim results and the validity rate; never raises."""
    items = claims(v)
    for i, tq in enumerate(v.attack_techniques):
        items.append((f"attack_techniques[{i}]", type("C", (), {"text": f"{tq.id}", "cite": tq.cite})()))
    for i, st in enumerate(v.recovery):
        items.append((f"recovery[{i}]", type("C", (), {"text": st.why, "cite": st.cite})()))
    ids = sorted({i for _, c in items for i in c.cite})
    rows = ev.audit.check_rows(ids) if ids else {}
    known = {e["data"].get("source") for e in ev.of("decision")} | {e["data"].get("source") for e in ev.of("lockdown")}
    known.discard(None)
    out = []
    for path, c in items:
        if path.startswith("recovery") and not c.cite:
            errs = []                                       # recovery steps are re-tested in the twin anyway
        else:
            errs = check_claim(ev, c.text, list(c.cite), rows, features, known)
        out.append({"path": path, "text": c.text, "cite": list(c.cite), "ok": not errs, "errors": errs})
    bad_q = [q for q in v.open_questions if not q.strip().endswith("?")]
    for q in bad_q:
        out.append({"path": "open_questions", "text": q, "cite": [], "ok": False,
                    "errors": ["uncited text outside open_questions, or not phrased as a question"]})
    n_ok = sum(x["ok"] for x in out)
    return {"claims": out, "checked": len(out), "passed": n_ok, "failed": len(out) - n_ok,
            "validity": round(n_ok / len(out), 4) if out else 1.0, "chain_ok_at_freeze": bool(ev.verify.get("ok"))}


def strip_failed(v: Verdict, result: dict) -> tuple[Verdict, list[dict]]:
    """Remove failed claims (after the one repair attempt). Returns the cleaned verdict and what was removed."""
    bad = {x["path"] for x in result["claims"] if not x["ok"]}
    removed = [x for x in result["claims"] if not x["ok"]]
    d = v.model_dump(by_alias=True)

    def keep(lst, prefix):
        return [c for i, c in enumerate(lst) if f"{prefix}[{i}]" not in bad]
    d["classification"]["rationale"] = keep(d["classification"]["rationale"], "classification.rationale")
    for i, h in enumerate(d["hypotheses"]):
        h["for"] = keep(h["for"], f"hypotheses[{i}].for")
        h["against"] = keep(h["against"], f"hypotheses[{i}].against")
    d["scope"]["writes_allowed_from_source"] = keep(d["scope"]["writes_allowed_from_source"],
                                                    "scope.writes_allowed_from_source")
    d["attack_techniques"] = keep(d["attack_techniques"], "attack_techniques")
    d["recovery"] = keep(d["recovery"], "recovery")
    d["open_questions"] = [q for q in d["open_questions"] if q.strip().endswith("?")]
    if not d["classification"]["rationale"] and d["classification"]["confidence"] == "high":
        d["classification"]["confidence"] = "medium"      # high confidence needs cited evidence
    return Verdict.model_validate(d), removed
