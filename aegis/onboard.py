"""Onboarding: draft config/tags.json from the PLC's own tag export (+ what Aegis observed).

A 3-person utility won't hand-write a register map. But every PLC programming
tool can export its tag list (address, name, description, units) to CSV. This
reads that export, works out which tags Aegis cares about from their names and
descriptions, infers scaling from the units and from the values Aegis saw on
the wire in monitor mode (data/discovery.json), and writes a DRAFT with
everything it's unsure about marked for review.

    python -m aegis.onboard --export plc_tags.csv [--discovery data/discovery.json] [--ai]

Addresses: classic Modbus notation (00001 coils, 10001 discrete inputs,
30001 input registers, 40001 holding registers; 5- or 6-digit) or table:offset
(e.g. "HR:3", "IR:0", "CO:1").

--ai: tags the keyword rules couldn't place are sent (descriptions only) to the
LLM, which may suggest a role from the fixed list below. Suggestions are
validated and marked "ai-suggested, review"; nothing is applied automatically.
"""
from __future__ import annotations

import argparse
import csv
import json
import os
import re
from pathlib import Path

from .config import Tags

# role -> (table, unit, keyword patterns (all lowercase), typical engineering range)
ROLES = {
    "ph":                ("input",   "pH",         [r"\bph\b(?!.*raw)(?!.*intake)", r"finished.*\bph\b", r"effluent.*\bph\b"], (6, 9.5)),
    "raw_ph":            ("input",   "pH",         [r"(raw|intake|source).*\bph\b", r"\bph\b.*(raw|intake)"], (6, 9.5)),
    "chlorine_residual": ("input",   "mg/L",       [r"(cl2|chlorine|free cl).*(resid|analy|res\b)", r"resid.*(cl2|chlorine)"], (0, 5)),
    "tank_level":        ("input",   "%",          [r"(clearwell|clear well|tank|reservoir).*(level|lvl)"], (0, 100)),
    "flow_out":          ("input",   "gpm",        [r"(dist|finished|effluent|high.?service).*flow", r"flow.*(dist|town|out)"], (0, 5000)),
    "raw_alkalinity":    ("input",   "mg/L CaCO3", [r"alkalin"], (10, 400)),
    "raw_turbidity":     ("input",   "NTU",        [r"(raw|intake).*turb", r"turb.*(raw|intake)"], (0, 100)),
    "water_temp":        ("input",   "C",          [r"(water|raw).*temp"], (0, 35)),
    "chlorine_dose":     ("holding", "mg/L",       [r"(cl2|chlorine|hypo).*(dose|setpoint|\bsp\b|feed)"], (0, 10)),
    "naoh_dose":         ("holding", "ppm",        [r"(naoh|caustic|lye|sodium hydroxide).*(dose|setpoint|\bsp\b|feed)"], (0, 20000)),
    "distribution_rate": ("holding", "gpm",        [r"(dist|high.?service).*(rate|flow).*(sp|setpoint)", r"(dist|high.?service).*(speed|rate) (sp|setpoint)"], (0, 5000)),
    "intake_pump":       ("coil",    "on/off",     [r"(intake|raw|low.?service|well).*pump.*(run|start|cmd|enable)"], (0, 1)),
    "distribution_pump": ("coil",    "on/off",     [r"(dist|high.?service).*pump.*(run|start|cmd|enable)"], (0, 1)),
}
TABLE_FROM_PREFIX = {"0": "coil", "1": "discrete", "3": "input", "4": "holding"}
SHORT = {"CO": "coil", "DI": "discrete", "IR": "input", "HR": "holding"}


def parse_address(text: str) -> tuple[str, int] | None:
    t = str(text).strip().upper().replace(" ", "")
    m = re.fullmatch(r"(CO|DI|IR|HR)[:\-]?(\d+)", t)
    if m:
        return SHORT[m.group(1)], int(m.group(2))
    if re.fullmatch(r"\d{5,6}", t):
        table = TABLE_FROM_PREFIX.get(t[0])
        if table is None:
            return None
        return table, int(t[1:]) - 1                 # 40001 -> holding register 0
    return None


def scale_from_units(units: str, desc: str) -> float | None:
    s = f"{units} {desc}".lower()
    m = re.search(r"x\s?(10|100|1000)\b|\*\s?(10|100|1000)\b|scale[d]?\s*(?:by|x)?\s*(10|100|1000)", s)
    if m:
        return float(next(g for g in m.groups() if g))
    m = re.search(r"\b0\.(1|01|001)\b", s)
    if m:
        return {"1": 10.0, "01": 100.0, "001": 1000.0}[m.group(1)]
    return None


def scale_from_values(role: str, lo: float, hi: float) -> float | None:
    """Smallest power-of-ten scale that puts every observed raw value inside the role's physical range
    (pH stored as 690..760 can only be x100; a tank level of 420..610 can only be x10)."""
    rlo, rhi = ROLES[role][3]
    for sc in (1.0, 10.0, 100.0, 1000.0):
        if rlo - 1e-9 <= lo / sc and hi / sc <= rhi + 1e-9:
            return sc
    return None


def match_role(name: str, desc: str) -> list[str]:
    text = f"{name} {desc}".lower().replace("_", " ")
    return [r for r, (_, _, pats, _) in ROLES.items() if any(re.search(p, text) for p in pats)]


def disambiguate(roles: list[str], table: str) -> list[str]:
    """Prefer the role whose register table matches (a holding 'flow setpoint' is the rate setpoint,
    not the flow meter), then the more specific role ('raw water pH' is raw_ph, not finished ph)."""
    if len(roles) > 1:
        same = [r for r in roles if ROLES[r][0] == table]
        roles = same or roles
    if len(roles) > 1:
        specific = [r for r in roles if r.startswith("raw_") or r.endswith("_dose") or r.endswith("_rate")]
        roles = specific if len(specific) == 1 else roles
    return roles


def draft(export_rows: list[dict], discovery: dict | None = None) -> dict:
    discovery = discovery or {}
    out = {"coils": {}, "holding": {}, "input": {}}
    review, unmapped, used = [], [], {}
    for row in export_rows:
        addr = parse_address(row.get("address") or row.get("Address") or "")
        name = (row.get("name") or row.get("Name") or row.get("tag") or "").strip()
        desc = (row.get("description") or row.get("Description") or "").strip()
        units = (row.get("units") or row.get("Units") or "").strip()
        if not addr:
            review.append(f"{name}: can't read address '{row.get('address') or row.get('Address')}'")
            continue
        table, a = addr
        roles = match_role(name, desc)
        roles = [r for r in roles if ROLES[r][0] == table or (ROLES[r][0] == "input" and table == "holding")]
        roles = disambiguate(roles, table)
        if len(roles) != 1:
            unmapped.append({"address": f"{table}:{a}", "name": name, "description": desc, "units": units,
                             "candidates": roles})
            continue
        role = roles[0]
        if role in used:
            review.append(f"{role}: matched twice ({used[role]} and {name}); kept the first, check which is right")
            continue
        used[role] = name
        sc = scale_from_units(units, desc)
        how = "from units/description" if sc else None
        seen = discovery.get(f"{table}:{a}")
        if sc is None and seen:
            sc = scale_from_values(role, seen["min"], seen["max"])
            how = f"from observed values {seen['min']}..{seen['max']}" if sc else None
        if sc is None:
            sc = 1.0
            if table != "coil" and ROLES[role][3][1] < 20:
                review.append(f"{role} ({name}): no scale in the export and no observed values; assumed 1, "
                              "check (pH and chlorine are usually stored x100)")
        key = {"coil": "coils"}.get(table, table)
        if table == "holding" and ROLES[role][0] == "input":
            review.append(f"{role} ({name}) is a holding register in this PLC; it will be read as a sensor")
        entry = {"address": a, "unit": ROLES[role][1], "label": name or role}
        if table != "coil":
            entry["scale"] = sc
        if how:
            entry["_scale_source"] = how
        out[key if key in out else "input"][role] = entry
    missing = [r for r in ROLES if r not in used]
    return {"tags": out, "review": review, "unmapped": unmapped, "missing_roles": missing,
            "twin_ready": all(r in used for r in ("ph", "chlorine_residual", "tank_level", "raw_ph",
                                                   "raw_alkalinity", "raw_turbidity"))}


async def ai_suggest(unmapped: list[dict]) -> list[dict]:
    """Ask the LLM to suggest roles for tags the rules couldn't place. Validated; never auto-applied."""
    import httpx
    key = os.getenv("GROQ_API_KEY") or os.getenv("AEGIS_LLM_KEY")
    if not key or not unmapped:
        return []
    from .copilot import API, MODEL
    prompt = ("Map PLC tags of a water treatment plant to these roles, or 'none'. Roles: "
              + ", ".join(f"{r} ({ROLES[r][0]}, {ROLES[r][1]})" for r in ROLES)
              + ". Answer as JSON list of {\"address\":..., \"role\":...}. Tags:\n"
              + json.dumps([{k: u[k] for k in ("address", "name", "description", "units")} for u in unmapped]))
    async with httpx.AsyncClient(timeout=40) as http:
        r = await http.post(API, headers={"Authorization": f"Bearer {key}"},
                            json={"model": MODEL, "messages": [{"role": "user", "content": prompt}], "temperature": 0})
        r.raise_for_status()
        text = r.json()["choices"][0]["message"]["content"]
    m = re.search(r"\[.*\]", text, re.S)
    try:
        items = json.loads(m.group(0)) if m else []
    except json.JSONDecodeError:
        return []
    ok = []
    valid = {u["address"] for u in unmapped}
    for it in items:
        if isinstance(it, dict) and it.get("address") in valid and it.get("role") in ROLES:
            ok.append({"address": it["address"], "role": it["role"], "status": "ai-suggested, review"})
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--export", required=True, help="CSV tag export from the PLC programming software")
    ap.add_argument("--discovery", default="data/discovery.json")
    ap.add_argument("--out", default="config/tags.draft.json")
    ap.add_argument("--ai", action="store_true")
    a = ap.parse_args()
    rows = list(csv.DictReader(open(a.export, newline="", encoding="utf-8-sig")))
    disc = json.loads(Path(a.discovery).read_text()) if Path(a.discovery).exists() else {}
    res = draft(rows, disc)
    Tags({k: {n: {kk: vv for kk, vv in e.items() if not kk.startswith("_")} for n, e in v.items()}
          for k, v in res["tags"].items()})       # validates the draft loads
    if a.ai:
        import asyncio
        res["ai_suggestions"] = asyncio.run(ai_suggest(res["unmapped"]))
    Path(a.out).write_text(json.dumps({"_doc": "DRAFT from aegis.onboard: review every entry, then rename to "
                                       "tags.json", **res["tags"]}, indent=2))
    print(f"draft written to {a.out}")
    print(f"mapped {sum(len(v) for v in res['tags'].values())} tags; twin ready: {res['twin_ready']}")
    for line in res["review"]:
        print("  REVIEW:", line)
    for u in res["unmapped"]:
        print(f"  unmapped: {u['address']} {u['name']} '{u['description']}' candidates={u['candidates']}")
    if res["missing_roles"]:
        print("  not found:", ", ".join(res["missing_roles"]))
    for s in res.get("ai_suggestions", []):
        print(f"  AI suggests: {s['address']} -> {s['role']} ({s['status']})")


if __name__ == "__main__":
    from dotenv import load_dotenv
    load_dotenv()
    main()
