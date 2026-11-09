"""Check the new acid feeds (chlorine gas, fluorosilicic acid, sodium fluoride) against PHREEQC (USGS).

    python -m scripts.validate_feeds_phreeqc [out.json]     (needs: pip install phreeqpython)

Fluoride: PHREEQC gets the real chemicals (H2SiF6 or NaF) and does its own hydrolysis and speciation, so this
checks both the stoichiometry Aegis assumes (FSA releases 1 acid equivalent per mol of fluoride, NaF none)
and the carbonate response. Chlorine gas: PHREEQC's standard database has no hypochlorite species, so gas is
given to it as the acid it releases (HCl at Aegis's 1.4 mg/L alkalinity per mg/L Cl2, the textbook design
figure): this checks the carbonate response, not the 1.4 figure itself.
"""
from __future__ import annotations

import itertools
import json
import sys

from aegis.process import (CACO3_EQ_MG, F_MG_PER_MOL, FLUORIDE_CHEMICALS, ct_from_ph_alk, mgl_caco3_to_eq,
                           ph_from_alk, pk_at)

WATERS = [(7.2, 30), (7.5, 77), (7.8, 120), (8.0, 200)]        # finished-water pH, alkalinity mg/L as CaCO3
FLUORIDE = [0.5, 0.7, 1.0, 2.0, 4.0]                           # mg/L F
CHLORINE = [1.0, 2.0, 4.0, 8.0]                                # mg/L Cl2


def aegis_ph(ph0, alk_mgl, acid_eq):
    pk = pk_at(25)
    alk = mgl_caco3_to_eq(alk_mgl)
    ct = ct_from_ph_alk(ph0, alk, *pk)
    return ph_from_alk(alk - acid_eq, ct, *pk)


def main():
    from phreeqpython import PhreeqPython
    pp = PhreeqPython()
    rows = []

    def phreeqc(ph0, alk, formula, mmol):
        s = pp.add_solution({"units": "mg/l", "pH": ph0, "Alkalinity": f"{alk} as CaCO3", "temp": 25,
                             "Na": 5, "Cl": 8})
        s.add(formula, mmol, "mmol")
        ph = s.pH
        s.forget()
        return ph

    for (ph0, alk), f in itertools.product(WATERS, FLUORIDE):
        for chem, formula, per_f in (("fsa", "H2SiF6", 1 / 6), ("naf", "NaF", 1.0)):
            acid = FLUORIDE_CHEMICALS[chem] * f / F_MG_PER_MOL
            rows.append({"feed": chem, "dose": f, "ph0": ph0, "alk": alk, "aegis": aegis_ph(ph0, alk, acid),
                         "phreeqc": phreeqc(ph0, alk, formula, f / 18.998 * per_f)})
    for (ph0, alk), c in itertools.product(WATERS, CHLORINE):
        acid = 1.4 * c / CACO3_EQ_MG
        rows.append({"feed": "chlorine gas", "dose": c, "ph0": ph0, "alk": alk, "aegis": aegis_ph(ph0, alk, acid),
                     "phreeqc": phreeqc(ph0, alk, "HCl", acid * 1000)})
    for r in rows:
        r["diff"] = r["aegis"] - r["phreeqc"]
    by = {}
    for r in rows:
        by.setdefault(r["feed"], []).append(abs(r["diff"]))
    for feed, d in by.items():
        print(f"{feed:13s} {len(d):3d} cases  mean |pH difference| {sum(d) / len(d):.3f}  max {max(d):.3f}")
    worst = max(rows, key=lambda r: abs(r["diff"]))
    print("worst:", {k: round(v, 3) if isinstance(v, float) else v for k, v in worst.items()})
    if len(sys.argv) > 1:
        json.dump(rows, open(sys.argv[1], "w"), indent=1)


if __name__ == "__main__":
    main()
