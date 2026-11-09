"""More chemical feeds: chlorine gas and fluoride (fluorosilicic acid, sodium fluorosilicate, sodium fluoride).

The default plant (bleach, no fluoride) must behave exactly as before; the example plant in
config/examples/gas-fluoride turns both on."""
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from aegis.process import CACO3_EQ_MG, F_MG_PER_MOL, ProcessModel, Raw

ROOT = Path(__file__).resolve().parents[1]
EX = ROOT / "config" / "examples" / "gas-fluoride"
SP = {"intake_pump": 1, "distribution_pump": 1, "chlorine_dose": 1.5, "naoh_dose": 100, "distribution_rate": 500}


def test_default_plant_chemistry_is_unchanged():
    m = ProcessModel()
    assert m.acid_added(SP) == 0.0
    a, c, cl = m.inlet(Raw(), SP)
    assert m.acid_added({**SP, "fluoride_dose": None}) == 0.0
    assert m.steady(Raw(), SP).fluoride == pytest.approx(0.2)      # natural fluoride only, nothing added


def test_chlorine_gas_and_fluorosilicic_acid_use_up_alkalinity_and_lower_ph():
    bleach = ProcessModel()
    gas = ProcessModel({"chlorine_source": "gas"})
    assert gas.acid_added(SP) == pytest.approx(1.4 * 1.5 / CACO3_EQ_MG)
    assert gas.ph(gas.steady(Raw(), SP)) < bleach.ph(bleach.steady(Raw(), SP)) - 0.05
    fsa = ProcessModel({"fluoride_chemical": "fsa"})
    naf = ProcessModel({"fluoride_chemical": "naf"})
    na2sif6 = ProcessModel({"fluoride_chemical": "na2sif6"})
    sp = {**SP, "fluoride_dose": 1.0}
    assert fsa.acid_added(sp) == pytest.approx(1.0 / F_MG_PER_MOL)
    assert fsa.acid_added(sp) * CACO3_EQ_MG == pytest.approx(2.63, abs=0.01)   # mg/L alkalinity per mg/L F
    assert na2sif6.acid_added(sp) == pytest.approx(fsa.acid_added(sp) * 2 / 3)
    assert naf.acid_added(sp) == 0.0


def test_fluoride_mixes_through_the_clearwell():
    m = ProcessModel({"baffling_cells": 3})
    s = m.steady(Raw(), {**SP, "fluoride_dose": 0.5})
    assert s.fluoride == pytest.approx(0.7)
    for _ in range(30):                                   # one hour after an overfeed to 5 mg/L
        m.step(s, Raw(), {**SP, "fluoride_dose": 5.0}, 120)
    assert 0.7 < s.fluoride < 5.2


def test_bad_chemical_names_are_refused(tmp_path):
    from aegis.config import load_process
    p = tmp_path / "process.json"
    p.write_text(json.dumps({"chlorine_source": "chlorine dioxide"}))
    with pytest.raises(ValueError, match="chlorine_source"):
        load_process(p)


EXAMPLE_PLANT = r'''
import json
from aegis.alerts import Alerter
from aegis.config import Tags, load_policy
from aegis.guard import Guard
from aegis.plant import Plant
from aegis.twin import Twin
plant = Plant(noise=False)
st = plant.snapshot()
pol = load_policy(Tags.load())
pol["limits"]["fluoride_dose"]["max"] = 5.0        # a badly set range: the twin still has to catch it
pol["limits"]["fluoride_dose"]["max_step"] = None
pol["limits"]["fluoride_dose"]["max_change_per_min"] = None
g = Guard(None, plant.snapshot, policy=pol, twin=Twin(), alerter=Alerter(None, throttle_s=0))
g.last_state = st
out = {"state": {k: st[k] for k in ("ph", "fluoride", "fluoride_dose")}}
for v in (40.0, 2.5, 0.6):
    d = g.check("fluoride_dose", v, st, "Operator HMI", "10.0.0.5:1")
    out[str(v)] = [d.allowed, d.check, d.reason[:160]]
plant.set("fluoride_dose", 3.0)
for _ in range(600):
    plant.step(1.0)
out["alarms"] = plant.alarms()
print(json.dumps(out))
'''


def test_example_plant_blocks_fluoride_overfeeds():
    env = {**os.environ, "AEGIS_TAGS": str(EX / "tags.json"), "AEGIS_POLICY": str(EX / "policy.json"),
           "AEGIS_PROCESS": str(EX / "process.json")}
    r = subprocess.run([sys.executable, "-c", EXAMPLE_PLANT], cwd=ROOT, env=env, capture_output=True, text=True,
                       timeout=120)
    assert r.returncode == 0, r.stderr
    out = json.loads(r.stdout.strip().splitlines()[-1])
    assert 0.6 < out["state"]["fluoride"] < 0.9 and out["state"]["ph"] < 7.4      # gas + FSA: lower pH
    assert out["40.0"][:2] == [False, "range"]                                     # blatant: range limit
    assert out["2.5"][:2] == [False, "predict"] and "fluoride" in out["2.5"][2]    # inside a bad range: the twin
    assert out["0.6"][0] is True                                                   # normal trim: allowed
    assert "FLUORIDE HIGH" in out["alarms"]
