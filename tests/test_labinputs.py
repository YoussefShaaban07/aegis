"""Lab inputs: the twin runs on a once-a-day alkalinity titration instead of an online analyzer."""
import pytest

from aegis.alerts import Alerter
from aegis.guard import Guard
from aegis.labinputs import LabInputs
from aegis.plant import Plant
from aegis.twin import Twin


class Clock:
    t = 1_000_000.0

    def __call__(self):
        return self.t


def test_fresh_lab_value_fills_missing_reading_and_twin_runs(tmp_path):
    clk = Clock()
    lab = LabInputs({"raw_alkalinity": {"max_age_h": 36}}, tmp_path / "lab.json", clock=clk)
    plant = Plant(noise=False)
    st = plant.snapshot()
    st.pop("raw_alkalinity")                                   # this PLC has no alkalinity analyzer
    assert not Twin.available(st)
    lab.enter("raw_alkalinity", 77, by="J. Smith")
    filled = lab.fill(st)
    assert filled["raw_alkalinity"] == 77 and Twin.available(filled)
    g = Guard(None, lambda: filled, twin=Twin())
    d = g.check("naoh_dose", 150, filled, "Operator HMI", "h:1")
    assert d.allowed and d.forecast is not None                 # the twin actually ran
    # survives a restart (the CLI on the Aegis box writes the same file)
    assert LabInputs({"raw_alkalinity": {}}, tmp_path / "lab.json", clock=clk).fill(st)["raw_alkalinity"] == 77


def test_plc_reading_wins_over_lab_value():
    lab = LabInputs({"raw_alkalinity": {}}, clock=Clock())
    lab.enter("raw_alkalinity", 50, by="x")
    assert lab.fill({"raw_alkalinity": 80.0})["raw_alkalinity"] == 80.0


def test_stale_lab_value_pauses_twin_and_alerts_once():
    clk = Clock()
    al = Alerter(None, throttle_s=0, clock=clk)
    lab = LabInputs({"raw_alkalinity": {"max_age_h": 36}}, alerter=al, clock=clk)
    lab.enter("raw_alkalinity", 77, by="x")
    clk.t += 37 * 3600
    st = lab.fill({"ph": 7.3})
    assert "raw_alkalinity" not in st
    lab.fill({"ph": 7.3})
    keys = [a["key"] for a in al.recent]
    assert keys == ["lab_stale:raw_alkalinity"] and "paused" in al.recent[0]["message"]
    plant = Plant(noise=False)
    snap = plant.snapshot(); snap.pop("raw_alkalinity")
    d = Guard(None, lambda: snap, twin=Twin()).check("naoh_dose", 120, snap, "Operator HMI", "h:1")
    assert d.allowed and "unavailable" in d.reason                 # static rules only, said plainly


def test_rejects_unconfigured_and_implausible_entries():
    lab = LabInputs({"raw_alkalinity": {}}, clock=Clock())
    with pytest.raises(ValueError):
        lab.enter("chlorine_dose", 3, by="x")
    with pytest.raises(ValueError):
        lab.enter("raw_alkalinity", 9000, by="x")
