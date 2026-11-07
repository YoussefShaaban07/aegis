"""Twin calibration from operating history (the simulator's true parameters are hidden from the fit)."""
import pytest

from aegis.calibrate import fit, read_history_csv
from aegis.config import load_process
from aegis.plant import Plant


def history(hours=14, seed=4):
    p = Plant(noise=True, seed=seed)
    events = {60: ("naoh_dose", 140), 200: ("chlorine_dose", 2.0), 330: ("naoh_dose", 90),
              520: ("chlorine_dose", 2.8), 640: ("naoh_dose", 120)}
    for m in range(hours * 60):
        if m in events:
            p.set(*events[m])
        if m == 400:
            p.set_scenario("storm")
        p.step(1.0)
    return p, list(p.history)


def test_calibration_recovers_feed_strength_and_cuts_error():
    plant, hist = history()
    wrong = load_process()
    wrong.update(naoh_feed_strength=0.13, chlorine_decay_per_hr=0.06, chlorine_demand_base=0.35)
    r = fit(hist, wrong)
    true_feed = plant.model.params["naoh_feed_strength"]
    assert abs(r["params"]["naoh_feed_strength"] - true_feed) / true_feed < 0.03
    assert r["after"]["ph_mae"] < r["before"]["ph_mae"] / 5
    assert r["after"]["cl_mae"] < r["before"]["cl_mae"]


def test_needs_enough_history():
    with pytest.raises(ValueError):
        fit([{"sim_t": 0}] * 5)


def test_history_csv_roundtrip(tmp_path):
    _, hist = history(hours=3)
    import csv
    keys = list(hist[0].keys())
    f = tmp_path / "h.csv"
    with open(f, "w", newline="") as fh:
        w = csv.DictWriter(fh, keys); w.writeheader(); w.writerows(hist)
    rows = read_history_csv(f)
    assert len(rows) == len(hist) and rows[5]["ph"] == pytest.approx(hist[5]["ph"])


def test_refuses_to_fit_a_single_window():
    _, hist = history(hours=1)
    with pytest.raises(ValueError, match="overfitting"):
        fit(hist)
