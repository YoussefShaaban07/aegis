"""Aegis's carbonate chemistry vs PHREEQC (USGS): an independent reference, not our own simulator."""
import pytest

pytest.importorskip("phreeqpython")


def test_twin_chemistry_agrees_with_phreeqc():
    import sys
    sys.path.insert(0, ".")
    from scripts.validate_phreeqc import main
    s = main([])
    assert s["cases"] == 100
    assert s["mean_abs_diff"] < 0.08                 # measured 0.053 pH
    assert s["mean_abs_diff_pH_7_to_9.5"] < 0.08
    assert s["safe_unsafe_disagreements"] <= 2       # both: soda ash in low-alkalinity water, see JUDGE_ROUNDS
