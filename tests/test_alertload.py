"""Alert load: a calm stretch with a sensible operator should produce almost no texts."""
from aegis.alertload import summarize, week


def test_two_days_alert_load_runs_and_counts():
    w = week(seed=7, days=2)
    s = summarize([w])
    assert s["days"] == 2 and s["texts_total"] == len(w["texts"])
    assert s["texts_per_calm_day"] <= 2          # a nuisance rate above this would make operators ignore Aegis
    assert all(set(t) >= {"day", "day_kind", "severity", "cause"} for t in w["texts"])
