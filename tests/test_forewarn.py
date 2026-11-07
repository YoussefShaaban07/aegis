"""Early warnings from the twin's forecast."""
from aegis.audit import AuditLog
from aegis.alerts import Alerter
from aegis.forewarn import ForecastWatch, first_crossings
from aegis.plant import Plant
from aegis.twin import Twin


def test_drain_warned_hours_before_low_level_alarm():
    plant = Plant(noise=False)
    plant.set("distribution_rate", 700)              # slow drain: 180 gpm net out
    al = Alerter(AuditLog(":memory:"))
    watch = ForecastWatch(al)
    tw = Twin()
    warned_at = alarm_at = None
    for minute in range(400):
        plant.step(1.0)
        if minute % 5 == 0:
            watch.update(tw.forecast(plant.snapshot(), None, 180, every_min=5), plant.snapshot())
            if watch.active and warned_at is None:
                warned_at = minute
        if "TANK LOW" in plant.alarms() and alarm_at is None:
            alarm_at = minute
    assert warned_at is not None and alarm_at is not None
    assert alarm_at - warned_at >= 150                # hours of notice instead of minutes
    assert al.recent[0]["key"] == "forecast:tank_level:below" and "about" in al.recent[0]["message"]


def test_one_alert_per_crossing_and_rearm():
    al = Alerter(None, throttle_s=0)
    w = ForecastWatch(al)
    bad = [{"min": 0, "ph": 7.4}, {"min": 30, "ph": 8.7}]
    good = [{"min": 0, "ph": 7.4}, {"min": 30, "ph": 7.5}]
    w.update(bad, {"ph": 7.4}); w.update(bad, {"ph": 7.4})
    assert len(al.recent) == 1
    w.update(good, {"ph": 7.4}); w.update(bad, {"ph": 7.4})
    assert len(al.recent) == 2


def test_no_warning_when_already_in_alarm_or_safe():
    assert first_crossings([{"min": 0, "ph": 9.0}])["ph"][0] == 0
    al = Alerter(None, throttle_s=0)
    ForecastWatch(al).update([{"min": 0, "ph": 9.0}, {"min": 10, "ph": 9.1}], {"ph": 9.0})
    assert not al.recent
