"""pass_writes: HMI housekeeping addresses forwarded without judging (Modbus side; CIP in test_cip)."""
import pytest

from aegis.config import PolicyError, Tags, load_policy, validate_policy
from aegis.guard import Guard
from aegis.plant import Plant


def test_modbus_housekeeping_register_passes_guarded_ones_still_judged():
    plant = Plant(noise=False)
    pol = load_policy(Tags.load())
    pol["pass_writes"] = ["holding 40-49"]
    g = Guard(None, plant.snapshot, policy=pol)
    assert g.check("holding 45", 1, plant.snapshot(), "Operator HMI", "h:1").check == "pass"
    assert g.check("holding 50", 1, plant.snapshot(), "Operator HMI", "h:1").check == "allowlist"
    assert g.check("naoh_dose", 11100, plant.snapshot(), "Operator HMI", "h:1").check == "range"


def test_guarded_tag_cannot_be_put_on_the_pass_list():
    pol = load_policy(Tags.load())
    pol["pass_writes"] = ["naoh_dose"]
    with pytest.raises(PolicyError):
        validate_policy(pol, Tags.load())
