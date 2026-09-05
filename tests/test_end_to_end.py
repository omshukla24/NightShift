"""End-to-end contract:

  * the naive handler breaks exactly the invariants each scenario is labelled with
  * the hardened handler passes every invariant on every scenario

These labels are also the ground truth the precision/recall bench uses, so this
file is doing double duty: correctness suite AND the measured-accuracy dataset.
"""
import pytest

from nightshift.runner import run_scenario
from nightshift.scenarios import SCENARIOS


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.key)
def test_naive_breaks_exactly_the_expected_invariants(scenario):
    result = run_scenario(scenario, "naive")
    failed = {r.name for r in result.failures}
    assert failed == set(scenario.expected_naive), (
        f"{scenario.key}: expected {set(scenario.expected_naive)}, got {failed}"
    )


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.key)
def test_fixed_handler_passes_everything(scenario):
    result = run_scenario(scenario, "fixed")
    failed = {r.name for r in result.failures}
    assert not failed, f"{scenario.key}: fixed handler unexpectedly failed {failed}"


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.key)
def test_naive_money_at_risk_matches_control_flag(scenario):
    result = run_scenario(scenario, "naive")
    if scenario.control:
        assert result.money_at_risk == 0, "a legitimate control flow must risk nothing"
    else:
        assert result.money_at_risk > 0


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.key)
def test_no_handler_crashes(scenario):
    for target in ("naive", "fixed"):
        assert not run_scenario(scenario, target).errors


@pytest.mark.parametrize("scenario", SCENARIOS, ids=lambda s: s.key)
def test_fixed_handler_risks_nothing(scenario):
    result = run_scenario(scenario, "fixed")
    assert result.money_at_risk == 0
