"""The reliability score: hardened integration aces it, naive fails it."""
from nightshift.score import scorecard


def test_fixed_scores_perfect():
    sc = scorecard("fixed")
    assert sc.score == 100.0 and sc.grade == "A+"
    assert sc.scenarios_clean == sc.scenarios_total
    assert sc.exposure_paise == 0


def test_naive_fails():
    sc = scorecard("naive")
    assert sc.grade == "F"
    assert sc.scenarios_clean < sc.scenarios_total
    assert sc.exposure_paise > 0


def test_per_oracle_rates_present_for_every_invariant():
    from nightshift.oracles import ORACLE_NAMES
    sc = scorecard("naive")
    assert set(sc.per_oracle_pass_rate) == set(ORACLE_NAMES)
