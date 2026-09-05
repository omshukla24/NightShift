"""The fuzz campaign: coverage, reproducibility, shrinking, and the survival property."""
from nightshift.campaign import fuzz


def test_hardened_handler_survives_the_whole_campaign():
    for seed in (1, 2, 3):
        rep = fuzz("fixed", trials=300, seed=seed)
        assert rep.failing_trials == 0, f"seed {seed}: {rep.failing_trials} failures"
        assert rep.crashes == 0


def test_campaign_covers_every_invariant_on_the_naive_handler():
    rep = fuzz("naive", trials=300, seed=1)
    assert rep.coverage == 1.0            # trips all 8 invariants
    assert rep.failing_trials > 0


def test_campaign_is_reproducible():
    a = fuzz("naive", trials=120, seed=42)
    b = fuzz("naive", trials=120, seed=42)
    assert a.oracle_hits == b.oracle_hits
    assert a.minimal_cases == b.minimal_cases


def test_shrinking_produces_small_minimal_cases():
    rep = fuzz("naive", trials=300, seed=1)
    for oracle, seq in rep.minimal_cases.items():
        assert 1 <= len(seq) <= 4, f"{oracle} minimal case not minimal: {seq}"
