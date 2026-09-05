"""The measured numbers are themselves under test — so a regression fails CI.

If someone weakens an oracle (introducing false positives) or removes a defense
without a guarding oracle, these assertions break the build.
"""
from nightshift import bench


def test_detection_is_perfect_with_zero_false_positives():
    c = bench.detection()
    assert c.fp == 0, f"false positives crept in: {c}"
    assert c.fn == 0, f"a known bug slipped through: {c}"
    assert c.precision == 1.0 and c.recall == 1.0


def test_every_defense_is_load_bearing():
    killed = bench.mutation()
    assert all(killed.values()), f"a defense had no guarding oracle: {killed}"
    assert sum(killed.values()) == len(bench.MUTANTS)
