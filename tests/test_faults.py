"""Tests for the fault transforms — each must be deterministic and faithful."""
from nightshift import faults
from nightshift.model import build_delivery

SECRET = "whsec_test"


def _capture(eid="e1", amount=1000):
    return build_delivery(SECRET, event_id=eid, etype="payment.captured", order_id="o1",
                          payment_id="p1", kind="capture", amount=amount)


def test_duplicate_repeats_captures_with_same_event_id():
    out = faults.duplicate([_capture()], times=3)
    assert len(out) == 3
    assert {d.event_id for d in out} == {"e1"}  # same idempotency key


def test_drop_marks_capture_undelivered():
    out = faults.drop([_capture()])
    assert all(not d.delivered for d in out)


def test_reorder_reverses_stream():
    a, b = _capture("e1"), _capture("e2")
    out = faults.reorder([a, b])
    assert [d.event_id for d in out] == ["e2", "e1"]


def test_tamper_amount_changes_amount_and_breaks_signature():
    out = faults.tamper_amount([_capture(amount=200000)], secret=SECRET, to=2000)
    d = out[0]
    assert d.amount == 2000
    assert d.amount_true == 200000
    assert not d.signature_valid(SECRET)  # attacker cannot re-sign


def test_forge_appends_invalid_capture():
    out = faults.forge([], secret=SECRET, order_id="o1", amount=60000)
    assert len(out) == 1
    assert out[0].is_forged and not out[0].signature_valid(SECRET)


def test_valid_delivery_has_valid_signature():
    assert _capture().signature_valid(SECRET)
