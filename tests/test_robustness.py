"""Robustness & safety properties: no crashes, idempotent recovery, no leaks,
exact money math, and input validation."""
import pytest

from nightshift import constants as C
from nightshift.handlers import FixedHandler, NaiveHandler
from nightshift.model import Delivery, GroundTruth, build_delivery, validate_amount
from nightshift.runner import DEFAULT_SECRET, run_scenario
from nightshift.scenarios import by_key

EXACT_RISK_PAISE = {
    "replay": 50000, "dropped": 120000, "reorder": 80000, "underpaid": 100000,
    "tampered": 200000, "forged": 60000, "double_refund": 90000,
    "currency_swap": 60000, "over_refund": 50000, "partial_refund": 0,
}


@pytest.mark.parametrize("key,paise", EXACT_RISK_PAISE.items())
def test_money_at_risk_is_exact(key, paise):
    assert run_scenario(by_key(key), "naive").money_at_risk == paise


def test_handlers_never_crash_on_garbage_body():
    junk = Delivery(event_id="e", etype="payment.captured", order_id="o", payment_id="p",
                    kind=C.CAPTURE, amount=100, currency=C.INR, body=b"not json{", signature="x")
    for h in (NaiveHandler(DEFAULT_SECRET), FixedHandler(DEFAULT_SECRET)):
        h.register_order("o", 100)
        h.handle(junk)  # must not raise


def test_reconcile_is_idempotent():
    s = by_key("dropped")
    gt = s.ground_truth()
    h = FixedHandler(DEFAULT_SECRET, verifier=gt.is_true_capture)
    for oid, amt in s.orders:
        h.register_order(oid, amt)
    for d in s.actual_deliveries(DEFAULT_SECRET):
        h.handle(d)
    h.reconcile(gt.movements)
    h.reconcile(gt.movements)  # twice
    h.reconcile(gt.movements)  # thrice
    assert h.state.fulfillments.count("ord_drop") == 1
    assert len([e for e in h.state.ledger if e.order_id == "ord_drop"]) == 1


def test_report_never_leaks_the_secret():
    from nightshift.report import render
    for target in ("naive", "fixed"):
        assert DEFAULT_SECRET not in render(target)


def test_amount_validation_rejects_bad_values():
    for bad in (0, -1, 1.5, True, "100"):
        with pytest.raises((ValueError, TypeError)):
            validate_amount(bad)  # type: ignore[arg-type]


def test_empty_signature_is_never_valid():
    d = build_delivery(DEFAULT_SECRET, event_id="e", etype="payment.captured", order_id="o",
                       payment_id="p", kind=C.CAPTURE, amount=100)
    d.signature = ""
    d._sig_ok = None
    assert not d.signature_valid(DEFAULT_SECRET)


def test_signature_validity_is_cached_once():
    d = build_delivery(DEFAULT_SECRET, event_id="e", etype="payment.captured", order_id="o",
                       payment_id="p", kind=C.CAPTURE, amount=100)
    assert d.signature_valid(DEFAULT_SECRET) is True
    assert d._sig_ok is True  # cached
