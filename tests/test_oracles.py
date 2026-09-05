"""Unit tests for each oracle on hand-built traces — clean passes, dirty fails."""
from nightshift.model import GroundTruth, LedgerEntry, MerchantState, Order, TrueMovement, build_delivery
from nightshift import oracles
from nightshift.oracles import Trace

SECRET = "whsec_test"


def _trace(state, gt, deliveries=None):
    return Trace(SECRET, gt, deliveries or [], state)


def _gt(order_id, amount, movements=()):
    g = GroundTruth(order_amounts={order_id: amount})
    g.movements = list(movements)
    return g


def test_idempotency_flags_double_fulfilment():
    st = MerchantState(fulfillments=["o1", "o1"])
    st.ledger = [LedgerEntry("e1", "o1", "capture", 100), LedgerEntry("e1", "o1", "capture", 100)]
    r = oracles.idempotency(_trace(st, _gt("o1", 100)))
    assert not r.passed and r.money_at_risk == 100


def test_idempotency_passes_single():
    st = MerchantState(fulfillments=["o1"], ledger=[LedgerEntry("e1", "o1", "capture", 100)])
    assert oracles.idempotency(_trace(st, _gt("o1", 100))).passed


def test_conservation_flags_invented_money():
    st = MerchantState(ledger=[LedgerEntry("e1", "o1", "capture", 999)])
    gt = _gt("o1", 999)  # no true movement at all
    assert not oracles.conservation(_trace(st, gt)).passed


def test_conservation_passes_when_matched():
    st = MerchantState(ledger=[LedgerEntry("e1", "o1", "capture", 500)])
    gt = _gt("o1", 500, [TrueMovement("o1", "p1", "capture", 500)])
    assert oracles.conservation(_trace(st, gt)).passed


def test_no_unpaid_fulfilment_flags_short_payment():
    st = MerchantState(fulfillments=["o1"])
    gt = _gt("o1", 100000, [TrueMovement("o1", "p1", "capture", 100)])  # paid Rs1 for Rs1000
    assert not oracles.no_unpaid_fulfillment(_trace(st, gt)).passed


def test_reconciliation_flags_missing_payment():
    st = MerchantState()  # nothing recorded
    gt = _gt("o1", 100, [TrueMovement("o1", "p1", "capture", 100)])
    assert not oracles.reconciliation_completeness(_trace(st, gt)).passed


def test_signature_integrity_flags_bad_sig_that_changed_state():
    good = build_delivery(SECRET, event_id="e1", etype="payment.captured", order_id="o1",
                          payment_id="p1", kind="capture", amount=100)
    good.signature = "0" * 64  # now invalid
    st = MerchantState(ledger=[LedgerEntry("e1", "o1", "capture", 100)], fulfillments=["o1"])
    r = oracles.signature_integrity(_trace(st, _gt("o1", 100), [good]))
    assert not r.passed and "e1" in r.offending_events


def test_terminal_state_monotonicity_flags_refund_before_paid():
    st = MerchantState(status_history={"o1": ["refunded", "paid"]})
    assert not oracles.terminal_state_monotonicity(_trace(st, _gt("o1", 100))).passed


def test_terminal_state_monotonicity_passes_legal_lifecycle():
    st = MerchantState(status_history={"o1": ["paid", "refunded"]})
    assert oracles.terminal_state_monotonicity(_trace(st, _gt("o1", 100))).passed
