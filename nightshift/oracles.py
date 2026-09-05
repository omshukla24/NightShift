"""Oracles — deterministic invariants over a run.

This is the part that is NOT AI. Every oracle is a pure function over the event
trace and the handler's recorded state. It returns a verdict and, when it fails,
the exact offending events and the rupees at risk. The AI copilot is only ever
handed a verdict an oracle has already proven — it never decides one.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import constants as C
from .model import Delivery, GroundTruth, MerchantState


@dataclass
class Trace:
    secret: str
    ground_truth: GroundTruth
    deliveries: list[Delivery]
    state: MerchantState
    _legit: Optional[set] = field(default=None, compare=False, repr=False)
    _badsig: Optional[set] = field(default=None, compare=False, repr=False)

    def order_amount(self, order_id: str) -> int:
        if order_id in self.ground_truth.order_amounts:
            return self.ground_truth.order_amounts[order_id]
        o = self.state.orders.get(order_id)
        return o.amount if o else 0

    def order_currency(self, order_id: str) -> str:
        return self.ground_truth.order_currency(order_id)

    def legit_paid_orders(self) -> set[str]:
        """Orders with a true capture for the full order amount AND currency."""
        if self._legit is None:
            self._legit = {
                m.order_id for m in self.ground_truth.movements
                if m.kind == C.CAPTURE
                and m.amount == self.ground_truth.order_amounts.get(m.order_id)
                and m.currency == self.order_currency(m.order_id)
            }
        return self._legit

    def bad_signature_events(self) -> set[str]:
        if self._badsig is None:
            self._badsig = {d.event_id for d in self.deliveries
                            if d.delivered and not d.signature_valid(self.secret)}
        return self._badsig


@dataclass
class OracleResult:
    name: str
    passed: bool
    detail: str = ""
    money_at_risk: int = 0
    offending_orders: set[str] = field(default_factory=set)
    offending_events: list[str] = field(default_factory=list)


def idempotency(t: Trace) -> OracleResult:
    """A duplicated webhook must cause exactly one effect."""
    offenders: set[str] = set()
    money = 0
    for order_id, c in Counter(t.state.fulfillments).items():
        if c > 1:
            offenders.add(order_id)
            money += (c - 1) * t.order_amount(order_id)
    dup_events = [e for e, c in Counter(e.event_id for e in t.state.ledger).items() if c > 1]
    passed = not offenders and not dup_events
    detail = ("every event applied at most once" if passed
              else f"orders fulfilled more than once: {sorted(offenders)}; duplicate ledger events: {dup_events}")
    return OracleResult("idempotency", passed, detail, money, offenders, dup_events)


def conservation(t: Trace) -> OracleResult:
    """Every rupee the handler books must correspond to a real movement."""
    true = Counter((m.order_id, m.kind, m.amount) for m in t.ground_truth.movements)
    seen: Counter = Counter()
    offenders: set[str] = set()
    events: list[str] = []
    money = 0
    for e in t.state.ledger:
        key = (e.order_id, e.kind, e.amount)
        seen[key] += 1
        if seen[key] > true.get(key, 0):
            if e.order_id not in offenders:
                money += t.order_amount(e.order_id)
            offenders.add(e.order_id)
            events.append(e.event_id)
    passed = not offenders
    detail = ("recorded money matches money that truly moved" if passed
              else f"booked money with no matching payment on orders {sorted(offenders)}")
    return OracleResult("conservation", passed, detail, money, offenders, events)


def no_unpaid_fulfillment(t: Trace) -> OracleResult:
    """Nothing ships unless a full, real payment exists for it."""
    legit = t.legit_paid_orders()
    offenders = {o for o in set(t.state.fulfillments) if o not in legit}
    money = sum(t.order_amount(o) for o in offenders)
    passed = not offenders
    detail = ("every fulfilled order is backed by a full real payment" if passed
              else f"fulfilled without a full real payment: {sorted(offenders)}")
    return OracleResult("no_unpaid_fulfillment", passed, detail, money, offenders)


def reconciliation_completeness(t: Trace) -> OracleResult:
    """Every real payment must end up recorded — even if its webhook vanished."""
    fulfilled = set(t.state.fulfillments)
    offenders = {o for o in t.legit_paid_orders() if o not in fulfilled}
    money = sum(t.order_amount(o) for o in offenders)
    passed = not offenders
    detail = ("every real payment is accounted for" if passed
              else f"real payments never recorded (money received, order lost): {sorted(offenders)}")
    return OracleResult("reconciliation_completeness", passed, detail, money, offenders)


def signature_integrity(t: Trace) -> OracleResult:
    """No state change may be *caused by* an unsigned event.

    An event id that also arrived with a valid signature is attributable to that
    valid delivery, so only ids that NEVER arrived validly count as violations.
    """
    good = {d.event_id for d in t.deliveries if d.delivered and d.signature_valid(t.secret)}
    bad_only = t.bad_signature_events() - good
    ledger_events = {e.event_id for e in t.state.ledger}
    offending_events = sorted(bad_only & ledger_events)
    offenders = {e.order_id for e in t.state.ledger if e.event_id in offending_events}
    money = sum(t.order_amount(o) for o in offenders)
    passed = not offending_events
    detail = ("no unsigned or tampered event changed state" if passed
              else f"acted on events with invalid signatures: {offending_events}")
    return OracleResult("signature_integrity", passed, detail, money, offenders, offending_events)


def terminal_state_monotonicity(t: Trace) -> OracleResult:
    """Order status may only move created -> paid -> refunded, never backwards."""
    offenders: set[str] = set()
    for order_id, history in t.state.status_history.items():
        seen_paid = seen_refunded = False
        for s in history:
            if s == C.PAID:
                if seen_refunded:
                    offenders.add(order_id)
                seen_paid = True
            elif s == C.REFUNDED:
                if not seen_paid:
                    offenders.add(order_id)
                seen_refunded = True
    money = sum(t.order_amount(o) for o in offenders)
    passed = not offenders
    detail = ("order lifecycles are legal" if passed
              else f"illegal status transitions on orders {sorted(offenders)}")
    return OracleResult("terminal_state_monotonicity", passed, detail, money, offenders)


def no_over_refund(t: Trace) -> OracleResult:
    """You cannot refund more than you captured."""
    offenders: set[str] = set()
    money = 0
    for order_id in {e.order_id for e in t.state.ledger}:
        over = t.state.refunded_paise(order_id) - t.state.captured_paise(order_id)
        if over > 0:
            offenders.add(order_id)
            money += over
    passed = not offenders
    detail = ("no order was refunded beyond what it captured" if passed
              else f"refunded more than captured on orders {sorted(offenders)}")
    return OracleResult("no_over_refund", passed, detail, money, offenders)


def currency_consistency(t: Trace) -> OracleResult:
    """Money booked against an order must be in that order's currency."""
    offenders: set[str] = set()
    events: list[str] = []
    for e in t.state.ledger:
        if e.currency != t.order_currency(e.order_id):
            offenders.add(e.order_id)
            events.append(e.event_id)
    money = sum(t.order_amount(o) for o in offenders)
    passed = not offenders
    detail = ("every entry is in the order's currency" if passed
              else f"currency mismatch booked on orders {sorted(offenders)}")
    return OracleResult("currency_consistency", passed, detail, money, offenders, events)


ORACLES: list[Callable[[Trace], OracleResult]] = [
    idempotency, conservation, no_unpaid_fulfillment, reconciliation_completeness,
    signature_integrity, terminal_state_monotonicity, no_over_refund, currency_consistency,
]

ORACLE_NAMES = [o.__name__ for o in ORACLES]


def evaluate(t: Trace) -> list[OracleResult]:
    return [oracle(t) for oracle in ORACLES]
