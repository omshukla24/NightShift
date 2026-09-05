"""The scenarios — each a real 2 AM incident, encoded as data.

A scenario is: the orders a merchant created, what *truly* happened on Razorpay's
side (ground truth), and the transport fault applied to the webhook stream. The
`expected_naive` set is the ground-truth label used by the test suite and the
precision/recall bench. A `control` scenario is a legitimate, non-trivial flow
that must stay green on BOTH handlers — it's how we prove zero false positives.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from . import constants as C
from .faults import FAULTS
from .model import Delivery, GroundTruth, TrueMovement, build_delivery


@dataclass(frozen=True)
class Scenario:
    key: str
    title: str
    story: str
    orders: tuple[tuple[str, int], ...]
    movements: tuple[tuple[str, str, str, int], ...]
    fault: str = "none"
    fault_params: dict = field(default_factory=dict)
    reconcile: bool = False
    control: bool = False
    expected_naive: frozenset[str] = frozenset()

    @staticmethod
    def _mv(m):
        """A movement is (order_id, payment_id, kind, amount[, currency])."""
        order_id, payment_id, kind, amount = m[0], m[1], m[2], m[3]
        currency = m[4] if len(m) > 4 else C.INR
        return order_id, payment_id, kind, amount, currency

    def ground_truth(self) -> GroundTruth:
        gt = GroundTruth(order_amounts={oid: amt for oid, amt in self.orders})
        gt.movements = [TrueMovement(*self._mv(m)) for m in self.movements]
        return gt

    def ideal_deliveries(self, secret: str) -> list[Delivery]:
        out: list[Delivery] = []
        for i, m in enumerate(self.movements):
            order_id, payment_id, kind, amount, currency = self._mv(m)
            out.append(build_delivery(
                secret,
                event_id=f"evt_{self.key}_{i}",
                etype=C.EVENT_TYPE_FOR_KIND[kind],
                order_id=order_id, payment_id=payment_id, kind=kind,
                amount=amount, currency=currency,
                created_at=1_700_000_000 + i,  # deterministic, increasing
            ))
        return out

    def actual_deliveries(self, secret: str) -> list[Delivery]:
        return FAULTS[self.fault](self.ideal_deliveries(secret), secret=secret, **self.fault_params)


SCENARIOS: list[Scenario] = [
    Scenario(
        key="replay",
        title="Webhook replay (missing idempotency)",
        story="Razorpay retries a webhook it believed failed. The same "
        "payment.captured lands three times. The order ships three times.",
        orders=(("ord_replay", 50000),),
        movements=(("ord_replay", "pay_replay", C.CAPTURE, 50000),),
        fault="duplicate", fault_params={"times": 3},
        expected_naive=frozenset({"idempotency", "conservation"}),
    ),
    Scenario(
        key="dropped",
        title="Dropped webhook (no reconciliation)",
        story="The capture webhook never arrives. The customer paid; the "
        "merchant has no record of it, and never reconciles.",
        orders=(("ord_drop", 120000),),
        movements=(("ord_drop", "pay_drop", C.CAPTURE, 120000),),
        fault="drop", reconcile=True,
        expected_naive=frozenset({"reconciliation_completeness"}),
    ),
    Scenario(
        key="reorder",
        title="Out-of-order events (refund before capture)",
        story="The refund webhook overtakes the capture. A naive state machine "
        "marks the order refunded, then paid — money out, goods out.",
        orders=(("ord_reorder", 80000),),
        movements=(("ord_reorder", "pay_reorder", C.CAPTURE, 80000),
                   ("ord_reorder", "rfnd_reorder", C.REFUND, 80000)),
        fault="reorder", reconcile=True,
        expected_naive=frozenset({"terminal_state_monotonicity"}),
    ),
    Scenario(
        key="underpaid",
        title="Short payment (amount not checked against order)",
        story="The order is for Rs 1000, but a real, validly-signed capture "
        "arrives for Rs 1. The handler never compares the two, and fulfills.",
        orders=(("ord_under", 100000),),
        movements=(("ord_under", "pay_under", C.CAPTURE, 100),),
        fault="none",
        expected_naive=frozenset({"no_unpaid_fulfillment"}),
    ),
    Scenario(
        key="tampered",
        title="Tampered amount (signature not verified)",
        story="An attacker rewrites the amount in the payload. The signature no "
        "longer matches — but the handler never checks it, and books the lie.",
        orders=(("ord_tamper", 200000),),
        movements=(("ord_tamper", "pay_tamper", C.CAPTURE, 200000),),
        fault="tamper_amount", fault_params={"to": 2000}, reconcile=True,
        expected_naive=frozenset({"conservation", "signature_integrity"}),
    ),
    Scenario(
        key="forged",
        title="Forged capture (spoofed paid event)",
        story="An order is abandoned, never paid. A forged payment.captured is "
        "posted to the webhook URL. Unsigned-but-trusted, it ships for free.",
        orders=(("ord_forged", 60000),),
        movements=(),
        fault="forge", fault_params={"order_id": "ord_forged", "amount": 60000},
        expected_naive=frozenset({"no_unpaid_fulfillment", "signature_integrity", "conservation"}),
    ),
    Scenario(
        key="double_refund",
        title="Replayed refund (idempotency on refunds)",
        story="A refund webhook is retried. A handler that only dedupes captures "
        "books the refund twice — paying the customer back twice.",
        orders=(("ord_dref", 90000),),
        movements=(("ord_dref", "pay_dref", C.CAPTURE, 90000),
                   ("ord_dref", "rfnd_dref", C.REFUND, 90000)),
        fault="duplicate", fault_params={"times": 2, "kind": C.REFUND},
        expected_naive=frozenset({"idempotency", "conservation", "no_over_refund"}),
    ),
    Scenario(
        key="currency_swap",
        title="Currency mismatch (wrong-currency capture)",
        story="A capture arrives in USD for an order priced in INR. The handler "
        "books the number without checking the currency and ships against it.",
        orders=(("ord_ccy", 60000),),
        movements=(("ord_ccy", "pay_ccy", C.CAPTURE, 60000, "USD"),),
        fault="none",
        expected_naive=frozenset({"currency_consistency", "no_unpaid_fulfillment"}),
    ),
    Scenario(
        key="over_refund",
        title="Over-refund (refunding more than captured)",
        story="A refund is issued for Rs 800 against an order that only captured "
        "Rs 500. The handler pays it out without bounding it to the capture.",
        orders=(("ord_over", 50000),),
        movements=(("ord_over", "pay_over", C.CAPTURE, 50000),
                   ("ord_over", "rfnd_over", C.REFUND, 80000)),
        fault="none",
        expected_naive=frozenset({"no_over_refund"}),
    ),
    Scenario(
        key="partial_refund",
        title="Partial refund (legitimate — must stay green)",
        story="A customer is refunded part of a paid order. This is a correct, "
        "normal flow: no invariant should fire on either handler.",
        orders=(("ord_partial", 100000),),
        movements=(("ord_partial", "pay_partial", C.CAPTURE, 100000),
                   ("ord_partial", "rfnd_partial", C.REFUND, 40000)),
        fault="none", control=True,
        expected_naive=frozenset(),
    ),
]


def by_key(key: str) -> Scenario:
    for s in SCENARIOS:
        if s.key == key:
            return s
    raise KeyError(key)
