"""The integration everyone writes first.

Every one of these lines looks reasonable in a tutorial. Together they are six
different ways to lose money at 2 AM. NIGHTSHIFT's oracles find all of them.
"""
from __future__ import annotations

from .. import constants as C
from ..model import Delivery, Order
from .base import PaymentHandler


class NaiveHandler(PaymentHandler):
    def handle(self, d: Delivery) -> None:
        if not d.delivered:
            return  # a dropped webhook simply never arrives — and is never noticed

        # BUG 1: never verifies the signature. A forged or tampered event is trusted.
        # BUG 2: never dedupes on event_id. A replayed webhook is processed again.
        # BUG 3: trusts an unknown order_id, auto-creating it from the event.
        if d.order_id not in self.state.orders:
            self.state.orders[d.order_id] = Order(d.order_id, d.amount, d.currency, C.CREATED)

        if d.kind == C.CAPTURE:
            # BUG 4: records the *delivered* amount and currency, never checking them.
            # BUG 5: fulfills on the webhook alone, without confirming with Razorpay.
            self.state.book(d.event_id, d.order_id, C.CAPTURE, d.amount, d.currency)
            self.state.set_status(d.order_id, C.PAID)
            self.state.fulfill(d.order_id)
        elif d.kind == C.REFUND:
            # BUG 7: no bound check — refunds more than was captured, and blindly.
            self.state.book(d.event_id, d.order_id, C.REFUND, d.amount, d.currency)
            self.state.set_status(d.order_id, C.REFUNDED)

    # BUG 6: no reconcile() — a dropped webhook is money that silently vanishes.
