"""The common interface every target integration implements.

A handler is the System Under Test. NIGHTSHIFT ships two reference targets:
  - NaiveHandler: the integration everyone writes first. It works in the demo
    and loses money at 2 AM.
  - FixedHandler: the same integration, hardened. It passes every oracle.

Your real submission can wrap Razorpay's official sample app behind this
interface (see targets/) and point the harness at it.
"""
from __future__ import annotations

from ..model import Delivery, MerchantState, Order, Verifier


class PaymentHandler:
    def __init__(self, secret: str, verifier: Verifier | None = None) -> None:
        self.secret = secret
        self.verifier = verifier
        self.state = MerchantState()

    def register_order(self, order_id: str, amount: int, currency: str = "INR") -> None:
        """Merchant creates an order (the amount it expects to be paid)."""
        self.state.orders[order_id] = Order(order_id, amount, currency, "created")

    def handle(self, d: Delivery) -> None:  # pragma: no cover - overridden
        raise NotImplementedError

    def reconcile(self, movements) -> None:
        """Poll Razorpay for settled payments/refunds and backfill anything missing.

        No-op by default; a correct integration overrides this to close the gap
        left by a dropped or rejected webhook. `movements` is the list of true
        TrueMovement records (what a Razorpay API poll would return).
        """
        return
