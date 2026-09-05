"""The same integration, hardened. Passes every oracle.

The diff between this and NaiveHandler *is* the submission's core lesson: cheap
checks, enforced in code, that no amount of prompting can replace.

Each check is a named, toggleable *defense*. With all defenses on (the default)
the handler is correct. The precision/recall bench turns them off one at a time
(mutation testing) to prove each oracle catches exactly the defense it guards.
"""
from __future__ import annotations

from .. import constants as C
from ..model import Delivery
from .base import PaymentHandler

# Default hardened handler. Each defense is the sole guard for one failure class
# (proven by the mutation bench). Mutation testing showed the old "ordering" check
# (reject refund-before-capture) was fully subsumed by "refund_bound" — a refund
# before any capture always exceeds the zero captured — so it was removed as dead
# code. "verify" (a full Razorpay API confirm per event) is real defense-in-depth
# but redundant with amount+signature here, so it is opt-in, not default.
ALL_DEFENSES = frozenset({C.DEF_SIG, C.DEF_DEDUPE, C.DEF_ORDER, C.DEF_AMOUNT,
                          C.DEF_RECONCILE, C.DEF_REFUND_BOUND})


class FixedHandler(PaymentHandler):
    def __init__(self, secret, verifier=None, defenses=None) -> None:
        super().__init__(secret, verifier)
        self.defenses = ALL_DEFENSES if defenses is None else frozenset(defenses)

    def _on(self, name: str) -> bool:
        return name in self.defenses

    def handle(self, d: Delivery) -> None:
        if not d.delivered:
            return  # still dropped — but reconcile() below closes the gap

        # FIX 1: verify the signature. No valid signature => no state change, ever.
        if self._on(C.DEF_SIG) and not d.signature_valid(self.secret):
            self.state.reject(d.event_id)
            return

        # FIX 2: idempotency. The event_id is the natural key; process it once.
        if self._on(C.DEF_DEDUPE) and d.event_id in self.state.processed_event_ids:
            return

        # FIX 3: never trust an unknown order.
        order = self.state.orders.get(d.order_id)
        if self._on(C.DEF_ORDER) and order is None:
            self.state.reject(d.event_id)
            return

        if d.kind == C.CAPTURE:
            # FIX 4: the delivered amount must match the order we created.
            if self._on(C.DEF_AMOUNT) and (order is None or d.amount != order.amount or d.currency != order.currency):
                self.state.reject(d.event_id)
                return
            # FIX 5 (opt-in): confirm against Razorpay itself before releasing anything.
            if self._on(C.DEF_VERIFY) and (self.verifier is None or not self.verifier(d.payment_id, d.order_id, d.amount)):
                self.state.reject(d.event_id)
                return
            self.state.mark_processed(d.event_id)
            cur = order.currency if order else d.currency
            self.state.book(d.event_id, d.order_id, C.CAPTURE, order.amount if order else d.amount, cur)
            self.state.set_status(d.order_id, C.PAID)
            self.state.fulfill(d.order_id)

        elif d.kind == C.REFUND:
            # FIX 6: never refund more than was captured on the order. This also
            # rejects a refund that arrives before any capture (captured == 0),
            # which is why a separate ordering check is unnecessary.
            if self._on(C.DEF_REFUND_BOUND) and \
                    self.state.refunded_paise(d.order_id) + d.amount > self.state.captured_paise(d.order_id):
                self.state.reject(d.event_id)
                return
            self.state.mark_processed(d.event_id)
            cur = order.currency if order else d.currency
            self.state.book(d.event_id, d.order_id, C.REFUND, d.amount, cur)
            self.state.set_status(d.order_id, C.REFUNDED)

    def reconcile(self, movements) -> None:
        """Close the gap a dropped or rejected webhook leaves, by polling Razorpay.

        Idempotent: re-running it never double-books, because it checks the O(1)
        capture/refund indexes before writing.
        """
        if not self._on(C.DEF_RECONCILE):
            return

        for m in movements:
            if m.kind != C.CAPTURE or self.state.has_capture(m.order_id):
                continue
            order = self.state.orders.get(m.order_id)
            if order is None or m.amount != order.amount or m.currency != order.currency:
                continue  # only full, legitimate, same-currency payments get fulfilled
            self.state.book(f"recon:{m.payment_id}", m.order_id, C.CAPTURE, order.amount, order.currency)
            self.state.set_status(m.order_id, C.PAID)
            self.state.fulfill(m.order_id)

        for m in movements:
            if m.kind != C.REFUND or self.state.has_refund(m.order_id):
                continue
            if not self.state.has_capture(m.order_id):
                continue
            if self.state.refunded_paise(m.order_id) + m.amount > self.state.captured_paise(m.order_id):
                continue  # never reconcile a refund beyond the capture
            order = self.state.orders.get(m.order_id)
            cur = order.currency if order else m.currency
            self.state.book(f"recon:{m.payment_id}", m.order_id, C.REFUND, m.amount, cur)
            self.state.set_status(m.order_id, C.REFUNDED)
