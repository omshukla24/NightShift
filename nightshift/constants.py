"""Single source of truth for the string literals the whole system shares.

Magic strings scattered across modules are how a `"capture"` in one file quietly
stops matching a `"catpure"` in another. Everything routes through here.
"""
from __future__ import annotations

# Movement kinds
CAPTURE = "capture"
REFUND = "refund"
KINDS = (CAPTURE, REFUND)

# Razorpay webhook event types
PAYMENT_CAPTURED = "payment.captured"
REFUND_PROCESSED = "refund.processed"
EVENT_TYPE_FOR_KIND = {CAPTURE: PAYMENT_CAPTURED, REFUND: REFUND_PROCESSED}

# Order lifecycle
CREATED = "created"
PAID = "paid"
REFUNDED = "refunded"

# Defaults
INR = "INR"

# The named defenses of the hardened handler (also the mutation-test targets).
DEF_SIG = "sig"
DEF_DEDUPE = "dedupe"
DEF_ORDER = "order"
DEF_AMOUNT = "amount"
DEF_VERIFY = "verify"
DEF_ORDERING = "ordering"
DEF_RECONCILE = "reconcile"
DEF_REFUND_BOUND = "refund_bound"
