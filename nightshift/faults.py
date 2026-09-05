"""Faults — the ways a webhook stream really arrives at 2 AM.

Each fault is a pure transform over an ideal (validly signed, in-order) list of
Deliveries. Nothing here is random: a fault takes a seed of explicit parameters
and produces a deterministic stream, so every run is reproducible and every
finding is grounded in an exact sequence of events (not "the model thought so").
"""
from __future__ import annotations

import copy
from typing import Callable

from . import constants as C
from .model import Delivery, build_delivery

BROKEN_SIGNATURE = "0" * 64  # a signature no secret could have produced


def duplicate(deliveries: list[Delivery], *, times: int = 2, kind: str = C.CAPTURE, **_) -> list[Delivery]:
    """Razorpay retries a webhook it thinks failed. The same event arrives N times."""
    out: list[Delivery] = []
    for d in deliveries:
        out.append(d)
        if d.kind == kind:
            for _ in range(times - 1):
                out.append(copy.copy(d))  # identical event_id — the idempotency key
    return out


def drop(deliveries: list[Delivery], *, kind: str = C.CAPTURE, **_) -> list[Delivery]:
    """A webhook is never delivered. The merchant only knows if it reconciles."""
    out = []
    for d in deliveries:
        nd = copy.copy(d)
        if d.kind == kind:
            nd.delivered = False
        out.append(nd)
    return out


def reorder(deliveries: list[Delivery], **_) -> list[Delivery]:
    """Events arrive out of order — a refund lands before its own capture."""
    return list(reversed(deliveries))


def tamper_amount(deliveries: list[Delivery], *, secret: str, to: int, **_) -> list[Delivery]:
    """An attacker edits the amount in the payload. The signature no longer matches."""
    out = []
    tampered = False
    for d in deliveries:
        if d.kind == C.CAPTURE and not tampered:
            nd = build_delivery(
                secret,
                event_id=d.event_id,
                etype=d.etype,
                order_id=d.order_id,
                payment_id=d.payment_id,
                kind=C.CAPTURE,
                amount=to,               # the lie
                currency=d.currency,
                amount_true=d.amount,    # the truth, kept for the oracles
            )
            nd.signature = BROKEN_SIGNATURE  # can't re-sign without the secret
            out.append(nd)
            tampered = True
        else:
            out.append(d)
    return out


def forge(
    deliveries: list[Delivery],
    *,
    secret: str,
    order_id: str,
    amount: int,
    payment_id: str = "pay_forged",
    **_,
) -> list[Delivery]:
    """A forged 'payment.captured' for an order that was never actually paid.

    This is exactly the shape of an AI-agent or fraudster spoofing a paid event.
    """
    nd = build_delivery(
        secret,
        event_id="evt_forged",
        etype=C.PAYMENT_CAPTURED,
        order_id=order_id,
        payment_id=payment_id,
        kind=C.CAPTURE,
        amount=amount,
        is_forged=True,
    )
    nd.signature = BROKEN_SIGNATURE
    return list(deliveries) + [nd]


def identity(deliveries: list[Delivery], **_) -> list[Delivery]:
    """No transport fault — the bug lives entirely in the handler (e.g. underpayment)."""
    return list(deliveries)


FAULTS: dict[str, Callable[..., list[Delivery]]] = {
    "duplicate": duplicate,
    "drop": drop,
    "reorder": reorder,
    "tamper_amount": tamper_amount,
    "forge": forge,
    "none": identity,
}
