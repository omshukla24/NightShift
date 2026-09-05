"""Core data model for NIGHTSHIFT.

Money is always an integer number of *paise* (1 rupee = 100 paise) — exactly like
the Razorpay API. Keeping money as ints (never floats) is itself one of the
invariants we defend: float rupees are how you silently lose money.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from . import constants as C
from .errors import ValidationError


def rupees(paise: int) -> str:
    """One place that formats money for humans. Never used for arithmetic."""
    return f"Rs {paise / 100:,.2f}"


def validate_amount(amount: int) -> int:
    if not isinstance(amount, int) or isinstance(amount, bool):
        raise ValidationError(f"amount must be an int number of paise, got {type(amount).__name__}")
    if amount <= 0:
        raise ValidationError(f"amount must be positive paise, got {amount}")
    return amount


# --------------------------------------------------------------------------- #
# Webhook signing — mirrors Razorpay's X-Razorpay-Signature scheme.
# --------------------------------------------------------------------------- #
def sign(secret: str, body: bytes) -> str:
    return hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()


def signature_is_valid(secret: str, body: bytes, signature: str) -> bool:
    if not signature:
        return False
    return hmac.compare_digest(sign(secret, body), signature)  # constant-time


# --------------------------------------------------------------------------- #
# Ground truth — what really happened on Razorpay's side.
# --------------------------------------------------------------------------- #
@dataclass(frozen=True, slots=True)
class TrueMovement:
    order_id: str
    payment_id: str
    kind: str
    amount: int
    currency: str = C.INR


@dataclass
class GroundTruth:
    order_amounts: dict[str, int] = field(default_factory=dict)
    order_currencies: dict[str, str] = field(default_factory=dict)
    movements: list[TrueMovement] = field(default_factory=list)

    def order_currency(self, order_id: str) -> str:
        return self.order_currencies.get(order_id, C.INR)

    def true_captures(self) -> list[TrueMovement]:
        return [m for m in self.movements if m.kind == C.CAPTURE]

    def is_true_capture(self, payment_id: str, order_id: str, amount: int) -> bool:
        return any(
            m.kind == C.CAPTURE and m.payment_id == payment_id
            and m.order_id == order_id and m.amount == amount
            for m in self.movements
        )

    def net_paise(self) -> int:
        return sum(m.amount if m.kind == C.CAPTURE else -m.amount for m in self.movements)


# --------------------------------------------------------------------------- #
# A webhook delivery to the merchant.
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class Delivery:
    event_id: str
    etype: str
    order_id: str
    payment_id: str
    kind: str
    amount: int
    currency: str
    body: bytes
    signature: str
    delivered: bool = True
    created_at: int = 0
    is_forged: bool = False
    amount_true: Optional[int] = None
    _sig_ok: Optional[bool] = field(default=None, compare=False, repr=False)

    def signature_valid(self, secret: str) -> bool:
        if self._sig_ok is None:
            self._sig_ok = signature_is_valid(secret, self.body, self.signature)
        return self._sig_ok


def build_delivery(
    secret: str,
    *,
    event_id: str,
    etype: str,
    order_id: str,
    payment_id: str,
    kind: str,
    amount: int,
    currency: str = C.INR,
    created_at: Optional[int] = None,
    is_forged: bool = False,
    amount_true: Optional[int] = None,
) -> Delivery:
    if kind not in C.KINDS:
        raise ValidationError(f"unknown kind {kind!r}")
    validate_amount(amount)
    ts = created_at if created_at is not None else int(time.time())
    payload = {
        "id": event_id, "event": etype, "created_at": ts,
        "payload": {kind: {"entity": {
            "id": payment_id, "order_id": order_id, "amount": amount, "currency": currency,
        }}},
    }
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return Delivery(
        event_id=event_id, etype=etype, order_id=order_id, payment_id=payment_id,
        kind=kind, amount=amount, currency=currency, body=body,
        signature=sign(secret, body), created_at=ts,
        is_forged=is_forged, amount_true=amount_true if amount_true is not None else amount,
    )


# --------------------------------------------------------------------------- #
# What a handler records.
# --------------------------------------------------------------------------- #
@dataclass(slots=True)
class LedgerEntry:
    event_id: str
    order_id: str
    kind: str
    amount: int
    currency: str = C.INR


@dataclass(slots=True)
class Order:
    order_id: str
    amount: int
    currency: str = C.INR
    status: str = C.CREATED


@dataclass
class MerchantState:
    orders: dict[str, Order] = field(default_factory=dict)
    ledger: list[LedgerEntry] = field(default_factory=list)
    fulfillments: list[str] = field(default_factory=list)
    status_history: dict[str, list[str]] = field(default_factory=dict)
    processed_event_ids: set[str] = field(default_factory=set)
    rejected_event_ids: list[str] = field(default_factory=list)
    captured_orders: set[str] = field(default_factory=set)
    refunded_orders: set[str] = field(default_factory=set)

    def book(self, event_id: str, order_id: str, kind: str, amount: int, currency: str = C.INR) -> None:
        self.ledger.append(LedgerEntry(event_id, order_id, kind, amount, currency))
        (self.captured_orders if kind == C.CAPTURE else self.refunded_orders).add(order_id)

    def fulfill(self, order_id: str) -> None:
        self.fulfillments.append(order_id)

    def reject(self, event_id: str) -> None:
        self.rejected_event_ids.append(event_id)

    def mark_processed(self, event_id: str) -> None:
        self.processed_event_ids.add(event_id)

    def has_capture(self, order_id: str) -> bool:
        return order_id in self.captured_orders

    def has_refund(self, order_id: str) -> bool:
        return order_id in self.refunded_orders

    def refunded_paise(self, order_id: str) -> int:
        return sum(e.amount for e in self.ledger if e.order_id == order_id and e.kind == C.REFUND)

    def captured_paise(self, order_id: str) -> int:
        return sum(e.amount for e in self.ledger if e.order_id == order_id and e.kind == C.CAPTURE)

    def set_status(self, order_id: str, status: str) -> None:
        self.status_history.setdefault(order_id, []).append(status)
        if order_id in self.orders:
            self.orders[order_id].status = status

    def net_paise(self) -> int:
        return sum(e.amount if e.kind == C.CAPTURE else -e.amount for e in self.ledger)


Verifier = Callable[[str, str, int], bool]
