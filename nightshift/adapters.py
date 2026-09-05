"""Bridges to a real Razorpay integration.

Three things you need to fuzz your actual app instead of the reference handlers:

  * `razorpay_signature` — sign a body exactly as Razorpay does (HMAC-SHA256).
  * `delivery_from_webhook` — turn a *real* captured Razorpay webhook JSON into a
    NIGHTSHIFT Delivery, so you can replay and fuzz production payloads.
  * `RemoteHandler` — a PaymentHandler that drives your app over HTTP: it POSTs each
    (possibly faulted) webhook to your endpoint and reads back your app's state. The
    HTTP transport and the state reader are injected, so it's testable without a
    server and swappable for `requests` in production.
"""
from __future__ import annotations

import json
from typing import Callable

from . import constants as C
from .model import Delivery, MerchantState, sign
from .handlers.base import PaymentHandler

razorpay_signature = sign  # identical scheme; re-exported for discoverability

# Razorpay puts the entity under payload.payment / payload.refund, keyed by the
# event family, not by our internal "capture"/"refund" kind.
_PAYLOAD_KEY = {C.PAYMENT_CAPTURED: "payment", C.REFUND_PROCESSED: "refund"}
_KIND = {C.PAYMENT_CAPTURED: C.CAPTURE, C.REFUND_PROCESSED: C.REFUND}


def delivery_from_webhook(body: bytes, signature: str) -> Delivery:
    """Parse a real Razorpay webhook body into a Delivery (no re-signing)."""
    evt = json.loads(body)
    etype = evt["event"]
    if etype not in _PAYLOAD_KEY:
        raise ValueError(f"unsupported event type {etype!r}")
    entity = evt["payload"][_PAYLOAD_KEY[etype]]["entity"]
    return Delivery(
        event_id=evt.get("id", entity.get("id", "")),
        etype=etype,
        order_id=entity["order_id"],
        payment_id=entity["id"],
        kind=_KIND[etype],
        amount=int(entity["amount"]),
        currency=entity.get("currency", C.INR),
        body=body,
        signature=signature,
        created_at=int(evt.get("created_at", 0)),
    )


# Transport signature: (method, path, body, headers) -> anything.
Transport = Callable[[str, str, bytes, dict], object]
StateReader = Callable[[], MerchantState]


class RemoteHandler(PaymentHandler):
    """Drive a real integration over HTTP; read its state back for the oracles."""

    def __init__(self, secret: str, transport: Transport, read_state: StateReader,
                 path: str = "/webhook") -> None:
        super().__init__(secret)
        self._transport = transport
        self._read_state = read_state
        self._path = path

    def handle(self, d: Delivery) -> None:
        if not d.delivered:
            return
        self._transport("POST", self._path, d.body, {"X-Razorpay-Signature": d.signature})

    @property
    def state(self) -> MerchantState:  # type: ignore[override]
        return self._read_state()

    @state.setter
    def state(self, _value) -> None:
        # PaymentHandler.__init__ assigns self.state; ignore — state lives remotely.
        pass
