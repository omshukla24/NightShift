"""The Razorpay bridge: real-webhook parsing + a remote handler over a stub transport."""
import json

import pytest

from nightshift import constants as C
from nightshift.adapters import RemoteHandler, delivery_from_webhook, razorpay_signature
from nightshift.handlers import NaiveHandler
from nightshift.runner import DEFAULT_SECRET


def _webhook(event, key, entity):
    return json.dumps({"id": "evt_1", "event": event, "created_at": 1700,
                       "payload": {key: {"entity": entity}}}).encode()


def test_parses_real_capture_webhook():
    body = _webhook("payment.captured", "payment",
                    {"id": "pay_1", "order_id": "ord_1", "amount": 50000, "currency": "INR"})
    d = delivery_from_webhook(body, razorpay_signature(DEFAULT_SECRET, body))
    assert d.kind == C.CAPTURE and d.amount == 50000 and d.order_id == "ord_1"
    assert d.signature_valid(DEFAULT_SECRET)


def test_parses_real_refund_webhook():
    body = _webhook("refund.processed", "refund",
                    {"id": "rfnd_1", "order_id": "ord_1", "amount": 20000, "currency": "INR"})
    d = delivery_from_webhook(body, "sig")
    assert d.kind == C.REFUND and d.amount == 20000


def test_unsupported_event_rejected():
    body = _webhook("payment.failed", "payment", {"id": "p", "order_id": "o", "amount": 1})
    with pytest.raises(ValueError):
        delivery_from_webhook(body, "sig")


def test_remote_handler_drives_backend_over_transport():
    backend = NaiveHandler(DEFAULT_SECRET)
    backend.register_order("ord_1", 50000)
    seen = []

    def transport(method, path, body, headers):
        seen.append((method, path))
        backend.handle(delivery_from_webhook(body, headers["X-Razorpay-Signature"]))

    body = _webhook("payment.captured", "payment",
                    {"id": "pay_1", "order_id": "ord_1", "amount": 50000, "currency": "INR"})
    d = delivery_from_webhook(body, razorpay_signature(DEFAULT_SECRET, body))
    rh = RemoteHandler(DEFAULT_SECRET, transport, lambda: backend.state)
    rh.handle(d)
    assert seen == [("POST", "/webhook")]
    assert rh.state.fulfillments == ["ord_1"]
