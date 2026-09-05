"""Optional live demo: expose the reference handlers over HTTP (FastAPI).

    pip install -e ".[web]"
    uvicorn targets.live_demo:app --reload

POST a signed webhook to /webhook/naive or /webhook/fixed and GET /state/<target>
to watch the ledger. This is only for the "it's real HTTP, not a script" beat in
the video — the harness itself needs none of it.
"""
from __future__ import annotations

try:
    from fastapi import FastAPI, Request
except Exception as e:  # pragma: no cover
    raise SystemExit("Install web extras first:  pip install -e \".[web]\"") from e

from nightshift import constants as C
from nightshift.handlers import FixedHandler, NaiveHandler
from nightshift.model import Delivery, signature_is_valid
from nightshift.runner import DEFAULT_SECRET

app = FastAPI(title="NIGHTSHIFT live demo")
_handlers = {"naive": NaiveHandler(DEFAULT_SECRET), "fixed": FixedHandler(DEFAULT_SECRET)}


@app.post("/register/{target}/{order_id}/{amount}")
def register(target: str, order_id: str, amount: int):
    _handlers[target].register_order(order_id, amount)
    return {"ok": True}


@app.post("/webhook/{target}")
async def webhook(target: str, request: Request):
    import json

    body = await request.body()
    sig = request.headers.get("X-Razorpay-Signature", "")
    evt = json.loads(body)                       # parse once
    kind = C.CAPTURE if C.CAPTURE in evt["event"] else C.REFUND
    ent = evt["payload"][kind]["entity"]
    d = Delivery(
        event_id=evt["id"], etype=evt["event"],
        order_id=ent["order_id"], payment_id=ent["id"], kind=kind,
        amount=ent["amount"], currency=ent["currency"], body=body, signature=sig,
    )
    _handlers[target].handle(d)
    return {"accepted_signature": signature_is_valid(DEFAULT_SECRET, body, sig)}


@app.get("/state/{target}")
def state(target: str):
    s = _handlers[target].state
    return {
        "fulfillments": s.fulfillments,
        "ledger": [e.__dict__ for e in s.ledger],
        "net_paise": s.net_paise(),
        "rejected": s.rejected_event_ids,
    }
