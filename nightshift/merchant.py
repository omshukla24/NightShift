"""A REAL Razorpay-integrated merchant — the target you actually ship.

The bundled reference server (`nightshift serve`) is pure stdlib with made-up
orders. THIS is a real Razorpay integration:

  * it creates real *test-mode* orders through the Razorpay SDK (`order.create`),
    so every purchase shows up in your Razorpay Dashboard;
  * it verifies webhook signatures with Razorpay's own `Utility.verify_webhook_
    signature`, using YOUR webhook secret — the exact code path production runs.

NIGHTSHIFT then red-teams it the same way it would attack your live app.

    nightshift merchant --port 5000              # a handler with the usual bugs
    nightshift merchant --port 5001 --hardened   # the same integration, done safely
    nightshift --secret <your-webhook-secret> scan --url http://localhost:5000

Config (environment variables):
    NIGHTSHIFT_SECRET      your Razorpay webhook secret — used BOTH to verify here
                           and to sign the scan, so the two always agree.
    RAZORPAY_KEY_ID        rzp_test_xxxxx   (only needed for the live storefront)
    RAZORPAY_KEY_SECRET    xxxxxxxxxxxxx    (only needed for the live storefront)

Only the webhook secret is needed to run a real security scan. The two API keys
light up the storefront (creating real orders); without them the shop page tells
you exactly what to add, and the /webhook + /state endpoints NIGHTSHIFT drives
keep working — so you can scan before checkout is fully wired.

Everything binds to 127.0.0.1. Nothing is published.
"""
from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import threading
import time
import webbrowser

from . import constants as C

# The tell-tale gap between "check if seen" and "record as seen" in real code.
RACE_WINDOW_SECONDS = 0.02
# Reject events whose Razorpay timestamp is older than this (anti-replay).
FRESHNESS_WINDOW_SECONDS = 300


# --------------------------------------------------------------------------- #
# secrets / keys
# --------------------------------------------------------------------------- #
def webhook_secret() -> str:
    """The webhook secret this app verifies with — also what you scan with."""
    return (os.getenv("NIGHTSHIFT_SECRET")
            or os.getenv("RAZORPAY_WEBHOOK_SECRET")
            or "whsec_nightshift_demo")


def _api_keys() -> tuple[str | None, str | None]:
    return os.getenv("RAZORPAY_KEY_ID"), os.getenv("RAZORPAY_KEY_SECRET")


# --------------------------------------------------------------------------- #
# signature verification — the REAL Razorpay SDK path, with a stdlib fallback
# that computes the byte-identical HMAC-SHA256 digest.
# --------------------------------------------------------------------------- #
def verify_signature(body: bytes, signature: str, secret: str) -> bool:
    """True iff `signature` is a valid Razorpay signature over `body`.

    Uses razorpay.Utility().verify_webhook_signature when the SDK is installed
    (identical scheme, exercised the way production does); otherwise falls back
    to the same HMAC-SHA256 hex digest the SDK computes internally.
    """
    if not signature:
        return False
    try:
        import razorpay  # the real thing
        razorpay.Utility().verify_webhook_signature(body.decode("utf-8"), signature, secret)
        return True  # no exception == valid
    except ImportError:
        expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, signature)
    except Exception:
        return False  # SignatureVerificationError (or malformed) == invalid


# --------------------------------------------------------------------------- #
# in-memory merchant store (same shape the scanner + oracles read)
# --------------------------------------------------------------------------- #
class Store:
    def __init__(self) -> None:
        self.orders: dict[str, dict] = {}
        self.ledger: list[dict] = []
        self.fulfillments: list[str] = []
        self.processed: set[str] = set()
        self.lock = threading.Lock()

    def register(self, order_id: str, amount: int, currency: str = C.INR) -> None:
        self.orders[order_id] = {"amount": int(amount), "currency": currency}

    def snapshot(self) -> dict:
        cap = sum(e["amount"] for e in self.ledger if e["kind"] == C.CAPTURE)
        ref = sum(e["amount"] for e in self.ledger if e["kind"] == C.REFUND)
        return {
            "orders": self.orders, "ledger": self.ledger,
            "fulfillments": self.fulfillments, "processed": sorted(self.processed),
            "captured_paise": cap, "refunded_paise": ref, "net_paise": cap - ref,
        }


def _entity(evt: dict):
    etype = evt["event"]
    key = "payment" if C.CAPTURE in etype else "refund"
    kind = C.CAPTURE if C.CAPTURE in etype else C.REFUND
    return kind, evt["payload"][key]["entity"]


# --------------------------------------------------------------------------- #
# the two webhook handlers — the whole point of the scan
# --------------------------------------------------------------------------- #
def handle_naive(store: Store, body: bytes, sig: str, secret: str) -> dict:
    """The integration everyone writes first.

    BUG: the signature is never verified. BUG: it *has* a dedupe check, but the
    check-then-record isn't atomic, so concurrent deliveries double-spend. No
    freshness window, no known-order check, no refund bound.
    """
    evt = json.loads(body)
    eid = evt.get("id", "")
    if eid in store.processed:                    # dedupe: catches a *sequential* replay
        return {"status": "duplicate ignored"}
    kind, ent = _entity(evt)
    oid = ent["order_id"]
    time.sleep(RACE_WINDOW_SECONDS)               # a DB round-trip: the race window
    store.orders.setdefault(oid, {"amount": int(ent["amount"]),
                                  "currency": ent.get("currency", C.INR)})
    store.processed.add(eid)
    store.ledger.append({"event_id": eid, "order_id": oid, "kind": kind,
                         "amount": int(ent["amount"]), "currency": ent.get("currency", C.INR)})
    if kind == C.CAPTURE:
        store.fulfillments.append(oid)
    return {"status": "processed"}


def handle_hardened(store: Store, body: bytes, sig: str, secret: str) -> dict:
    """The same integration, done safely — every attack bounces."""
    if not verify_signature(body, sig, secret):
        return {"status": "rejected: bad signature"}
    evt = json.loads(body)
    if int(evt.get("created_at", 0)) < int(time.time()) - FRESHNESS_WINDOW_SECONDS:
        return {"status": "rejected: stale event"}
    with store.lock:                              # atomic check-and-act
        eid = evt.get("id", "")
        if eid in store.processed:
            return {"status": "duplicate ignored"}
        kind, ent = _entity(evt)
        oid = ent["order_id"]
        order = store.orders.get(oid)
        if order is None:                         # never fulfil an order we didn't create
            return {"status": "rejected: unknown order"}
        amt = int(ent["amount"])
        if kind == C.CAPTURE and (amt != order["amount"]
                                  or ent.get("currency", C.INR) != order["currency"]):
            return {"status": "rejected: amount/currency mismatch"}
        if kind == C.REFUND:
            refunded = sum(e["amount"] for e in store.ledger
                           if e["order_id"] == oid and e["kind"] == C.REFUND)
            captured = sum(e["amount"] for e in store.ledger
                           if e["order_id"] == oid and e["kind"] == C.CAPTURE)
            if refunded + amt > captured:
                return {"status": "rejected: over-refund"}
        store.processed.add(eid)
        booked = order["amount"] if kind == C.CAPTURE else amt
        store.ledger.append({"event_id": eid, "order_id": oid, "kind": kind,
                             "amount": booked, "currency": order["currency"]})
        if kind == C.CAPTURE:
            store.fulfillments.append(oid)
        return {"status": "processed"}


# --------------------------------------------------------------------------- #
# storefront
# --------------------------------------------------------------------------- #
_SHOP_HTML = r"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Acme Pay — a real Razorpay checkout</title>
<script src="https://checkout.razorpay.com/v1/checkout.js"></script>
<style>
:root{color-scheme:light}*{box-sizing:border-box}
body{margin:0;background:#f4f2ee;color:#181614;font:15px/1.55 -apple-system,Segoe UI,Roboto,sans-serif}
.wrap{max-width:640px;margin:0 auto;padding:40px 20px}
.card{background:#fff;border:1px solid #e6e1d8;border-radius:16px;padding:28px;box-shadow:0 1px 3px rgba(0,0,0,.05)}
h1{font-size:22px;margin:0 0 2px}.sub{color:#7a736a;margin:0 0 22px;font-size:13px}
.prod{display:flex;justify-content:space-between;align-items:center;border:1px solid #ece7de;border-radius:12px;padding:18px 20px;margin-bottom:18px}
.prod b{font-size:17px}.prod small{color:#8a8378}
.price{font-size:22px;font-weight:800}
.btn{border:0;border-radius:10px;padding:13px 22px;font:inherit;font-weight:700;cursor:pointer;background:#3395ff;color:#fff;font-size:15px}
.btn:disabled{opacity:.5;cursor:default}
.mode{display:inline-block;font-size:11px;font-weight:800;letter-spacing:.06em;text-transform:uppercase;padding:3px 9px;border-radius:999px;margin-left:8px}
.mode.naive{background:#fde7e7;color:#c02626}.mode.hardened{background:#e3f6e8;color:#1a7f37}
.banner{background:#fff7e6;border:1px solid #ffe1a8;border-radius:10px;padding:12px 14px;font-size:13px;margin-bottom:18px;color:#7a5a10}
.banner code{background:#fceecb;padding:1px 5px;border-radius:4px}
#out{margin-top:16px;font-size:13px;white-space:pre-wrap;font-family:ui-monospace,Menlo,monospace}
.ok{color:#1a7f37}.err{color:#c02626}
.footnote{margin-top:22px;color:#9a938a;font-size:12px}
</style></head><body><div class="wrap"><div class="card">
<h1>Acme Pay <span class="mode {mode}">{mode} integration</span></h1>
<p class="sub">A real Razorpay checkout, running on <b>127.0.0.1</b>. Orders are created in test mode.</p>
{banner}
<div class="prod"><span><b>Premium Plan</b><br><small>1 seat · monthly</small></span>
  <span class="price">₹500</span></div>
<button class="btn" id="pay" {disabled}>Pay ₹500 with Razorpay</button>
<div id="out"></div>
<p class="footnote">This is the app NIGHTSHIFT attacks. Run
<code style="background:#f0ece3;padding:1px 5px;border-radius:4px">nightshift scan --url http://localhost:{port}</code>
in another terminal to red-team this exact endpoint.</p>
</div></div>
<script>
const out=document.getElementById('out');
document.getElementById('pay').onclick=async()=>{
  out.textContent='Creating a real test-mode order…';
  let r;
  try{ r=await (await fetch('/create-order',{method:'POST'})).json(); }
  catch(e){ out.innerHTML='<span class="err">Could not reach the server.</span>'; return; }
  if(r.error){ out.innerHTML='<span class="err">'+r.error+'</span>'; return; }
  out.innerHTML='<span class="ok">Order '+r.order_id+' created in your Razorpay Dashboard.</span>\nOpening Razorpay Checkout…';
  const rzp=new Razorpay({
    key:r.key_id, order_id:r.order_id, amount:r.amount, currency:r.currency,
    name:'Acme Pay', description:'Premium Plan',
    handler:async(resp)=>{
      const v=await (await fetch('/verify-payment',{method:'POST',headers:{'Content-Type':'application/json'},
        body:JSON.stringify(resp)})).json();
      out.innerHTML = v.ok
        ? '<span class="ok">✓ Payment '+resp.razorpay_payment_id+' verified. Order '+r.order_id+' is paid.</span>'
        : '<span class="err">Signature verification FAILED — payment not trusted.</span>';
    },
    theme:{color:'#3395ff'}
  });
  rzp.on('payment.failed',f=>{out.innerHTML='<span class="err">Payment failed: '+(f.error&&f.error.description||'')+'</span>';});
  rzp.open();
};
</script></body></html>"""


def _shop_page(mode: str, port: int) -> str:
    key_id, key_secret = _api_keys()
    if key_id and key_secret:
        banner, disabled = "", ""
    else:
        banner = ('<div class="banner">Add <code>RAZORPAY_KEY_ID</code> and '
                  '<code>RAZORPAY_KEY_SECRET</code> to your environment to enable live checkout. '
                  'The security scan works without them.</div>')
        disabled = "disabled"
    return (_SHOP_HTML.replace("{mode}", mode).replace("{banner}", banner)
            .replace("{disabled}", disabled).replace("{port}", str(port)))


# --------------------------------------------------------------------------- #
# Flask app
# --------------------------------------------------------------------------- #
def build_app(hardened: bool = False, secret: str | None = None, port: int = 5000):
    try:
        from flask import Flask, request, jsonify
    except ImportError as e:  # pragma: no cover - surfaced by the CLI
        raise SystemExit(
            "The merchant app needs Flask (and the Razorpay SDK):\n"
            "    pip install flask razorpay\n"
            "  or:  pip install -e \".[merchant]\""
        ) from e

    secret = secret or webhook_secret()
    store = Store()
    app = Flask(__name__)
    mode = "hardened" if hardened else "naive"

    @app.get("/health")
    def health():
        return jsonify(ok=True, mode=mode)

    @app.get("/state")
    def state():
        return jsonify(store.snapshot())

    @app.post("/register")
    def register():
        o = request.get_json(force=True, silent=True) or {}
        store.register(o["order_id"], int(o["amount"]), o.get("currency", C.INR))
        return jsonify(ok=True)

    @app.post("/webhook")
    def webhook():
        body = request.get_data()                       # RAW bytes — what the signature covers
        sig = request.headers.get("X-Razorpay-Signature", "")
        res = (handle_hardened(store, body, sig, secret) if hardened
               else handle_naive(store, body, sig, secret))
        return jsonify(res)

    @app.get("/")
    def shop():
        return _shop_page(mode, port)

    @app.post("/create-order")
    def create_order():
        key_id, key_secret = _api_keys()
        if not (key_id and key_secret):
            return jsonify(error="Set RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET to create real orders.")
        try:
            import razorpay
            client = razorpay.Client(auth=(key_id, key_secret))
            order = client.order.create({
                "amount": 50000, "currency": C.INR, "receipt": f"rcpt_{int(time.time())}",
                "payment_capture": 1,
            })
        except Exception as e:
            return jsonify(error=f"Razorpay order.create failed: {e}")
        store.register(order["id"], 50000, C.INR)       # so the hardened handler knows it
        return jsonify(order_id=order["id"], key_id=key_id, amount=50000, currency=C.INR)

    @app.post("/verify-payment")
    def verify_payment():
        key_id, key_secret = _api_keys()
        data = request.get_json(force=True, silent=True) or {}
        try:
            import razorpay
            client = razorpay.Client(auth=(key_id, key_secret))
            client.utility.verify_payment_signature({
                "razorpay_order_id": data.get("razorpay_order_id", ""),
                "razorpay_payment_id": data.get("razorpay_payment_id", ""),
                "razorpay_signature": data.get("razorpay_signature", ""),
            })
            return jsonify(ok=True)
        except Exception:
            return jsonify(ok=False)

    return app


def serve(port: int = 5000, hardened: bool = False, secret: str | None = None,
          open_browser: bool = False) -> None:
    secret = secret or webhook_secret()
    app = build_app(hardened=hardened, secret=secret, port=port)
    mode = "hardened (safe)" if hardened else "naive (vulnerable)"
    keyed = "with live checkout" if all(_api_keys()) else "scan-only (no API keys set)"
    url = f"http://127.0.0.1:{port}"
    print(f"Acme Pay — REAL Razorpay merchant [{mode}, {keyed}] on {url}")
    print(f"  webhook secret: {'(from env)' if os.getenv('NIGHTSHIFT_SECRET') or os.getenv('RAZORPAY_WEBHOOK_SECRET') else '(demo default — set NIGHTSHIFT_SECRET to your real one)'}")
    print(f"  scan it:  nightshift scan --url {url}")
    if open_browser:
        threading.Timer(0.7, lambda: webbrowser.open(url)).start()
    # threaded=True so the concurrency-race attack is real (not serialized).
    app.run(host="127.0.0.1", port=port, threaded=True)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="nightshift-merchant",
                                description="A real Razorpay-integrated merchant to scan.")
    p.add_argument("--port", type=int, default=5000)
    p.add_argument("--hardened", action="store_true", help="run the safe integration")
    p.add_argument("--open", action="store_true", help="open the storefront in a browser")
    a = p.parse_args(argv)
    serve(a.port, hardened=a.hardened, open_browser=a.open)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
