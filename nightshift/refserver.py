"""A runnable, Razorpay-style webhook receiver — the target NIGHTSHIFT attacks.

Two modes, one process:
  * naive    — the integration everyone writes first. It even *has* a dedupe check,
               but the check isn't atomic, so it double-spends under concurrency.
  * hardened — the same app, locked and verified. It survives every attack.

Run it:
    python -m nightshift.refserver --port 8000            # vulnerable
    python -m nightshift.refserver --port 8001 --hardened # safe

Then attack it:
    python -m nightshift scan --url http://localhost:8000

It speaks the same HMAC-SHA256 signature scheme as Razorpay, so the exact same
attacks run against Razorpay's own reference sample app once you add a `/state`
shim (see the run guide).
"""
from __future__ import annotations

import argparse
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import constants as C
from .config import DEFAULT
from .model import signature_is_valid

RACE_WINDOW_SECONDS = 0.02  # the tell-tale gap between "check" and "act" in real code
FRESHNESS_WINDOW_SECONDS = 300


class Store:
    def __init__(self) -> None:
        self.orders: dict[str, dict] = {}
        self.ledger: list[dict] = []
        self.fulfillments: list[str] = []
        self.processed: set[str] = set()
        self.lock = threading.Lock()

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


def _handle_naive(store: Store, evt: dict, sig: str, secret: str) -> dict:
    # BUG: signature never checked. BUG: dedupe check is NOT atomic (race window).
    eid = evt.get("id", "")
    if eid in store.processed:
        return {"status": "duplicate ignored"}
    kind, ent = _entity(evt)
    oid = ent["order_id"]
    time.sleep(RACE_WINDOW_SECONDS)      # simulate a DB round-trip: the race window
    store.orders.setdefault(oid, {"amount": ent["amount"], "currency": ent.get("currency", C.INR)})
    store.processed.add(eid)
    store.ledger.append({"event_id": eid, "order_id": oid, "kind": kind,
                         "amount": int(ent["amount"]), "currency": ent.get("currency", C.INR)})
    if kind == C.CAPTURE:
        store.fulfillments.append(oid)
    return {"status": "processed"}


def _handle_hardened(store: Store, evt: dict, sig: str, secret: str, body: bytes) -> dict:
    if not signature_is_valid(secret, body, sig):
        return {"status": "rejected: bad signature"}
    if int(evt.get("created_at", 0)) < int(time.time()) - FRESHNESS_WINDOW_SECONDS:
        return {"status": "rejected: stale event"}
    with store.lock:                                   # atomic check-and-act
        eid = evt.get("id", "")
        if eid in store.processed:
            return {"status": "duplicate ignored"}
        kind, ent = _entity(evt)
        oid = ent["order_id"]
        order = store.orders.get(oid)
        if order is None:
            return {"status": "rejected: unknown order"}
        amt = int(ent["amount"])
        if kind == C.CAPTURE and (amt != order["amount"] or ent.get("currency", C.INR) != order["currency"]):
            return {"status": "rejected: amount/currency mismatch"}
        if kind == C.REFUND:
            refunded = sum(e["amount"] for e in store.ledger if e["order_id"] == oid and e["kind"] == C.REFUND)
            captured = sum(e["amount"] for e in store.ledger if e["order_id"] == oid and e["kind"] == C.CAPTURE)
            if refunded + amt > captured:
                return {"status": "rejected: over-refund"}
        store.processed.add(eid)
        booked = order["amount"] if kind == C.CAPTURE else amt
        store.ledger.append({"event_id": eid, "order_id": oid, "kind": kind,
                             "amount": booked, "currency": order["currency"]})
        if kind == C.CAPTURE:
            store.fulfillments.append(oid)
        return {"status": "processed"}


def make_handler(store: Store, hardened: bool, secret: str):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_):  # keep the server quiet
            pass

        def _json(self, code: int, obj: dict) -> None:
            payload = json.dumps(obj).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _body(self) -> bytes:
            return self.rfile.read(int(self.headers.get("Content-Length", 0)))

        def do_GET(self):
            if self.path == "/health":
                return self._json(200, {"ok": True, "mode": "hardened" if hardened else "naive"})
            if self.path == "/state":
                return self._json(200, store.snapshot())
            self._json(404, {"error": "not found"})

        def do_POST(self):
            body = self._body()
            if self.path == "/register":
                o = json.loads(body)
                store.orders[o["order_id"]] = {"amount": int(o["amount"]),
                                               "currency": o.get("currency", C.INR)}
                return self._json(200, {"ok": True})
            if self.path == "/webhook":
                sig = self.headers.get("X-Razorpay-Signature", "")
                evt = json.loads(body)
                res = (_handle_hardened(store, evt, sig, secret, body) if hardened
                       else _handle_naive(store, evt, sig, secret))
                return self._json(200, res)
            self._json(404, {"error": "not found"})

    return Handler


def build_server(port: int = 8000, hardened: bool = False, secret: str = DEFAULT.secret):
    store = Store()
    httpd = ThreadingHTTPServer(("127.0.0.1", port), make_handler(store, hardened, secret))
    httpd.store = store  # type: ignore[attr-defined]
    return httpd


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="nightshift-refserver")
    p.add_argument("--port", type=int, default=8000)
    p.add_argument("--hardened", action="store_true")
    p.add_argument("--secret", default=DEFAULT.secret)
    a = p.parse_args(argv)
    httpd = build_server(a.port, a.hardened, a.secret)
    mode = "hardened" if a.hardened else "naive (vulnerable)"
    print(f"NIGHTSHIFT reference server [{mode}] on http://127.0.0.1:{a.port}  (Ctrl-C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        httpd.shutdown()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
