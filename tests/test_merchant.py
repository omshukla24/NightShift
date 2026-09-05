"""The REAL Razorpay-integrated target: same verdicts as the reference server,
but signatures verified by the actual Razorpay SDK and served by Flask.

These tests skip cleanly if flask/razorpay aren't installed (they live behind the
``merchant`` extra), so the stdlib-only core still tests green anywhere.
"""
import json
import threading
import time
import urllib.request

import pytest

pytest.importorskip("flask")
pytest.importorskip("razorpay")

from nightshift import constants as C
from nightshift.merchant import build_app, verify_signature, Store, handle_hardened, handle_naive
from nightshift.model import sign
from nightshift.scanner import scan

SECRET = "whsec_nightshift_demo"


# --------------------------------------------------------------------------- #
# signature verification goes through the real SDK
# --------------------------------------------------------------------------- #
def test_verify_signature_matches_razorpay_scheme():
    body = json.dumps({"event": "payment.captured", "x": 1}).encode()
    assert verify_signature(body, sign(SECRET, body), SECRET) is True
    assert verify_signature(body, "deadbeef", SECRET) is False
    assert verify_signature(body, "", SECRET) is False


# --------------------------------------------------------------------------- #
# handler-level behaviour (no server needed)
# --------------------------------------------------------------------------- #
def _capture(order_id, amount, eid, secret=SECRET, created_at=None):
    evt = {"id": eid, "event": "payment.captured",
           "created_at": created_at if created_at is not None else int(time.time()),
           "payload": {"payment": {"entity": {"id": "pay_" + eid, "order_id": order_id,
                                              "amount": amount, "currency": "INR"}}}}
    b = json.dumps(evt).encode()
    return b, sign(secret, b)


def test_hardened_accepts_legit_capture_for_known_order():
    st = Store(); st.register("order_ok", 50000)
    b, s = _capture("order_ok", 50000, "evt_ok")
    assert handle_hardened(st, b, s, SECRET)["status"] == "processed"
    assert st.fulfillments == ["order_ok"]


@pytest.mark.parametrize("mutate", [
    ("forged", lambda b: (b, sign("attacker", b))),                 # wrong-secret signature
    ("unsigned", lambda b: (b, "")),                                # no signature
])
def test_hardened_rejects_bad_signatures(mutate):
    _, make = mutate
    st = Store(); st.register("order_x", 50000)
    b, _ = _capture("order_x", 50000, "evt_x")
    body, badsig = make(b)
    assert "rejected" in handle_hardened(st, body, badsig, SECRET)["status"]
    assert st.fulfillments == []


def test_hardened_rejects_unknown_order_stale_and_naive_accepts_unsigned():
    st = Store()
    b, s = _capture("order_never_made", 50000, "evt_idor")
    assert handle_hardened(st, b, s, SECRET)["status"] == "rejected: unknown order"
    st2 = Store(); st2.register("order_s", 50000)
    b2, s2 = _capture("order_s", 50000, "evt_stale", created_at=1)   # 1970
    assert handle_hardened(st2, b2, s2, SECRET)["status"] == "rejected: stale event"
    # naive fulfils an unsigned webhook (the vulnerability we demonstrate)
    st3 = Store(); st3.register("order_n", 50000)
    b3, _ = _capture("order_n", 50000, "evt_n")
    assert handle_naive(st3, b3, "", SECRET)["status"] == "processed"
    assert st3.fulfillments == ["order_n"]


# --------------------------------------------------------------------------- #
# Flask app contract (test client — no network)
# --------------------------------------------------------------------------- #
def test_flask_contract_endpoints():
    app = build_app(hardened=True, secret=SECRET, port=5000)
    c = app.test_client()
    assert c.get("/health").get_json()["mode"] == "hardened"
    assert c.post("/register", json={"order_id": "o1", "amount": 50000}).get_json()["ok"]
    b, s = _capture("o1", 50000, "evt1")
    c.post("/webhook", data=b, headers={"X-Razorpay-Signature": s, "Content-Type": "application/json"})
    snap = c.get("/state").get_json()
    assert snap["fulfillments"] == ["o1"] and snap["net_paise"] == 50000
    assert b"Acme Pay" in c.get("/").data          # storefront renders


# --------------------------------------------------------------------------- #
# full live scan against the REAL app (mirrors the reference-server test)
# --------------------------------------------------------------------------- #
def _serve(hardened):
    from werkzeug.serving import make_server
    app = build_app(hardened=hardened, secret=SECRET, port=0)
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{srv.server_port}"
    for _ in range(80):
        try:
            urllib.request.urlopen(url + "/health", timeout=1); break
        except Exception:
            time.sleep(0.05)
    return srv, url


def test_live_scan_naive_real_app_is_wrecked():
    srv, url = _serve(hardened=False)
    try:
        rep = scan(url, SECRET)
        assert rep.grade == "F"
        assert {"unsigned", "forged", "idor", "over_refund", "race"} <= {f.attack for f in rep.hits}
    finally:
        srv.shutdown()


def test_live_scan_hardened_real_app_survives():
    srv, url = _serve(hardened=True)
    try:
        rep = scan(url, SECRET)
        assert rep.grade == "A+" and rep.hits == []
    finally:
        srv.shutdown()
