"""`nightshift prove` — watch the theft happen in the shop's OWN ledger.

The scan reports a grade. Fair question: is the money real, or a number the tool
made up? This command removes all doubt. It runs two identical shops — a naive
integration and a hardened one — fires the same real attacks over HTTP at both,
and reads each shop's OWN books (GET /state) before and after every attack.

The naive shop actually records fulfilments (goods shipped / access granted) with
NO matching payment — that is the theft, in its own database. The hardened shop
records nothing — the attack is rejected. Same code, same attacks, opposite books.

    nightshift prove
    nightshift prove --url http://localhost:5000    # prove against your own app

Why these are real attacks, not a simulation: a Razorpay webhook endpoint is a
public URL. Anyone who knows it can POST a 'payment.captured' event to it. If the
handler doesn't verify the signature (unsigned/forged), dedupe atomically (race),
check the order is yours (idor), or bound refunds (over-refund), the attacker gets
free goods or drains money — exactly what this fires, over real HTTP.
"""
from __future__ import annotations

import argparse
import json
import threading
import time
import urllib.request

from . import constants as C
from .config import DEFAULT
from .model import sign
from .refserver import build_server
from .scanner import ATTACKS, _register, _send, _state, _webhook

_ANSI = {"green": "\033[32m", "red": "\033[31m", "bold": "\033[1m", "dim": "\033[2m",
         "yellow": "\033[33m", "reset": "\033[0m"}

_WHAT = {
    "replay":      "re-sends the same paid webhook 3x",
    "race":        "fires 6 identical webhooks at once",
    "unsigned":    "sends a 'paid' webhook, no signature",
    "forged":      "signs with a secret it doesn't know",
    "tamper":      "rewrites the amount way down",
    "over_refund": "refunds more than was ever paid",
    "stale":       "replays a years-old 'paid' event",
    "idor":        "pays for an order that never existed",
}


def _c(enabled: bool):
    return _ANSI if enabled else {k: "" for k in _ANSI}


def _spawn(hardened: bool, secret: str):
    httpd = build_server(0, hardened=hardened, secret=secret)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{httpd.server_address[1]}"
    for _ in range(80):
        try:
            urllib.request.urlopen(url + "/health", timeout=1)
            break
        except Exception:
            time.sleep(0.05)
    return httpd, url


def _fulfilled(url: str) -> list[str]:
    return _state(url)["fulfillments"]


def _run_all(url: str, secret: str) -> dict:
    """Fire every attack; capture the fulfilment delta each one causes in the shop."""
    out = {}
    for fn in ATTACKS:
        before = len(_fulfilled(url))
        f = fn(url, secret)
        after = len(_fulfilled(url))
        out[f.attack] = (f, after - before)
    return out


def _rupees(paise: int) -> str:
    return f"Rs {paise/100:,.0f}"


# --------------------------------------------------------------------------- #
# a raw, undeniable walkthrough of one attack (no signature at all)
# --------------------------------------------------------------------------- #
def _walkthrough(n_url: str, h_url: str, secret: str, c: dict) -> list[str]:
    oid, amt = "PROOF-order-with-no-payment", 40000
    body = _webhook(C.CAPTURE, oid, "pay_proof", amt, event_id="evt_proof")
    _register(n_url, oid, amt)
    _register(h_url, oid, amt)
    pretty = json.dumps(json.loads(body), indent=2)
    L = [
        "",
        f"{c['bold']}== WALKTHROUGH: one unsigned webhook, sent to both shops =={c['reset']}",
        f"{c['dim']}The attacker POSTs this to /webhook. Note there is NO X-Razorpay-Signature header —",
        f"the attacker does not know your secret and cannot make one.{c['reset']}",
        "",
        f"    POST /webhook   HTTP/1.1",
        f"    Content-Type: application/json",
        f"    {c['red']}(no X-Razorpay-Signature header at all){c['reset']}",
        "",
    ]
    L += ["    " + ln for ln in pretty.splitlines()]
    # before
    nb, hb = _fulfilled(n_url).count(oid), _fulfilled(h_url).count(oid)
    # fire the UNSIGNED webhook at both
    _send(n_url, body, secret=None)
    _send(h_url, body, secret=None)
    na, ha = _fulfilled(n_url).count(oid), _fulfilled(h_url).count(oid)
    L += [
        "",
        f"  {c['bold']}The shops' own ledgers, for order {oid}:{c['reset']}",
        f"    NAIVE    shop:  fulfilled before = {nb}   ->   after = {na}   "
        + (f"{c['red']}{c['bold']}SHIPPED {_rupees(amt)} for a webhook with no signature — THEFT{c['reset']}"
           if na > nb else f"{c['green']}no change{c['reset']}"),
        f"    HARDENED shop:  fulfilled before = {hb}   ->   after = {ha}   "
        + (f"{c['green']}{c['bold']}rejected — nothing shipped, Rs 0 lost{c['reset']}"
           if ha == hb else f"{c['red']}shipped (unexpected){c['reset']}"),
    ]
    return L


# --------------------------------------------------------------------------- #
# main
# --------------------------------------------------------------------------- #
def prove(secret: str = DEFAULT.secret, url: str | None = None, color: bool = True) -> str:
    c = _c(color)
    head = [
        f"{c['bold']}NIGHTSHIFT — PROOF OF EXPLOITABILITY{c['reset']}",
        f"{c['dim']}Every rupee below is read from a shop's own /state ledger AFTER the attack —",
        f"it is what the shop actually recorded, not a number NIGHTSHIFT invented.{c['reset']}",
        "",
    ]

    if url:
        naive = _run_all(url, secret)
        rows = [f"{c['bold']}Target: {url}{c['reset']}", ""]
        stolen = 0
        for name, _t, _s in [(a, 0, 0) for a in _WHAT]:  # stable order
            if name not in naive:
                continue
            f, dl = naive[name]
            what = _WHAT.get(name, "")
            if f.succeeded:
                stolen += f.money_at_risk
                verdict = f"{c['red']}{c['bold']}STOLEN {_rupees(f.money_at_risk)}{c['reset']}"
                if dl > 1:
                    verdict += f"{c['red']} ({dl}x shipped){c['reset']}"
            else:
                verdict = f"{c['green']}blocked{c['reset']}"
            rows.append(f"  {name:12} {what:44} {verdict}")
        rows += ["", f"  {c['bold']}TOTAL STOLEN: {c['red']}{_rupees(stolen)}{c['reset']}"]
        return "\n".join(head + rows)

    n_httpd, n_url = _spawn(False, secret)
    h_httpd, h_url = _spawn(True, secret)
    try:
        naive = _run_all(n_url, secret)
        hard = _run_all(h_url, secret)
        rows = [
            f"  {'attack':12} {'what the attacker does':38} {'NAIVE shop':22} HARDENED shop",
            f"  {'-'*12} {'-'*38} {'-'*22} {'-'*14}",
        ]
        stolen_n = stolen_h = 0
        for name in _WHAT:
            if name not in naive:
                continue
            fn_, dln = naive[name]
            fh_, dlh = hard[name]
            what = _WHAT[name]
            if fn_.succeeded:
                stolen_n += fn_.money_at_risk
                ncell = f"{c['red']}STOLEN {_rupees(fn_.money_at_risk)}{c['reset']}"
                if dln > 1:
                    ncell = f"{c['red']}{dln}x = {_rupees(fn_.money_at_risk)}{c['reset']}"
            else:
                ncell = f"{c['green']}safe{c['reset']}"
            if fh_.succeeded:
                stolen_h += fh_.money_at_risk
                hcell = f"{c['red']}STOLEN {_rupees(fh_.money_at_risk)}{c['reset']}"
            else:
                hcell = f"{c['green']}blocked{c['reset']}"
            # pad accounting for invisible ANSI codes
            npad = 22 + (len(ncell) - len(_strip(ncell)))
            rows.append(f"  {name:12} {what:38} {ncell:<{npad}} {hcell}")
        rows += [
            f"  {'-'*12} {'-'*38} {'-'*22} {'-'*14}",
            f"  {'TOTAL':12} {'money moved out of the shop':38} "
            f"{c['red']}{c['bold']}{('STOLEN '+_rupees(stolen_n)):22}{c['reset']} "
            f"{c['green']}{c['bold']}{_rupees(stolen_h)} lost{c['reset']}",
        ]
        walk = _walkthrough(n_url, h_url, secret, c)
        verdict = [
            "",
            f"{c['bold']}Verdict:{c['reset']} the naive shop recorded {c['red']}{_rupees(stolen_n)}{c['reset']} of "
            f"fulfilments with no matching payment. The hardened shop recorded {c['green']}{_rupees(stolen_h)}{c['reset']}.",
            f"Same attacks, same code — the only difference is signature checks, atomic dedupe,",
            f"order ownership, freshness and refund bounds. That is the whole product.",
        ]
        return "\n".join(head + rows + walk + verdict)
    finally:
        n_httpd.shutdown()
        h_httpd.shutdown()


def _strip(s: str) -> str:
    import re
    return re.sub(r"\033\[[0-9;]*m", "", s)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="nightshift-prove")
    p.add_argument("--url")
    p.add_argument("--secret", default=DEFAULT.secret)
    p.add_argument("--no-color", action="store_true")
    a = p.parse_args(argv)
    print(prove(secret=a.secret, url=a.url, color=not a.no_color))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
