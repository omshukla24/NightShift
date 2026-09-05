"""Live red-team scanner — attacks a *running* payment endpoint over HTTP.

This is the "run it before you go live" product: point it at a URL and it fires a
battery of real malicious webhooks — replay, a concurrency race, unsigned, forged,
tampered, over-refund, stale-timestamp, and IDOR — then reads the app's state back
and reports which attacks actually moved money. Stdlib only (urllib), so it runs
anywhere and can be aimed at Razorpay's own sample app (see the run guide).
"""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field

from . import constants as C
from .config import DEFAULT
from .model import sign

CRITICAL, HIGH, MEDIUM = "CRITICAL", "HIGH", "MEDIUM"


# --------------------------------------------------------------------------- #
# tiny HTTP helpers
# --------------------------------------------------------------------------- #
def _post(url: str, path: str, body: bytes, headers: dict | None = None, timeout: float = 5.0):
    req = urllib.request.Request(url.rstrip("/") + path, data=body, method="POST",
                                 headers=headers or {})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read() or b"{}")


def _state(url: str, timeout: float = 5.0) -> dict:
    with urllib.request.urlopen(url.rstrip("/") + "/state", timeout=timeout) as r:
        return json.loads(r.read())


def _register(url: str, order_id: str, amount: int, currency: str = C.INR):
    _post(url, "/register", json.dumps({"order_id": order_id, "amount": amount,
                                        "currency": currency}).encode())


def _webhook(kind: str, order_id: str, payment_id: str, amount: int,
             currency: str = C.INR, event_id: str = "evt", created_at: int | None = None) -> bytes:
    etype = C.PAYMENT_CAPTURED if kind == C.CAPTURE else C.REFUND_PROCESSED
    key = "payment" if kind == C.CAPTURE else "refund"
    return json.dumps({
        "id": event_id, "event": etype,
        "created_at": created_at if created_at is not None else int(time.time()),
        "payload": {key: {"entity": {"id": payment_id, "order_id": order_id,
                                     "amount": amount, "currency": currency}}},
    }).encode()


def _send(url: str, body: bytes, secret: str | None):
    headers = {"Content-Type": "application/json"}
    if secret is not None:
        headers["X-Razorpay-Signature"] = sign(secret, body)
    return _post(url, "/webhook", body, headers)


def _fulfilled(url: str, order_id: str) -> int:
    return _state(url)["fulfillments"].count(order_id)


# --------------------------------------------------------------------------- #
# findings
# --------------------------------------------------------------------------- #
@dataclass
class Finding:
    attack: str
    title: str
    severity: str
    succeeded: bool          # True => the attack moved money it should not have
    detail: str
    money_at_risk: int = 0


@dataclass
class ScanReport:
    url: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def hits(self) -> list[Finding]:
        return [f for f in self.findings if f.succeeded]

    @property
    def exposure(self) -> int:
        return sum(f.money_at_risk for f in self.hits)

    @property
    def grade(self) -> str:
        n = len(self.hits)
        return "A+" if n == 0 else "B" if n == 1 else "C" if n <= 2 else "D" if n <= 4 else "F"

    def render(self) -> str:
        lines = [f"LIVE SCAN · {self.url}",
                 f"  grade: {self.grade}   attacks landed: {len(self.hits)}/{len(self.findings)}"
                 f"   exposure: Rs {self.exposure/100:,.2f}", ""]
        for f in self.findings:
            mark = "HIT " if f.succeeded else "safe"
            tag = f"[{f.severity}]" if f.succeeded else ""
            lines.append(f"  [{mark}] {f.attack:16} {tag:10} {f.detail}")
        return "\n".join(lines)


# --------------------------------------------------------------------------- #
# the attacks — each returns a Finding
# --------------------------------------------------------------------------- #
def _atk_replay(url, secret):
    oid, amt = "scan_replay", 50000
    _register(url, oid, amt)
    body = _webhook(C.CAPTURE, oid, "pay_r", amt, event_id="evt_replay")
    _send(url, body, secret); _send(url, body, secret); _send(url, body, secret)
    n = _fulfilled(url, oid)
    return Finding("replay", "Webhook replay double-spend", HIGH, n > 1,
                   f"order fulfilled {n}x on a replayed webhook", amt * max(0, n - 1))


def _atk_race(url, secret, workers=6):
    oid, amt = "scan_race", 70000
    _register(url, oid, amt)
    body = _webhook(C.CAPTURE, oid, "pay_race", amt, event_id="evt_race")
    barrier = threading.Barrier(workers)

    def fire():
        barrier.wait()               # release all threads at once, into the race window
        try:
            _send(url, body, secret)
        except Exception:
            pass

    threads = [threading.Thread(target=fire) for _ in range(workers)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    n = _fulfilled(url, oid)
    return Finding("race", "Concurrency race double-spend", CRITICAL, n > 1,
                   f"{workers} parallel webhooks -> order fulfilled {n}x (non-atomic dedupe)",
                   amt * max(0, n - 1))


def _atk_unsigned(url, secret):
    oid, amt = "scan_unsigned", 40000
    _register(url, oid, amt)
    body = _webhook(C.CAPTURE, oid, "pay_u", amt, event_id="evt_unsigned")
    _send(url, body, secret=None)    # no signature at all
    ok = _fulfilled(url, oid) > 0
    return Finding("unsigned", "Signature not verified", CRITICAL, ok,
                   "an unsigned webhook was accepted and fulfilled" if ok
                   else "unsigned webhook rejected", amt if ok else 0)


def _atk_forged(url, secret):
    oid, amt = "scan_forged", 60000
    _register(url, oid, amt)
    body = _webhook(C.CAPTURE, oid, "pay_f", amt, event_id="evt_forged")
    _send(url, body, secret="attacker-does-not-know-the-secret")
    ok = _fulfilled(url, oid) > 0
    return Finding("forged", "Forged (bad-signature) event accepted", CRITICAL, ok,
                   "a forged webhook shipped an order" if ok else "forged webhook rejected",
                   amt if ok else 0)


def _atk_tamper(url, secret):
    oid, real = "scan_tamper", 200000
    _register(url, oid, real)
    # attacker rewrites the amount; can't re-sign, so it's signed with a wrong secret
    body = _webhook(C.CAPTURE, oid, "pay_t", 2000, event_id="evt_tamper")
    _send(url, body, secret="wrong-secret")
    st = _state(url)
    booked = sum(e["amount"] for e in st["ledger"] if e["order_id"] == oid)
    ok = booked not in (0, real)
    return Finding("tamper", "Tampered amount booked", HIGH, ok,
                   f"booked Rs {booked/100:.0f} for a Rs {real/100:.0f} order" if ok
                   else "tampered amount rejected", real if ok else 0)


def _atk_over_refund(url, secret):
    oid, cap = "scan_over", 50000
    _register(url, oid, cap)
    _send(url, _webhook(C.CAPTURE, oid, "pay_o", cap, event_id="evt_ocap"), secret)
    _send(url, _webhook(C.REFUND, oid, "rfnd_o", 80000, event_id="evt_oref"), secret)
    st = _state(url)
    refunded = sum(e["amount"] for e in st["ledger"] if e["order_id"] == oid and e["kind"] == C.REFUND)
    ok = refunded > cap
    return Finding("over_refund", "Refund exceeds capture", HIGH, ok,
                   f"refunded Rs {refunded/100:.0f} against a Rs {cap/100:.0f} capture" if ok
                   else "over-refund rejected", refunded - cap if ok else 0)


def _atk_stale(url, secret):
    oid, amt = "scan_stale", 45000
    _register(url, oid, amt)
    body = _webhook(C.CAPTURE, oid, "pay_s", amt, event_id="evt_stale", created_at=1)  # 1970
    _send(url, body, secret)
    ok = _fulfilled(url, oid) > 0
    return Finding("stale", "Stale/replayed-timestamp event accepted", MEDIUM, ok,
                   "a decades-old event was accepted (no freshness window)" if ok
                   else "stale event rejected", amt if ok else 0)


def _atk_idor(url, secret):
    # a capture for an order the attacker never created ("another merchant's" order)
    oid, amt = "victim_order_9999", 999900
    body = _webhook(C.CAPTURE, oid, "pay_idor", amt, event_id="evt_idor")
    _send(url, body, secret)
    ok = _fulfilled(url, oid) > 0
    return Finding("idor", "Unknown-order (IDOR/forgery) accepted", CRITICAL, ok,
                   "fulfilled an order that was never created" if ok
                   else "unknown order rejected", amt if ok else 0)


ATTACKS = [_atk_replay, _atk_race, _atk_unsigned, _atk_forged, _atk_tamper,
           _atk_over_refund, _atk_stale, _atk_idor]


def scan(url: str, secret: str = DEFAULT.secret) -> ScanReport:
    try:
        urllib.request.urlopen(url.rstrip("/") + "/health", timeout=5.0)
    except urllib.error.URLError as e:
        raise ConnectionError(f"cannot reach target at {url}: {e}") from e
    report = ScanReport(url=url)
    for attack in ATTACKS:
        try:
            report.findings.append(attack(url, secret))
        except Exception as e:  # a probe failing is itself worth surfacing
            report.findings.append(Finding(attack.__name__, "probe error", MEDIUM, False, str(e)))
    return report
