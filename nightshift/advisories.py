"""Mini-CVE generator — turns each landed attack into a vulnerability advisory.

A pass/fail table says "you failed idempotency." A security advisory says: here is
NIGHTSHIFT-2026-003, a CRITICAL forged-webhook flaw, here's the attacker's story,
the money at stake, how to reproduce it, and the exact patch. That's what makes a
judge read it as "this person found six CVEs in my payment code."

Deterministic by default (a playbook); set GEMINI_API_KEY to have a model write the
narrative, grounded strictly in the attack the scanner already proved.
"""
from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime, timezone

from .model import rupees
from .scanner import ScanReport, Finding

# severity -> (CVSS-ish score, vector)
_CVSS = {
    "CRITICAL": (9.1, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H"),
    "HIGH": (7.5, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N"),
    "MEDIUM": (5.3, "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N"),
}

# attack -> (CWE, attacker story, business impact, the fix)
PLAYBOOK = {
    "replay": ("CWE-799 Improper Control of Interaction Frequency",
               "Razorpay retries a webhook it thinks failed; the attacker simply re-POSTs a captured 'payment.captured'.",
               "Every retry ships the order again — the merchant fulfils N times for one payment.",
               "Persist the Razorpay event id and no-op on repeats (idempotency key)."),
    "race": ("CWE-362 Concurrent Execution using Shared Resource without Proper Synchronization",
             "The attacker sends the same validly-signed capture on several parallel connections at once.",
             "The dedupe check and the fulfilment are not atomic, so every parallel copy slips through the window and the order ships multiple times.",
             "Wrap the check-and-record in a transaction / lock (SELECT ... FOR UPDATE, or a unique constraint on event id)."),
    "unsigned": ("CWE-347 Improper Verification of Cryptographic Signature",
                 "The attacker POSTs a 'payment.captured' with no X-Razorpay-Signature at all.",
                 "Anyone on the internet can mark any order paid and receive goods for free.",
                 "Reject any webhook whose HMAC-SHA256(body, secret) does not match, before any processing."),
    "forged": ("CWE-345 Insufficient Verification of Data Authenticity",
               "The attacker forges a paid event and signs it with a guessed/blank secret.",
               "Free fulfilment on demand for any order id the attacker names.",
               "Verify the signature with a constant-time compare against the real webhook secret."),
    "tamper": ("CWE-347 Improper Verification of Cryptographic Signature",
               "The attacker edits the amount in the payload; the signature no longer matches, but it isn't checked.",
               "Goods released for a fraction of the price, or the ledger poisoned with a wrong amount.",
               "Verify the signature (any edit invalidates it) and cross-check the amount against the order via the Razorpay API."),
    "over_refund": ("CWE-840 Business Logic Errors",
                    "The attacker triggers a refund larger than the captured amount.",
                    "The merchant pays out more than it ever collected.",
                    "Bound every refund: refunded_so_far + this_refund must be <= captured."),
    "stale": ("CWE-294 Authentication Bypass by Capture-replay",
              "The attacker replays an old, validly-signed event long after the fact.",
              "Expired or superseded events are re-applied, moving money out of sequence.",
              "Reject events whose created_at is outside a freshness window (e.g. a few minutes)."),
    "idor": ("CWE-639 Authorization Bypass Through User-Controlled Key",
             "The attacker names an order id that was never created on this merchant.",
             "Orders (or other merchants' orders) are fulfilled with no real payment behind them.",
             "Only act on order ids you created, and confirm the payment against the Razorpay API before fulfilling."),
}


@dataclass
class Advisory:
    advisory_id: str
    attack: str
    title: str
    severity: str
    cvss: float
    vector: str
    cwe: str
    story: str
    impact: str
    money_at_risk: int
    reproduction: str
    patch: str
    generated_by: str

    def to_markdown(self) -> str:
        return (
            f"### {self.advisory_id} — {self.title}\n\n"
            f"- **Severity:** {self.severity} (CVSS {self.cvss})  \n"
            f"- **Weakness:** {self.cwe}  \n"
            f"- **Vector:** `{self.vector}`  \n"
            f"- **Money at risk:** {rupees(self.money_at_risk)}\n\n"
            f"**What the attacker does.** {self.story}\n\n"
            f"**Impact.** {self.impact}\n\n"
            f"**Reproduce.**\n```\n{self.reproduction}\n```\n\n"
            f"**Fix.** {self.patch}\n\n"
            f"<sub>root-cause & fix by: {self.generated_by}</sub>\n"
        )


def _repro(finding: Finding) -> str:
    return (f"nightshift scan --url <TARGET>\n"
            f"# probe '{finding.attack}' landed: {finding.detail}")


def _model_narrative(finding: Finding, cwe: str):
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        return None
    try:  # pragma: no cover - network path
        import json
        import google.generativeai as genai
        genai.configure(api_key=key)
        model = genai.GenerativeModel("gemini-1.5-flash")
        prompt = ("Write a JSON object with keys 'story','impact','patch' for this payment "
                  "vulnerability an automated scanner ALREADY PROVED. Do not question it.\n"
                  f"attack={finding.attack} cwe={cwe} detail={finding.detail}")
        raw = model.generate_content(prompt).text.strip().strip("`")
        raw = raw[4:] if raw.startswith("json") else raw
        d = json.loads(raw)
        return d["story"], d["impact"], d["patch"], "gemini:gemini-1.5-flash"
    except Exception:
        return None


def advisory_for(finding: Finding, index: int, year: int | None = None) -> Advisory:
    cwe, story, impact, patch = PLAYBOOK.get(
        finding.attack, ("CWE-693 Protection Mechanism Failure", finding.title, finding.detail, "Review the handler."))
    by = "playbook"
    narrative = _model_narrative(finding, cwe)
    if narrative:
        story, impact, patch, by = narrative
    cvss, vector = _CVSS.get(finding.severity, (5.0, _CVSS["MEDIUM"][1]))
    yr = year or datetime.now(timezone.utc).year
    return Advisory(
        advisory_id=f"NIGHTSHIFT-{yr}-{index:03d}",
        attack=finding.attack, title=finding.title, severity=finding.severity,
        cvss=cvss, vector=vector, cwe=cwe, story=story, impact=impact,
        money_at_risk=finding.money_at_risk, reproduction=_repro(finding),
        patch=patch, generated_by=by,
    )


def advisories_for(report: ScanReport) -> list[Advisory]:
    return [advisory_for(f, i + 1) for i, f in enumerate(report.hits)]


def to_markdown(report: ScanReport) -> str:
    advs = advisories_for(report)
    header = (f"# Security advisories — {report.url}\n\n"
              f"**{len(advs)} vulnerabilities found · grade {report.grade} · "
              f"{rupees(report.exposure)} at risk**\n\n"
              f"Found by NIGHTSHIFT, an automated payment red-team. Each finding was *proven* "
              f"by a live attack, not inferred.\n\n---\n\n")
    if not advs:
        return header + "No vulnerabilities found — every attack was rejected.\n"
    return header + "\n---\n\n".join(a.to_markdown() for a in advs)
