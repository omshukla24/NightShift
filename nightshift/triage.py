"""Triage — the ONLY place AI is used, and it is used on a short leash.

The oracle has already *proven* a violation and handed us the exact offending
events and rupees at risk. The AI's single job is to turn that proof into a
readable incident: root cause, blast radius, and a suggested fix. It is never
asked "is this a bug?" — a model must not be the thing that decides whether
money is safe.

Everything here runs with NO API key: a deterministic playbook produces the
report. Set GEMINI_API_KEY (or OPENAI_API_KEY) to have a model write the prose
instead — grounded strictly in the oracle's proven facts.
"""
from __future__ import annotations

import json
import os
import textwrap
from dataclasses import dataclass

from .config import DEFAULT as _CFG
from .model import rupees
from .oracles import OracleResult, Trace

# Deterministic root-cause + fix playbook, keyed by the invariant that fired.
# This is what makes the tool useful even with the network unplugged.
PLAYBOOK: dict[str, dict[str, str]] = {
    "idempotency": {
        "root_cause": "The webhook was processed more than once because the handler "
        "does not treat the Razorpay event id as an idempotency key. Razorpay retries "
        "deliveries it believes failed, so at-least-once delivery is guaranteed.",
        "fix": "Persist processed event ids and no-op on repeats:\n"
        "    if event_id in seen: return 200\n    seen.add(event_id)",
    },
    "conservation": {
        "root_cause": "The handler booked money that does not match any real payment — "
        "either a duplicated capture or an amount taken from an untrusted payload.",
        "fix": "Never trust the amount in the webhook body. Fetch the payment from the "
        "Razorpay API and record that amount, and dedupe captures by event id.",
    },
    "no_unpaid_fulfillment": {
        "root_cause": "An order was fulfilled without a full, real payment behind it — "
        "the handler did not compare the captured amount to the order amount.",
        "fix": "Gate fulfilment on: amount_captured == order.amount AND a Razorpay API "
        "fetch confirming the payment is captured. Otherwise, do not release goods.",
    },
    "reconciliation_completeness": {
        "root_cause": "A real payment was never recorded because its webhook was dropped, "
        "and there is no reconciliation job to notice the gap.",
        "fix": "Run a periodic reconcile: list settled payments via the Razorpay API and "
        "backfill any order that is paid on Razorpay but unrecorded locally.",
    },
    "signature_integrity": {
        "root_cause": "The handler acted on an event whose X-Razorpay-Signature is invalid "
        "or missing — a forged or tampered event was trusted.",
        "fix": "Verify HMAC-SHA256(body, webhook_secret) with a constant-time compare "
        "before any processing. Reject on mismatch; change no state.",
    },
    "terminal_state_monotonicity": {
        "root_cause": "Events arrived out of order and the state machine moved backwards "
        "(e.g. refunded before paid), because status is set blindly from each event.",
        "fix": "Enforce a legal lifecycle (created -> paid -> refunded). Reject or buffer "
        "an event that would move the order backwards, and reconcile the true order.",
    },
}


@dataclass
class Incident:
    scenario_key: str
    invariant: str
    severity: str
    money_at_risk_paise: int
    offending_events: list[str]
    proof: str          # deterministic, from the oracle
    root_cause: str     # from the playbook or the model
    fix: str
    generated_by: str   # "playbook" or "gemini:<model>" etc.

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["money_at_risk"] = rupees(self.money_at_risk_paise)
        return d

    def render(self) -> str:
        return textwrap.dedent(
            f"""\
            INCIDENT · {self.scenario_key} · {self.invariant}  [{self.severity}]
            Money at risk : {rupees(self.money_at_risk_paise)}
            Offending events: {', '.join(self.offending_events) or '(state-level)'}
            Proof          : {self.proof}
            Root cause     : {self.root_cause}
            Suggested fix  :
            {textwrap.indent(self.fix, '    ')}
            (root cause & fix by: {self.generated_by})
            """
        )


def _severity(paise: int) -> str:
    if paise >= _CFG.sev1_paise:
        return "SEV1"
    if paise >= _CFG.sev2_paise:
        return "SEV2"
    return "SEV3"


def _proof(result: OracleResult, trace: Trace) -> str:
    seq = " -> ".join(
        f"{d.etype}({d.order_id},{d.amount},sig={'ok' if d.signature_valid(trace.secret) else 'BAD'}"
        f"{',dropped' if not d.delivered else ''})"
        for d in trace.deliveries
    )
    return f"invariant '{result.name}' failed: {result.detail}. Event sequence: {seq or '(none)'}"


def _model_narrative(result: OracleResult, proof: str) -> tuple[str, str, str] | None:
    """Optional: ask a model to write root_cause + fix, grounded in the proof.

    Returns None if no key is configured or the call fails — the caller then
    falls back to the deterministic playbook. The model is given ONLY the proven
    facts and is told it may not overturn the verdict.
    """
    key = os.getenv("GEMINI_API_KEY")
    if not key:
        return None
    try:  # pragma: no cover - network path, exercised only when a key is set
        import google.generativeai as genai

        genai.configure(api_key=key)
        model = genai.GenerativeModel("gemini-1.5-flash")
        prompt = (
            "You are a payments reliability engineer writing an incident note.\n"
            "A deterministic checker has ALREADY PROVEN this violation; do not question it.\n"
            "Write two short sections, 'root_cause' and 'fix', as strict JSON with those keys.\n\n"
            f"Invariant: {result.name}\nProof: {proof}\n"
            f"Money at risk (paise): {result.money_at_risk}\n"
        )
        raw = model.generate_content(prompt).text.strip().strip("`")
        if raw.startswith("json"):
            raw = raw[4:]
        data = json.loads(raw)
        return data["root_cause"], data["fix"], "gemini:gemini-1.5-flash"
    except Exception:
        return None


def triage(result: OracleResult, trace: Trace, scenario_key: str) -> Incident:
    proof = _proof(result, trace)
    narrative = _model_narrative(result, proof)
    if narrative is not None:
        root_cause, fix, by = narrative
    else:
        pb = PLAYBOOK.get(result.name, {"root_cause": result.detail, "fix": "Review handler."})
        root_cause, fix, by = pb["root_cause"], pb["fix"], "playbook"
    return Incident(
        scenario_key=scenario_key,
        invariant=result.name,
        severity=_severity(result.money_at_risk),
        money_at_risk_paise=result.money_at_risk,
        offending_events=result.offending_events,
        proof=proof,
        root_cause=root_cause,
        fix=fix,
        generated_by=by,
    )
