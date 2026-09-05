"""NIGHTSHIFT — the 2 AM machine.

A deterministic fault-injection + invariant-checking harness for Razorpay
payment integrations. It replays and perturbs the webhook/event layer against
a merchant's own handler, and a set of deterministic ORACLES prove money-safety
invariants. When an invariant is violated, an AI copilot only *explains* the
violation the oracle already proved — it never decides whether money is safe.

Rename freely; NIGHTSHIFT is a placeholder that echoes Razorpay's own footer,
"Built during the night shift."
"""

__all__ = ["__version__"]
__version__ = "0.5.0"
