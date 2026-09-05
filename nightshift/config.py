"""Runtime configuration — no magic numbers buried in logic.

Thresholds, the demo secret, and the optional replay window live here so they can
be tuned in one place (and overridden per-run) instead of being hard-coded.
"""
from __future__ import annotations

import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    # Webhook secret used to sign/verify in the harness (Razorpay's HMAC scheme).
    secret: str = "whsec_nightshift_demo"

    # Incident severity bands, in paise.
    sev1_paise: int = 100_000   # >= Rs 1,000 at risk
    sev2_paise: int = 10_000    # >= Rs 100 at risk

    # Optional anti-replay: reject events older than this many seconds (0 = off).
    replay_window_seconds: int = 0

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            secret=os.getenv("NIGHTSHIFT_SECRET", cls.secret),
            replay_window_seconds=int(os.getenv("NIGHTSHIFT_REPLAY_WINDOW", "0")),
        )


DEFAULT = Config()
