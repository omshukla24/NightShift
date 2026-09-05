"""Reliability score — a single grade for an integration's money-safety.

Runs every scenario against a target and turns the invariant results into a 0–100
score and an A–F grade, plus a per-invariant pass rate. It's the headline number
for "how much would you trust this integration", and it's how you show a before/after
when a team hardens their handler.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from .oracles import ORACLE_NAMES
from .runner import DEFAULT_SECRET, run_all


def _grade(score: float) -> str:
    for cutoff, letter in ((97, "A+"), (90, "A"), (80, "B"), (70, "C"), (60, "D")):
        if score >= cutoff:
            return letter
    return "F"


@dataclass
class ScoreCard:
    target: str
    score: float
    grade: str
    scenarios_clean: int
    scenarios_total: int
    checks_passed: int
    checks_total: int
    exposure_paise: int
    per_oracle_pass_rate: dict[str, float] = field(default_factory=dict)

    def render(self) -> str:
        lines = [
            f"RELIABILITY SCORE · {self.target}",
            f"  score : {self.score:.1f}/100   grade: {self.grade}",
            f"  incident types survived: {self.scenarios_clean}/{self.scenarios_total}",
            f"  invariant checks held  : {self.checks_passed}/{self.checks_total}",
            f"  exposure: Rs {self.exposure_paise/100:,.2f}",
            "  per-invariant pass rate:",
        ]
        for name in ORACLE_NAMES:
            lines.append(f"    {name:30} {self.per_oracle_pass_rate.get(name, 1.0):.0%}")
        return "\n".join(lines)


def scorecard(target: str = "fixed", secret: str = DEFAULT_SECRET) -> ScoreCard:
    results = run_all(target, secret)
    clean = passed = total = exposure = 0
    per_pass: Counter = Counter()
    per_total: Counter = Counter()
    for r in results:
        exposure += r.money_at_risk
        if r.passed:
            clean += 1
        for o in r.oracle_results:
            total += 1
            per_total[o.name] += 1
            if o.passed:
                passed += 1
                per_pass[o.name] += 1
    # Headline score = fraction of incident types the integration survives cleanly.
    score = 100.0 * clean / len(results) if results else 100.0
    rates = {n: (per_pass[n] / per_total[n] if per_total[n] else 1.0) for n in ORACLE_NAMES}
    return ScoreCard(target, score, _grade(score), clean, len(results), passed, total, exposure, rates)
