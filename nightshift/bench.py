"""Bench — measured accuracy of the oracle suite. Honest metrics, no cherry-picking.

  1. Detection on a labelled set. Every (handler, scenario, oracle) cell is a
     labelled check: the naive handler's known bugs are the positives, the fully
     hardened handler is all-negative, and the control scenario (a legitimate
     partial refund) must stay negative on both. We report precision, recall, F1,
     specificity and the full confusion matrix — including false-positive count,
     the number that actually matters for a checker you'd let block a release.

  2. Mutation testing. Remove each defense from the hardened handler one at a time
     and confirm an oracle catches the regression. A defense no oracle catches is
     dead weight; a bug no oracle catches is a false sense of safety.
"""
from __future__ import annotations

from dataclasses import dataclass

from . import constants as C
from .handlers import FixedHandler
from .oracles import Trace, evaluate
from .runner import DEFAULT_SECRET, run_scenario
from .scenarios import SCENARIOS, by_key

# A removed defense -> the invariant that must notice, on the scenario that triggers it.
MUTANTS = {
    C.DEF_SIG: ("signature_integrity", "forged"),
    C.DEF_DEDUPE: ("idempotency", "replay"),
    C.DEF_AMOUNT: ("no_unpaid_fulfillment", "underpaid"),
    C.DEF_RECONCILE: ("reconciliation_completeness", "dropped"),
    C.DEF_REFUND_BOUND: ("no_over_refund", "over_refund"),
}


@dataclass
class Confusion:
    tp: int = 0
    fp: int = 0
    fn: int = 0
    tn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 1.0

    @property
    def specificity(self) -> float:
        return self.tn / (self.tn + self.fp) if (self.tn + self.fp) else 1.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        return 2 * p * r / (p + r) if (p + r) else 1.0


def detection() -> Confusion:
    c = Confusion()
    for s in SCENARIOS:
        for target, positives in (("naive", set(s.expected_naive)), ("fixed", set())):
            res = run_scenario(s, target)
            for o in res.oracle_results:
                predicted, actual = (not o.passed), (o.name in positives)
                if predicted and actual:
                    c.tp += 1
                elif predicted and not actual:
                    c.fp += 1
                elif not predicted and actual:
                    c.fn += 1
                else:
                    c.tn += 1
    return c


def _run_mutant(defense: str, scenario) -> set[str]:
    gt = scenario.ground_truth()
    handler = FixedHandler(DEFAULT_SECRET, verifier=gt.is_true_capture,
                           defenses=FixedHandler(DEFAULT_SECRET).defenses - {defense})
    for oid, amt in scenario.orders:
        handler.register_order(oid, amt)
    deliveries = scenario.actual_deliveries(DEFAULT_SECRET)  # built once
    for d in deliveries:
        handler.handle(d)
    if scenario.reconcile:
        handler.reconcile(gt.movements)
    trace = Trace(DEFAULT_SECRET, gt, deliveries, handler.state)
    return {r.name for r in evaluate(trace) if not r.passed}


def mutation() -> dict[str, bool]:
    return {d: (oracle in _run_mutant(d, by_key(sk))) for d, (oracle, sk) in MUTANTS.items()}


def summary() -> str:
    c = detection()
    m = mutation()
    lines = [
        "DETECTION (labelled set)",
        f"  checks={c.tp + c.fp + c.fn + c.tn}  TP={c.tp} FP={c.fp} FN={c.fn} TN={c.tn}",
        f"  precision={c.precision:.3f}  recall={c.recall:.3f}  "
        f"specificity={c.specificity:.3f}  F1={c.f1:.3f}",
        "",
        "MUTATION TESTING (each defense removed once)",
    ]
    for d, ok in m.items():
        lines.append(f"  drop '{d}'  -> caught by {MUTANTS[d][0]:32} {'KILLED' if ok else 'SURVIVED (!)'}")
    lines.append(f"  kill rate = {sum(m.values())}/{len(m)}")
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover
    print(summary())
