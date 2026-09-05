"""Fuzz campaign — randomized fault composition with failing-case shrinking.

Instead of the six hand-written scenarios, a campaign composes *random* sequences
of faults over each scenario's event stream, runs them against a target, and:

  * measures **oracle coverage** — how many invariants the campaign managed to trip,
  * for every invariant it breaks, **shrinks** the random stream to a minimal failing
    sequence (delta-debugging), so a 20-event mess collapses to the 2 events that
    actually matter,
  * and asserts the property that matters: the hardened handler survives the entire
    campaign with **zero** failures.

Everything is seeded, so a campaign is 100% reproducible from `(seed, trials)`.
"""
from __future__ import annotations

import copy
import random
from collections import Counter
from dataclasses import dataclass, field

from . import constants as C
from . import faults
from .model import Delivery, GroundTruth
from .oracles import ORACLE_NAMES, Trace, evaluate
from .runner import DEFAULT_SECRET, make_handler
from .scenarios import SCENARIOS, Scenario


def _failing(target: str, scenario: Scenario, deliveries: list[Delivery], secret: str) -> set[str]:
    gt = scenario.ground_truth()
    h = make_handler(target, secret, gt)
    for oid, amt in scenario.orders:
        h.register_order(oid, amt)
    for d in deliveries:
        try:
            h.handle(d)
        except Exception:
            return {"__crash__"}
    # A correct integration always reconciles (idempotent, a no-op on the naive
    # handler), so the fuzzer runs it too — otherwise a dropped webhook would be
    # blamed on the harness, not the handler.
    h.reconcile(gt.movements)
    return {r.name for r in evaluate(Trace(secret, gt, deliveries, h.state)) if not r.passed}


def _corrupt_signature(d: Delivery) -> Delivery:
    nd = copy.copy(d)
    nd.signature = "0" * 64
    nd._sig_ok = None
    return nd


def _mutate(deliveries: list[Delivery], scenario: Scenario, secret: str, rng: random.Random):
    ds = list(deliveries)
    ops: list[str] = []
    for _ in range(rng.randint(1, 3)):
        op = rng.choice(["dup", "drop", "reorder", "tamper", "forge", "corrupt"])
        if op == "dup" and ds:
            ds = faults.duplicate(ds, times=rng.randint(2, 4), kind=rng.choice(C.KINDS))
        elif op == "drop" and ds:
            ds = faults.drop(ds, kind=rng.choice(C.KINDS))
        elif op == "reorder":
            ds = faults.reorder(ds)
        elif op == "tamper" and any(d.kind == C.CAPTURE for d in ds):
            ds = faults.tamper_amount(ds, secret=secret, to=rng.choice([1, 100, 999999]))
        elif op == "forge":
            oid, amt = rng.choice(scenario.orders)
            ds = faults.forge(ds, secret=secret, order_id=oid, amount=amt)
        elif op == "corrupt" and ds:
            i = rng.randrange(len(ds))
            ds = ds[:i] + [_corrupt_signature(ds[i])] + ds[i + 1:]
        ops.append(op)
    return ds, ops


def _shrink(deliveries: list[Delivery], scenario: Scenario, target: str,
            oracle: str, secret: str) -> list[Delivery]:
    """Greedy delta-debug: drop events while the oracle still fails."""
    cur = list(deliveries)
    changed = True
    while changed and len(cur) > 1:
        changed = False
        for i in range(len(cur)):
            candidate = cur[:i] + cur[i + 1:]
            if oracle in _failing(target, scenario, candidate, secret):
                cur = candidate
                changed = True
                break
    return cur


def _repr(deliveries: list[Delivery], secret: str) -> list[str]:
    return [
        f"{d.etype.split('.')[-1]} {d.order_id} {d.amount}{d.currency}"
        f" sig={'ok' if d.signature_valid(secret) else 'BAD'}"
        f"{' dropped' if not d.delivered else ''}"
        for d in deliveries
    ]


@dataclass
class CampaignReport:
    target: str
    trials: int
    seed: int
    failing_trials: int
    oracle_hits: Counter = field(default_factory=Counter)
    minimal_cases: dict[str, list[str]] = field(default_factory=dict)
    crashes: int = 0

    @property
    def coverage(self) -> float:
        return len([o for o in ORACLE_NAMES if self.oracle_hits.get(o)]) / len(ORACLE_NAMES)

    def render(self) -> str:
        lines = [
            f"CAMPAIGN target={self.target} trials={self.trials} seed={self.seed}",
            f"  failing trials : {self.failing_trials}/{self.trials}",
            f"  oracle coverage: {self.coverage:.0%} ({len([o for o in ORACLE_NAMES if self.oracle_hits.get(o)])}/{len(ORACLE_NAMES)})",
            f"  crashes        : {self.crashes}",
        ]
        for oracle in ORACLE_NAMES:
            if oracle in self.minimal_cases:
                seq = " | ".join(self.minimal_cases[oracle])
                lines.append(f"  minimal case · {oracle}:\n      {seq}")
        return "\n".join(lines)


def fuzz(target: str = "naive", trials: int = 200, seed: int = 0,
         secret: str = DEFAULT_SECRET, shrink: bool = True) -> CampaignReport:
    rng = random.Random(seed)
    rep = CampaignReport(target=target, trials=trials, seed=seed, failing_trials=0)
    for _ in range(trials):
        scenario = rng.choice(SCENARIOS)
        ideal = scenario.ideal_deliveries(secret)
        mutated, _ops = _mutate(ideal, scenario, secret, rng)
        failing = _failing(target, scenario, mutated, secret)
        if "__crash__" in failing:
            rep.crashes += 1
            failing.discard("__crash__")
        if failing:
            rep.failing_trials += 1
        for oracle in failing:
            rep.oracle_hits[oracle] += 1
            if shrink and oracle not in rep.minimal_cases:
                minimal = _shrink(mutated, scenario, target, oracle, secret)
                rep.minimal_cases[oracle] = _repr(minimal, secret)
    return rep


if __name__ == "__main__":  # pragma: no cover
    print(fuzz("naive", trials=200, seed=1).render())
