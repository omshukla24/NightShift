"""Runner — apply a scenario to a target handler and score the invariants.

Resilient by construction: if a target integration *throws* on a hostile event
(itself a finding — a crash mid-payment is a 2 AM incident), the harness records
the error and keeps going instead of dying with it.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from .config import DEFAULT
from .handlers import FixedHandler, NaiveHandler, PaymentHandler
from .model import GroundTruth
from .oracles import OracleResult, Trace, evaluate
from .scenarios import SCENARIOS, Scenario

DEFAULT_SECRET = DEFAULT.secret


def make_handler(target: str, secret: str, gt: GroundTruth) -> PaymentHandler:
    if target == "naive":
        return NaiveHandler(secret)
    if target == "fixed":
        # A correct handler verifies each event against the Razorpay API before
        # acting. Here the verifier is backed by ground truth (the API's answer).
        return FixedHandler(secret, verifier=gt.is_true_capture)
    raise ValueError(f"unknown target: {target!r}")


@dataclass
class ScenarioResult:
    key: str
    title: str
    story: str
    target: str
    oracle_results: list[OracleResult]
    money_at_risk: int
    trace: Trace = field(repr=False)
    errors: list[str] = field(default_factory=list)

    @property
    def failures(self) -> list[OracleResult]:
        return [r for r in self.oracle_results if not r.passed]

    @property
    def passed(self) -> bool:
        return not self.failures and not self.errors


def run_scenario(scenario: Scenario, target: str, secret: str = DEFAULT_SECRET) -> ScenarioResult:
    gt = scenario.ground_truth()
    handler = make_handler(target, secret, gt)
    for order_id, amount in scenario.orders:
        handler.register_order(order_id, amount)

    deliveries = scenario.actual_deliveries(secret)
    errors: list[str] = []
    for d in deliveries:
        try:
            handler.handle(d)
        except Exception as e:  # a target that crashes is a finding, not a harness death
            errors.append(f"handler crashed on {d.event_id}: {type(e).__name__}: {e}")
    if scenario.reconcile:
        try:
            handler.reconcile(gt.movements)
        except Exception as e:
            errors.append(f"reconcile crashed: {type(e).__name__}: {e}")

    trace = Trace(secret, gt, deliveries, handler.state)
    results = evaluate(trace)

    offending: set[str] = set()
    for r in results:
        if not r.passed:
            offending |= r.offending_orders
    money = sum(trace.order_amount(o) for o in offending)

    return ScenarioResult(scenario.key, scenario.title, scenario.story, target,
                          results, money, trace, errors)


def run_all(target: str, secret: str = DEFAULT_SECRET) -> list[ScenarioResult]:
    return [run_scenario(s, target, secret) for s in SCENARIOS]
