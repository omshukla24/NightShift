"""Seeded property tests (no external deps).

Instead of one hand-picked case, we hammer the handlers with hundreds of random
(but reproducible) event streams and assert the invariants hold. This is the
"would you trust it" evidence: the hardened handler stays correct under arbitrary
duplication and reordering of legitimate events, with zero false positives.
"""
import random

from nightshift import constants as C
from nightshift.handlers import FixedHandler, NaiveHandler
from nightshift.model import GroundTruth, TrueMovement, build_delivery
from nightshift.oracles import Trace, evaluate
from nightshift.runner import DEFAULT_SECRET


def _valid_capture(order_id, amount, i):
    return build_delivery(DEFAULT_SECRET, event_id=f"evt_{order_id}_{i}",
                          etype=C.PAYMENT_CAPTURED, order_id=order_id,
                          payment_id=f"pay_{order_id}", kind=C.CAPTURE, amount=amount)


def test_idempotency_holds_for_any_duplication_count():
    for k in range(1, 26):
        fixed = FixedHandler(DEFAULT_SECRET)
        naive = NaiveHandler(DEFAULT_SECRET)
        for h in (fixed, naive):
            h.register_order("o1", 5000)
        d = _valid_capture("o1", 5000, 0)
        for _ in range(k):
            fixed.handle(d)
            naive.handle(d)
        assert fixed.state.fulfillments.count("o1") == 1     # deduped, always
        assert naive.state.fulfillments.count("o1") == k     # naive duplicates every time


def test_hardened_handler_has_zero_false_positives_under_chaos():
    rng = random.Random(1729)  # fixed seed => reproducible
    for _ in range(300):
        n = rng.randint(1, 6)
        orders = {f"o{i}": rng.randint(1, 5000) * 100 for i in range(n)}
        gt = GroundTruth(order_amounts=dict(orders))
        gt.movements = [TrueMovement(o, f"pay_{o}", C.CAPTURE, a) for o, a in orders.items()]

        stream = []
        for i, (o, a) in enumerate(orders.items()):
            reps = rng.randint(1, 4)  # legit event, retried a few times
            stream += [_valid_capture(o, a, i) for _ in range(reps)]
        rng.shuffle(stream)

        h = FixedHandler(DEFAULT_SECRET, verifier=gt.is_true_capture)
        for o, a in orders.items():
            h.register_order(o, a)
        for d in stream:
            h.handle(d)
        h.reconcile(gt.movements)

        trace = Trace(DEFAULT_SECRET, gt, stream, h.state)
        failures = [r.name for r in evaluate(trace) if not r.passed]
        assert not failures, f"false positive on legit chaos: {failures} (orders={orders})"
