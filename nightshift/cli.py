"""NIGHTSHIFT command line.

    nightshift run    --target naive [--scenario replay] [--json] [--incidents]
    nightshift run    --target fixed --fail-on-violation
    nightshift report --target naive --format sarif -o findings.sarif
    nightshift bench                       # measured precision/recall + mutation
    nightshift fuzz   --target naive --trials 500 --seed 1
    nightshift score  --target fixed       # 0-100 reliability grade
    nightshift diff                        # naive vs fixed, what the fix changed
    nightshift list   scenarios|oracles

Exit codes: 0 ok · 1 an invariant failed / threshold exceeded · 2 internal error.
"""
from __future__ import annotations

import argparse
import os
import sys

from . import export
from .bench import summary as bench_summary
from .campaign import fuzz as run_fuzz
from .model import rupees
from .oracles import ORACLE_NAMES
from .report import write as write_html_report
from .runner import DEFAULT_SECRET, run_scenario
from .score import scorecard
from .scenarios import SCENARIOS, by_key
from .triage import triage

_ANSI = {"green": "\033[32m", "red": "\033[31m", "dim": "\033[2m", "reset": "\033[0m"}


def _colors(enabled: bool):
    return _ANSI if enabled else {k: "" for k in _ANSI}


def _results(target: str, secret: str, only: str | None):
    scenarios = [by_key(only)] if only else SCENARIOS
    return [run_scenario(s, target, secret) for s in scenarios]


def _run_json(results) -> dict:
    return {
        "target": results[0].target if results else None,
        "total_money_at_risk_paise": sum(r.money_at_risk for r in results),
        "scenarios": [{
            "key": r.key, "money_at_risk_paise": r.money_at_risk, "errors": r.errors,
            "oracles": {o.name: {"passed": o.passed, "money_at_risk_paise": o.money_at_risk}
                        for o in r.oracle_results},
        } for r in results],
    }


def _cmd_run(a) -> int:
    import json
    results = _results(a.target, a.secret, a.scenario)
    any_fail = any(r.failures or r.errors for r in results)
    total = sum(r.money_at_risk for r in results)
    if a.json:
        print(json.dumps(_run_json(results), indent=2))
    else:
        c = _colors(not a.no_color)
        for r in results:
            print(f"\n{r.title}\n{c['dim']}{r.story}{c['reset']}")
            for o in r.oracle_results:
                mark = f"{c['green']}PASS{c['reset']}" if o.passed else f"{c['red']}FAIL{c['reset']}"
                print(f"  [{mark}] {o.name:30} {'' if o.passed else o.detail}")
            for err in r.errors:
                print(f"  {c['red']}ERROR{c['reset']} {err}")
            if r.money_at_risk:
                print(f"  {c['red']}money at risk: {rupees(r.money_at_risk)}{c['reset']}")
            if a.incidents:
                for o in r.failures:
                    print("\n" + triage(o, r.trace, r.key).render())
        col = c['red'] if total else c['green']
        print(f"\n{'='*60}\nTOTAL money at risk on '{a.target}': {col}{rupees(total)}{c['reset']}")
    if a.fail_on_violation and any_fail:
        return 1
    if a.fail_over is not None and total > a.fail_over:
        return 1
    return 0


def _cmd_report(a) -> int:
    if a.format == "html":
        print(f"wrote {write_html_report(a.output or 'report.html', a.target, a.secret)}")
        return 0
    text = export.EXPORTERS[a.format](_results(a.target, a.secret, None))
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"wrote {a.output}")
    else:
        print(text)
    return 0


def _cmd_bench(_a) -> int:
    print(bench_summary())
    return 0


def _cmd_fuzz(a) -> int:
    print(run_fuzz(a.target, trials=a.trials, seed=a.seed, secret=a.secret).render())
    return 0


def _cmd_score(a) -> int:
    print(scorecard(a.target, a.secret).render())
    return 0


def _cmd_diff(a) -> int:
    c = _colors(not a.no_color)
    print(f"{'scenario':16} {'naive':28} fixed")
    for s in SCENARIOS:
        nf = {r.name for r in run_scenario(s, "naive", a.secret).failures}
        ff = {r.name for r in run_scenario(s, "fixed", a.secret).failures}
        n = f"{c['red']}{len(nf)} broken{c['reset']}" if nf else f"{c['green']}clean{c['reset']}"
        f = f"{c['red']}{len(ff)} broken{c['reset']}" if ff else f"{c['green']}clean{c['reset']}"
        print(f"{s.key:16} {n:28} {f}")
    return 0


def _cmd_list(a) -> int:
    if a.what == "scenarios":
        for s in SCENARIOS:
            print(f"{s.key:16} {s.title}")
    else:
        for name in ORACLE_NAMES:
            print(name)
    return 0


def _cmd_scan(a) -> int:
    from .scanner import scan
    rep = scan(a.url, a.secret)
    print(rep.render())
    return 1 if (a.fail_on_hit and rep.hits) else 0


def _cmd_serve(a) -> int:
    from .refserver import main as serve_main
    return serve_main(["--port", str(a.port), "--secret", a.secret] + (["--hardened"] if a.hardened else []))


def _cmd_advisories(a) -> int:
    from .advisories import to_markdown
    from .scanner import scan
    md = to_markdown(scan(a.url, a.secret))
    if a.output:
        with open(a.output, "w", encoding="utf-8") as f:
            f.write(md)
        print(f"wrote {a.output}")
    else:
        print(md)
    return 0


def _cmd_cinema(a) -> int:
    from .cinema import write
    print(f"wrote {write(a.output or 'attack_cinema.html', a.secret)}")
    return 0


def _cmd_badge(a) -> int:
    from .badge import write
    print(f"wrote {write(a.output or 'nightshift-badge.svg', a.grade)}")
    return 0


def _cmd_dashboard(a) -> int:
    from .dashboard import serve
    serve(a.port, a.secret, open_browser=not a.no_open)
    return 0


def _cmd_merchant(a) -> int:
    from .merchant import serve
    serve(a.port, hardened=a.hardened, secret=a.secret, open_browser=a.open)
    return 0


def _cmd_prove(a) -> int:
    from .prove import prove
    print(prove(secret=a.secret, url=a.url, color=not a.no_color))
    return 0


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="nightshift", description="The 2 AM machine for Razorpay integrations.")
    p.add_argument("--secret", default=os.getenv("NIGHTSHIFT_SECRET", DEFAULT_SECRET),
                   help="webhook secret to sign/verify with (defaults to $NIGHTSHIFT_SECRET)")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colours")
    sub = p.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("run", help="run scenarios against a target and score invariants")
    r.add_argument("--target", choices=["naive", "fixed"], default="naive")
    r.add_argument("--scenario", help="run only this scenario key")
    r.add_argument("--json", action="store_true")
    r.add_argument("--incidents", action="store_true")
    r.add_argument("--fail-on-violation", action="store_true", help="exit 1 if any invariant fails")
    r.add_argument("--fail-over", type=int, metavar="PAISE", help="exit 1 if exposure exceeds PAISE")
    r.set_defaults(func=_cmd_run)

    rep = sub.add_parser("report", help="export findings (html/json/sarif/junit/markdown/csv)")
    rep.add_argument("--target", choices=["naive", "fixed"], default="naive")
    rep.add_argument("--format", choices=["html", *export.EXPORTERS], default="html")
    rep.add_argument("-o", "--output")
    rep.set_defaults(func=_cmd_report)

    b = sub.add_parser("bench", help="measured precision/recall + mutation testing")
    b.set_defaults(func=_cmd_bench)

    fz = sub.add_parser("fuzz", help="randomized fault campaign with failing-case shrinking")
    fz.add_argument("--target", choices=["naive", "fixed"], default="naive")
    fz.add_argument("--trials", type=int, default=300)
    fz.add_argument("--seed", type=int, default=0)
    fz.set_defaults(func=_cmd_fuzz)

    sc = sub.add_parser("score", help="0-100 reliability grade for a target")
    sc.add_argument("--target", choices=["naive", "fixed"], default="fixed")
    sc.set_defaults(func=_cmd_score)

    df = sub.add_parser("diff", help="naive vs fixed — what the fix changed")
    df.set_defaults(func=_cmd_diff)

    ls = sub.add_parser("list", help="list scenarios or oracles")
    ls.add_argument("what", choices=["scenarios", "oracles"])
    ls.set_defaults(func=_cmd_list)

    scn = sub.add_parser("scan", help="LIVE red-team scan of a running payment endpoint")
    scn.add_argument("--url", required=True)
    scn.add_argument("--fail-on-hit", action="store_true", help="exit 1 if any attack lands")
    scn.set_defaults(func=_cmd_scan)

    sv = sub.add_parser("serve", help="run the bundled reference target (add --hardened for the safe one)")
    sv.add_argument("--port", type=int, default=8000)
    sv.add_argument("--hardened", action="store_true")
    sv.set_defaults(func=_cmd_serve)

    ad = sub.add_parser("advisories", help="scan an endpoint and emit CVE-style advisories (Markdown)")
    ad.add_argument("--url", required=True)
    ad.add_argument("-o", "--output")
    ad.set_defaults(func=_cmd_advisories)

    cn = sub.add_parser("cinema", help="write the animated attack-cinema HTML")
    cn.add_argument("-o", "--output")
    cn.set_defaults(func=_cmd_cinema)

    bd = sub.add_parser("badge", help="write an SVG money-safety grade badge")
    bd.add_argument("--grade", default="A+")
    bd.add_argument("-o", "--output")
    bd.set_defaults(func=_cmd_badge)

    dash = sub.add_parser("dashboard", help="LIVE web UI: watch attacks hit a local server in real time")
    dash.add_argument("--port", type=int, default=8888)
    dash.add_argument("--no-open", action="store_true", help="don't auto-open the browser")
    dash.set_defaults(func=_cmd_dashboard)

    mc = sub.add_parser("merchant", help="run a REAL Razorpay-integrated target (Flask + SDK) to scan")
    mc.add_argument("--port", type=int, default=5000)
    mc.add_argument("--hardened", action="store_true", help="run the safe integration (expect grade A+)")
    mc.add_argument("--open", action="store_true", help="open the storefront in a browser")
    mc.set_defaults(func=_cmd_merchant)

    pr = sub.add_parser("prove", help="side-by-side proof: watch the theft in each shop's own ledger")
    pr.add_argument("--url", help="prove against your own running app instead of the bundled shops")
    pr.set_defaults(func=_cmd_prove)
    return p


def main(argv=None) -> int:
    try:  # Windows consoles/pipes default to cp1252; never crash on a stray glyph
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
    args = _build_parser().parse_args(argv)
    try:
        return args.func(args)
    except BrokenPipeError:
        # downstream closed the pipe (e.g. `| head`) — exit quietly like any UNIX tool
        try:
            sys.stdout.close()
        except Exception:
            pass
        return 0
    except Exception as e:
        print(f"nightshift: error: {type(e).__name__}: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
