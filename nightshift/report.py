"""Report — render a run as a self-contained HTML page (the dashboard).

No server required: it writes a single static report.html you can open locally
or deploy to Vercel as a static file. Pass target='naive' to show the carnage,
target='fixed' to show the same integration, hardened and green.
"""
from __future__ import annotations

import html
import os

from .runner import DEFAULT_SECRET, run_all
from .triage import triage

_CSS = """
:root{color-scheme:dark}
*{box-sizing:border-box}
body{margin:0;background:#0b0b0d;color:#e9e4d8;font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace}
.wrap{max-width:1040px;margin:0 auto;padding:40px 24px 80px}
h1{font-size:30px;margin:0 0 4px;letter-spacing:-.5px}
.sub{color:#9a948a;margin:0 0 28px}
.kpis{display:flex;gap:16px;flex-wrap:wrap;margin:0 0 32px}
.kpi{background:#141317;border:1px solid #262229;border-radius:12px;padding:16px 20px;min-width:150px}
.kpi .n{font-size:26px;font-weight:700}
.kpi .l{color:#9a948a;font-size:12px;text-transform:uppercase;letter-spacing:.06em}
.red{color:#ff6b6b}.green{color:#7ee081}.amber{color:#f4c04d}
table{width:100%;border-collapse:collapse;margin:0 0 32px;font-size:13px}
th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #201d24}
th{color:#9a948a;font-weight:600;text-transform:uppercase;font-size:11px;letter-spacing:.06em}
.pill{display:inline-block;padding:2px 8px;border-radius:999px;font-size:11px;font-weight:700}
.pill.pass{background:#12301c;color:#7ee081}.pill.fail{background:#301414;color:#ff6b6b}
.card{background:#141317;border:1px solid #262229;border-left:3px solid #ff6b6b;border-radius:10px;padding:16px 18px;margin:0 0 14px}
.card h3{margin:0 0 6px;font-size:15px}
.card .meta{color:#9a948a;font-size:12px;margin:0 0 10px}
pre{background:#0d0c0f;border:1px solid #201d24;border-radius:8px;padding:12px;overflow-x:auto;white-space:pre-wrap;color:#cfc8ba;font-size:12.5px}
.foot{color:#6e685f;font-size:12px;margin-top:40px;border-top:1px solid #201d24;padding-top:16px}
"""


def _cell(passed: bool) -> str:
    return '<span class="pill pass">PASS</span>' if passed else '<span class="pill fail">FAIL</span>'


def render(target: str = "naive", secret: str = DEFAULT_SECRET) -> str:
    results = run_all(target, secret)
    oracle_names = [r.name for r in results[0].oracle_results]

    total_risk = sum(r.money_at_risk for r in results)
    total_fail = sum(len(r.failures) for r in results)
    total_checks = sum(len(r.oracle_results) for r in results)

    rows = []
    for r in results:
        cells = "".join(f"<td>{_cell(o.passed)}</td>" for o in r.oracle_results)
        risk = f'<span class="red">Rs {r.money_at_risk/100:,.0f}</span>' if r.money_at_risk else '<span class="green">Rs 0</span>'
        rows.append(f"<tr><td><b>{html.escape(r.title)}</b></td>{cells}<td>{risk}</td></tr>")

    cards = []
    for r in results:
        for o in r.failures:
            inc = triage(o, r.trace, r.key)
            cards.append(
                f'<div class="card"><h3>{html.escape(r.title)} — '
                f'<span class="red">{html.escape(o.name)}</span> '
                f'<span class="amber">[{inc.severity}]</span></h3>'
                f'<div class="meta">{html.escape(r.story)}</div>'
                f'<pre>{html.escape(inc.render())}</pre></div>'
            )

    heads = "".join(f"<th>{html.escape(n.replace('_',' '))}</th>" for n in oracle_names)
    verdict = "green" if total_fail == 0 else "red"
    return f"""<!doctype html><html><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NIGHTSHIFT — {html.escape(target)} run</title><style>{_CSS}</style></head><body>
<div class="wrap">
  <h1>NIGHTSHIFT <span class="{verdict}">·</span> the 2 AM machine</h1>
  <p class="sub">Fault-injection &amp; invariant report for the <b>{html.escape(target)}</b> Razorpay integration.</p>
  <div class="kpis">
    <div class="kpi"><div class="n {verdict}">{total_fail}/{total_checks}</div><div class="l">invariants broken</div></div>
    <div class="kpi"><div class="n {'red' if total_risk else 'green'}">Rs {total_risk/100:,.0f}</div><div class="l">money at risk</div></div>
    <div class="kpi"><div class="n">{len(results)}</div><div class="l">scenarios replayed</div></div>
  </div>
  <table><thead><tr><th>Scenario</th>{heads}<th>At risk</th></tr></thead><tbody>{''.join(rows)}</tbody></table>
  <h2 style="font-size:18px">Incidents</h2>
  {''.join(cards) or '<p class="green">No incidents — every invariant held.</p>'}
  <div class="foot">Verdicts are proven by deterministic oracles; root-cause &amp; fix prose by the triage layer
  ({'a model' if os.getenv('GEMINI_API_KEY') else 'a deterministic playbook — no API key set'}).
  NIGHTSHIFT · built during the night shift.</div>
</div></body></html>"""


def write(path: str = "report.html", target: str = "naive", secret: str = DEFAULT_SECRET) -> str:
    out = render(target, secret)
    with open(path, "w", encoding="utf-8") as f:
        f.write(out)
    return path
