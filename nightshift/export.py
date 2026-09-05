"""Export findings in the formats CI systems already understand.

  * SARIF 2.1.0  — GitHub code-scanning / security tab
  * JUnit XML    — every CI test reporter
  * JSON         — anything
  * Markdown     — a PR comment
  * CSV          — a spreadsheet

Each takes the list of ScenarioResult from `runner.run_all(target)`.
"""
from __future__ import annotations

import json
from xml.sax.saxutils import escape

from .oracles import ORACLE_NAMES
from .triage import _severity

_LEVEL = {"SEV1": "error", "SEV2": "error", "SEV3": "warning"}


def to_json(results) -> str:
    return json.dumps({
        "target": results[0].target if results else None,
        "total_money_at_risk_paise": sum(r.money_at_risk for r in results),
        "scenarios": [{
            "key": r.key, "title": r.title, "money_at_risk_paise": r.money_at_risk,
            "errors": r.errors,
            "oracles": {o.name: {"passed": o.passed, "detail": o.detail,
                                 "money_at_risk_paise": o.money_at_risk}
                        for o in r.oracle_results},
        } for r in results],
    }, indent=2)


def to_junit(results) -> str:
    cases = []
    failures = 0
    for r in results:
        for o in r.oracle_results:
            name = escape(f"{r.key}.{o.name}")
            if o.passed:
                cases.append(f'    <testcase classname="nightshift" name="{name}"/>')
            else:
                failures += 1
                cases.append(
                    f'    <testcase classname="nightshift" name="{name}">\n'
                    f'      <failure message="{escape(o.detail)}">Rs {o.money_at_risk/100:.2f} at risk</failure>\n'
                    f'    </testcase>'
                )
    total = sum(len(r.oracle_results) for r in results)
    body = "\n".join(cases)
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<testsuite name="nightshift" tests="{total}" failures="{failures}">\n{body}\n</testsuite>\n')


def to_sarif(results) -> str:
    rules = [{"id": name, "name": name,
              "shortDescription": {"text": name.replace("_", " ")}} for name in ORACLE_NAMES]
    findings = []
    for r in results:
        for o in r.oracle_results:
            if o.passed:
                continue
            findings.append({
                "ruleId": o.name,
                "level": _LEVEL[_severity(o.money_at_risk)],
                "message": {"text": f"{r.title}: {o.detail} (Rs {o.money_at_risk/100:.2f} at risk)"},
                "locations": [{"logicalLocations": [{"name": r.key, "kind": "scenario"}]}],
            })
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "NIGHTSHIFT", "informationUri": "https://example.invalid/nightshift",
                                "rules": rules}},
            "results": findings,
        }],
    }
    return json.dumps(doc, indent=2)


def to_markdown(results) -> str:
    head = "| Scenario | " + " | ".join(n.replace("_", " ") for n in ORACLE_NAMES) + " | ₹ at risk |"
    sep = "|" + "---|" * (len(ORACLE_NAMES) + 2)
    rows = [head, sep]
    for r in results:
        cells = " | ".join("✅" if o.passed else "❌" for o in r.oracle_results)
        rows.append(f"| {r.title} | {cells} | {r.money_at_risk/100:,.0f} |")
    total = sum(r.money_at_risk for r in results)
    rows.append(f"\n**Total money at risk on `{results[0].target}`: Rs {total/100:,.2f}**")
    return "\n".join(rows)


def to_csv(results) -> str:
    lines = ["scenario,oracle,passed,money_at_risk_paise"]
    for r in results:
        for o in r.oracle_results:
            lines.append(f"{r.key},{o.name},{o.passed},{o.money_at_risk}")
    return "\n".join(lines) + "\n"


EXPORTERS = {
    "json": to_json, "junit": to_junit, "sarif": to_sarif,
    "markdown": to_markdown, "csv": to_csv,
}
