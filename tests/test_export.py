"""Export formats must be valid and complete."""
import json
import xml.dom.minidom as minidom

import pytest

from nightshift import export
from nightshift.runner import run_all


@pytest.fixture(scope="module")
def naive_results():
    return run_all("naive")


def test_json_is_valid(naive_results):
    doc = json.loads(export.to_json(naive_results))
    assert doc["total_money_at_risk_paise"] > 0
    assert len(doc["scenarios"]) == 10


def test_sarif_is_valid_and_has_findings(naive_results):
    doc = json.loads(export.to_sarif(naive_results))
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"], "expected SARIF findings for the naive handler"
    assert all(f["ruleId"] for f in doc["runs"][0]["results"])


def test_junit_is_wellformed_xml(naive_results):
    minidom.parseString(export.to_junit(naive_results))  # raises if malformed


def test_csv_has_a_row_per_check(naive_results):
    rows = export.to_csv(naive_results).strip().splitlines()
    assert rows[0] == "scenario,oracle,passed,money_at_risk_paise"
    assert len(rows) - 1 == sum(len(r.oracle_results) for r in naive_results)


def test_fixed_sarif_has_no_findings():
    doc = json.loads(export.to_sarif(run_all("fixed")))
    assert doc["runs"][0]["results"] == []
