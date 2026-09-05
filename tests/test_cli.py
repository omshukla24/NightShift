"""CLI contract: JSON output shape and exit codes."""
import json

from nightshift.cli import main


def test_run_json_is_valid_and_shaped(capsys):
    rc = main(["run", "--target", "naive", "--json"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0
    assert out["target"] == "naive"
    assert out["total_money_at_risk_paise"] > 0
    assert len(out["scenarios"]) >= 8
    assert "oracles" in out["scenarios"][0]


def test_fail_on_violation_sets_exit_code():
    assert main(["run", "--target", "naive", "--json", "--fail-on-violation"]) == 1
    assert main(["run", "--target", "fixed", "--json", "--fail-on-violation"]) == 0


def test_bench_runs_clean(capsys):
    assert main(["bench"]) == 0
    assert "precision=1.000" in capsys.readouterr().out


def test_unknown_args_exit_2():
    # argparse raises SystemExit(2) for bad usage — that's the contract we want.
    try:
        main(["nonsense"])
    except SystemExit as e:
        assert e.code == 2


def test_fail_over_threshold_gates(capsys):
    assert main(["run", "--target", "naive", "--json", "--fail-over", "100"]) == 1
    capsys.readouterr()
    assert main(["run", "--target", "fixed", "--json", "--fail-over", "100"]) == 0


def test_scenario_filter_runs_one(capsys):
    assert main(["run", "--target", "naive", "--scenario", "over_refund", "--json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert len(out["scenarios"]) == 1 and out["scenarios"][0]["key"] == "over_refund"


def test_score_command(capsys):
    assert main(["score", "--target", "fixed"]) == 0
    assert "A+" in capsys.readouterr().out


def test_diff_command(capsys):
    assert main(["--no-color", "diff"]) == 0
    assert "clean" in capsys.readouterr().out


def test_list_commands(capsys):
    assert main(["list", "oracles"]) == 0
    assert "idempotency" in capsys.readouterr().out
    assert main(["list", "scenarios"]) == 0
    assert "replay" in capsys.readouterr().out


def test_fuzz_command(capsys):
    assert main(["fuzz", "--target", "fixed", "--trials", "50", "--seed", "1"]) == 0
    assert "failing trials : 0/50" in capsys.readouterr().out


def test_report_formats(capsys):
    for fmt in ("json", "sarif", "junit", "markdown", "csv"):
        assert main(["report", "--target", "naive", "--format", fmt]) == 0
        assert capsys.readouterr().out.strip()


def test_cinema_and_badge_write(tmp_path, capsys):
    assert main(["cinema", "-o", str(tmp_path / "c.html")]) == 0
    assert main(["badge", "--grade", "A+", "-o", str(tmp_path / "b.svg")]) == 0
    assert (tmp_path / "c.html").exists() and (tmp_path / "b.svg").exists()


def test_scan_via_cli_against_bundled_server(capsys):
    import threading
    import urllib.request
    from nightshift.refserver import build_server

    httpd = build_server(0, hardened=True)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{httpd.server_address[1]}"
    for _ in range(60):
        try:
            urllib.request.urlopen(url + "/health", timeout=1)
            break
        except Exception:
            import time
            time.sleep(0.05)
    try:
        assert main(["scan", "--url", url, "--fail-on-hit"]) == 0  # hardened => no hits
        assert "A+" in capsys.readouterr().out
    finally:
        httpd.shutdown()
