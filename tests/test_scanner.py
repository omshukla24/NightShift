"""Live scanner against the bundled reference server: naive is wrecked, hardened holds."""
import threading
import time
import urllib.request

import pytest

from nightshift.advisories import advisories_for, to_markdown
from nightshift.refserver import build_server
from nightshift.scanner import scan


def _serve(hardened):
    httpd = build_server(0, hardened=hardened)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{httpd.server_address[1]}"
    for _ in range(60):
        try:
            urllib.request.urlopen(url + "/health", timeout=1)
            break
        except Exception:
            time.sleep(0.05)
    return httpd, url


@pytest.fixture
def naive_url():
    httpd, url = _serve(False)
    yield url
    httpd.shutdown()


@pytest.fixture
def hardened_url():
    httpd, url = _serve(True)
    yield url
    httpd.shutdown()


def test_naive_target_is_wrecked(naive_url):
    rep = scan(naive_url)
    assert rep.grade == "F"
    assert len(rep.hits) >= 6
    landed = {f.attack for f in rep.hits}
    assert {"unsigned", "forged", "idor", "over_refund"} <= landed
    assert rep.exposure > 0


def test_hardened_target_survives_everything(hardened_url):
    rep = scan(hardened_url)
    assert rep.grade == "A+"
    assert rep.hits == []


def test_race_double_spends_but_sequential_replay_is_safe(naive_url):
    by = {f.attack: f for f in scan(naive_url).findings}
    assert by["race"].succeeded, "concurrency should defeat the non-atomic dedupe"
    assert not by["replay"].succeeded, "sequential replay is deduped — the race is the real bug"


def test_advisories_are_generated_from_a_live_scan(naive_url):
    rep = scan(naive_url)
    advs = advisories_for(rep)
    assert len(advs) == len(rep.hits)
    assert all(a.advisory_id.startswith("NIGHTSHIFT-") for a in advs)
    md = to_markdown(rep)
    assert "CVSS" in md and "Fix." in md


def test_unreachable_target_raises_clean_error():
    from nightshift.scanner import scan as s
    with pytest.raises(ConnectionError):
        s("http://127.0.0.1:1")  # nothing listening
