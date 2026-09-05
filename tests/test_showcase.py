"""Attack cinema + grade badge (offline, no server needed)."""
from nightshift import badge, cinema


def test_cinema_renders_self_contained_html():
    html = cinema.render()
    assert html.strip().startswith("<!doctype html>")
    assert 'id="counter"' in html and "PATCH DEPLOYED" in html
    assert "http://" not in html.replace("http://www.w3.org", "")  # no external deps besides the SVG ns


def test_badge_is_valid_svg_and_colours_by_grade():
    assert badge.badge_svg("A+").strip().startswith("<svg")
    assert "#3fb950" in badge.badge_svg("A+")   # green
    assert "#f85149" in badge.badge_svg("F")    # red


def test_badge_and_cinema_write(tmp_path):
    b = badge.write(str(tmp_path / "b.svg"), "A+")
    c = cinema.write(str(tmp_path / "c.html"))
    assert b.endswith("b.svg") and c.endswith("c.html")
