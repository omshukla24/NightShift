"""A shields-style SVG grade badge — 'money-safety: A+' for the README."""
from __future__ import annotations

_COLOR = {"A+": "#3fb950", "A": "#3fb950", "B": "#a3b30a", "C": "#d29922",
          "D": "#db6d28", "F": "#f85149"}


def badge_svg(grade: str, label: str = "money-safety") -> str:
    color = _COLOR.get(grade, "#8b949e")
    lw, gw = 84, 34  # label / grade widths
    total = lw + gw
    return f"""<svg xmlns="http://www.w3.org/2000/svg" width="{total}" height="20" role="img" aria-label="{label}: {grade}">
  <linearGradient id="s" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient>
  <rect rx="3" width="{total}" height="20" fill="#555"/>
  <rect rx="3" x="{lw}" width="{gw}" height="20" fill="{color}"/>
  <rect rx="3" width="{total}" height="20" fill="url(#s)"/>
  <g fill="#fff" text-anchor="middle" font-family="Verdana,DejaVu Sans,sans-serif" font-size="11">
    <text x="{lw/2}" y="14">{label}</text>
    <text x="{lw + gw/2}" y="14" font-weight="bold">{grade}</text>
  </g>
</svg>
"""


def write(path: str = "nightshift-badge.svg", grade: str = "A+", label: str = "money-safety") -> str:
    with open(path, "w", encoding="utf-8") as f:
        f.write(badge_svg(grade, label))
    return path
