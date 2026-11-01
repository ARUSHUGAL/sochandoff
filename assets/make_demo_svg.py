#!/usr/bin/env python3
"""Generate an animated SVG terminal demo for the README.

Renders two "frames" of real sochandoff output as a looping terminal cast:
  frame 1 — first sight: threat-intel lines appear
  frame 2 — next shift: cross-shift memory recognizes the repeat attacker

No external tools needed. The SVG renders inline on GitHub and loops.
Run from the repo root:  python assets/make_demo_svg.py
"""

from __future__ import annotations

from pathlib import Path

# Two curated frames (trimmed real output) so the demo stays readable.
FRAME_1 = [
    ("$ sochandoff", "prompt"),
    ("", "plain"),
    ("  SOC SHIFT HANDOFF", "head"),
    ("  Open cases: 5    At-risk of being dropped: 5", "plain"),
    ("", "plain"),
    ("  \u26a0  DROPPED-CASE GUARD \u2014 read these first", "red"),
    ("  ! [SOC-1042] Phishing: credential-harvest to finance", "bold"),
    ("      why flagged: open 4 shifts; no owner; high + unack", "yellow"),
    ("      \U0001f310 intel: 194.26.135.12 \u2014 known phishing, 312 reports", "cyan"),
    ("      \U0001f310 intel: finance-secure-login.com \u2014 typosquat domain", "cyan"),
]

FRAME_2 = [
    ("$ sochandoff   # next shift, 8 hours later", "prompt"),
    ("", "plain"),
    ("  SOC SHIFT HANDOFF", "head"),
    ("  Open cases: 5    At-risk of being dropped: 5", "plain"),
    ("", "plain"),
    ("  \u26a0  DROPPED-CASE GUARD \u2014 read these first", "red"),
    ("  ! [SOC-1042] Phishing: credential-harvest to finance", "bold"),
    ("      why flagged: open 5 shifts; no owner; high + unack", "yellow"),
    ("      \U0001f9e0 memory: 194.26.135.12 seen in 1 prior shift", "magenta"),
    ("      \U0001f310 intel: 194.26.135.12 \u2014 known phishing, 312 reports", "cyan"),
]

COLORS = {
    "prompt": "#7ee787",
    "plain": "#c9d1d9",
    "head": "#ffffff",
    "red": "#ff7b72",
    "yellow": "#e3b341",
    "cyan": "#39c5cf",
    "magenta": "#d2a8ff",
    "bold": "#ffffff",
}

CHAR_W = 8.4
LINE_H = 22
PAD = 20
WIDTH = 760
ROWS = max(len(FRAME_1), len(FRAME_2)) + 2
HEIGHT = PAD * 2 + 40 + ROWS * LINE_H


def esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def frame_group(frame, gid, begin, hold, total):
    """A group that is visible only during its slot, via opacity animation."""
    lines = []
    y0 = PAD + 48
    for i, (text, kind) in enumerate(frame):
        if not text:
            continue
        y = y0 + i * LINE_H
        weight = "bold" if kind in ("bold", "head", "red") else "normal"
        lines.append(
            f'<text x="{PAD}" y="{y}" fill="{COLORS[kind]}" '
            f'font-weight="{weight}">{esc(text)}</text>'
        )
    body = "\n      ".join(lines)
    # Visible for its hold window, hidden otherwise; loops forever.
    keytimes = f"0;{begin/total:.3f};{(begin+hold)/total:.3f};1"
    values = "0;1;1;0" if begin > 0 else "1;1;0;0"
    # For the first frame, show immediately; for the second, fade in after.
    if begin == 0:
        keytimes = f"0;{hold/total:.3f};{(hold+0.6)/total:.3f};1"
        values = "1;1;0;0"
    return (
        f'<g opacity="0">{body}'
        f'<animate attributeName="opacity" values="{values}" '
        f'keyTimes="{keytimes}" dur="{total}s" repeatCount="indefinite" '
        f'calcMode="spline" keySplines="0.4 0 0.2 1;0 0 1 1;0.4 0 0.2 1" />'
        f"</g>"
    )


def build() -> str:
    total = 8.0
    hold = 3.6
    header = (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{WIDTH}" '
        f'height="{HEIGHT}" viewBox="0 0 {WIDTH} {HEIGHT}" '
        f'font-family="SFMono-Regular,Consolas,Menlo,monospace" font-size="14">'
    )
    bg = (
        f'<rect width="{WIDTH}" height="{HEIGHT}" rx="10" fill="#0d1117" '
        f'stroke="#30363d"/>'
        f'<rect width="{WIDTH}" height="34" rx="10" fill="#161b22"/>'
        f'<rect y="24" width="{WIDTH}" height="10" fill="#161b22"/>'
        f'<circle cx="22" cy="17" r="6" fill="#ff5f56"/>'
        f'<circle cx="42" cy="17" r="6" fill="#ffbd2e"/>'
        f'<circle cx="62" cy="17" r="6" fill="#27c93f"/>'
        f'<text x="{WIDTH/2}" y="22" fill="#8b949e" font-size="12" '
        f'text-anchor="middle">sochandoff \u2014 SOC shift handoff</text>'
    )
    f1 = frame_group(FRAME_1, "f1", 0.0, hold, total)
    f2 = frame_group(FRAME_2, "f2", hold + 0.6, hold, total)
    return header + bg + f1 + f2 + "</svg>"


def main():
    out = Path(__file__).parent / "demo.svg"
    out.write_text(build())
    print(f"wrote {out} ({out.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
