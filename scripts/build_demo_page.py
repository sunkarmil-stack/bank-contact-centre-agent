"""Build the shareable stakeholder demo page from the recording.

    python -m scripts.record_demo        # 1. record real runs from the agent service
    python -m scripts.build_demo_page    # 2. write static/demo_page.html (replay mode)

``static/demo_page.html`` is a self-contained page (no backend needed) that
replays the recorded runs. Open it in a browser, or publish it as a link.
``--wrap`` adds a full HTML document wrapper for opening straight from disk.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"


def build(wrap: bool) -> Path:
    data = json.loads((STATIC / "demo_recording.json").read_text())
    data["mode"] = "replay"
    payload = json.dumps(data, default=str).replace("</", "<\\/")
    page = (STATIC / "console.html").read_text().replace("__CONSOLE_DATA__", payload)
    if wrap:
        page = ('<!doctype html><html lang="en"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width, initial-scale=1"></head><body>'
                + page + "</body></html>")
    out = STATIC / "demo_page.html"
    out.write_text(page)
    return out


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--wrap", action="store_true", help="add <html>/<head>/<body> for opening from disk")
    out = build(ap.parse_args().wrap)
    print(f"wrote {out} ({out.stat().st_size // 1024} KB)")
