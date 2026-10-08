#!/usr/bin/env python3
"""Capture 1920x1080 PNG screenshots of the five dashboards (+ the HTML report).

Needs: pip install playwright, plus a Chromium (``playwright install chromium``
or a system Chromium via --chromium /usr/bin/chromium).

    python scripts/capture_screenshots.py --out docs/screenshots
    python scripts/capture_screenshots.py --report docs/samples/weekly-report.html
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parents[1]
BOARDS = [
    ("hl-soc-overview", "01-soc-overview.png"),
    ("hl-creds-commands", "02-credentials-commands.png"),
    ("hl-attack-behaviour", "03-attack-behaviour.png"),
    ("hl-session-explorer", "04-session-explorer.png"),
    ("hl-pipeline-health", "05-pipeline-health.png"),
]


def env_file() -> dict[str, str]:
    out: dict[str, str] = {}
    p = ROOT / ".env"
    if p.exists():
        for line in p.read_text(encoding="utf-8").splitlines():
            k, sep, v = line.partition("=")
            if sep and not k.startswith("#"):
                out[k.strip()] = v.strip()
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:3000")
    ap.add_argument("--out", default=str(ROOT / "docs" / "screenshots"))
    ap.add_argument("--chromium", default=os.environ.get("HL_CHROMIUM", ""))
    ap.add_argument("--report", help="also screenshot this HTML report file")
    ap.add_argument("--range", default="now-7d")
    args = ap.parse_args()
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    env = env_file()
    for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
        os.environ.pop(k, None)
    with sync_playwright() as pw:
        launch = {"executable_path": args.chromium} if args.chromium else {}
        browser = pw.chromium.launch(args=["--no-proxy-server", "--disable-dev-shm-usage"], **launch)
        page = browser.new_page(viewport={"width": 1920, "height": 1080}, timezone_id="Asia/Kolkata")
        page.goto(f"{args.url}/login")
        page.fill("input[name='user']", env.get("GF_ADMIN_USER", "admin"))
        page.fill("input[name='password']", env.get("GF_ADMIN_PASSWORD", ""))
        page.click("button[type='submit']")
        page.wait_for_url("**/*", timeout=30000)
        page.wait_for_timeout(2000)
        for uid, name in BOARDS:
            page.goto(f"{args.url}/d/{uid}?orgId=1&from={args.range}&to=now&var-data=all&kiosk")
            page.wait_for_load_state("networkidle", timeout=60000)
            page.wait_for_timeout(5000)  # let panels finish rendering
            page.screenshot(path=str(out / name), full_page=False)
            print("saved", out / name)
        if args.report:
            page.goto(Path(args.report).resolve().as_uri())
            page.wait_for_timeout(1500)
            page.screenshot(path=str(out / "06-weekly-report.png"), full_page=False)
            print("saved", out / "06-weekly-report.png")
        browser.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
