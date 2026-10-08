"""``honeylens-report`` / ``python -m honeylens.reporting``: weekly report + IOC exports.

Example::

    honeylens-report --out out/ --days 7 --data all --mask-ips
"""

from __future__ import annotations

import argparse
import sys
from datetime import UTC, datetime
from pathlib import Path

import psycopg

from honeylens.config import Settings
from honeylens.logutil import setup_logging
from honeylens.reporting.data import FILTERS, load
from honeylens.reporting.render import write_all
from honeylens.secretcheck import require_secret


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(prog="honeylens-report", description="Weekly HTML report and IOC exports.")
    parser.add_argument("--out", default="out", help="output folder")
    parser.add_argument("--days", type=int, default=7, help="window length in days (default 7)")
    parser.add_argument("--end", help="window end, ISO time (default: now)")
    parser.add_argument("--data", choices=sorted(FILTERS), default="all", help="all, real or simulated sessions")
    parser.add_argument("--mask-ips", action="store_true", help="mask the last part of every IP (for public sharing)")
    parser.add_argument("--top", type=int, default=10)
    args = parser.parse_args(argv)
    setup_logging()
    if not 1 <= args.days <= 90:
        parser.error("--days must be 1-90")
    end = datetime.now(UTC)
    if args.end:
        end = datetime.fromisoformat(args.end.replace("Z", "+00:00"))
        end = end if end.tzinfo else end.replace(tzinfo=UTC)
    require_secret("HL_DB_PASSWORD")  # fail closed on missing/placeholder password
    settings = Settings()
    with psycopg.connect(settings.dsn()) as conn:
        conn.read_only = True
        data = load(conn, end, args.days, args.data, args.top)
    files = write_all(data, Path(args.out), args.mask_ips, args.days)
    for kind, path in files.items():
        print(f"{kind:9} {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
