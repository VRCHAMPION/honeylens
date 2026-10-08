"""Command-line interface: ``python -m honeylens.simulator`` / ``honeylens-simulator``.

Examples::

    # 16 real SSH sessions against Cowrie on your laptop (loopback only)
    python -m honeylens.simulator live --target 127.0.0.1 --port 2222 --sessions 16

    # 14 days of deterministic fake events
    python -m honeylens.simulator synthetic --seed 42 --days 14 --out synthetic.json
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from datetime import UTC, datetime

from honeylens.logutil import setup_logging
from honeylens.simulator.guard import TargetNotAllowed
from honeylens.simulator.personas import PERSONAS


def _parse_end(value: str | None) -> datetime:
    if not value:
        # Default: the current hour (UTC). Pass --end for byte-identical output.
        return datetime.now(UTC).replace(minute=0, second=0, microsecond=0)
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def main(argv: list[str] | None = None) -> int:
    """Entry point."""
    parser = argparse.ArgumentParser(prog="honeylens-simulator", description="Safe local attack simulator.")
    sub = parser.add_subparsers(dest="mode", required=True)

    live = sub.add_parser("live", help="real SSH sessions against an allowed local target")
    live.add_argument("--target", default="127.0.0.1")
    live.add_argument("--port", type=int, default=2222)
    live.add_argument("--sessions", type=int, default=8)
    live.add_argument("--seed", type=int, default=7)
    live.add_argument("--speed", type=float, default=1.0, help=">1 = faster (shorter pauses)")
    live.add_argument("--persona", action="append", help="limit to persona name(s)")

    syn = sub.add_parser("synthetic", help="write deterministic Cowrie-format JSON lines")
    syn.add_argument("--seed", type=int, default=42)
    syn.add_argument("--days", type=int, default=14)
    syn.add_argument("--sessions-per-day", type=int, default=60)
    syn.add_argument("--end", help="ISO time the data ends at (default: current UTC hour)")
    syn.add_argument("--out", default="synthetic.json")

    sub.add_parser("personas", help="list personas")
    args = parser.parse_args(argv)
    setup_logging()

    if args.mode == "personas":
        for p in PERSONAS:
            print(f"{p.name:22} {p.style:6} {p.description}")
        return 0
    if args.mode == "synthetic":
        if not 1 <= args.days <= 365 or not 1 <= args.sessions_per_day <= 10000:
            parser.error("days must be 1-365 and sessions-per-day 1-10000")
        from honeylens.simulator.synthetic import write

        n = write(args.out, args.seed, args.days, _parse_end(args.end), args.sessions_per_day)
        digest = hashlib.sha256(open(args.out, "rb").read()).hexdigest()  # noqa: SIM115
        print(f"wrote {n} events to {args.out} sha256={digest}")
        return 0
    if not 1 <= args.sessions <= 1000:
        parser.error("sessions must be 1-1000")
    from honeylens.simulator.live import run_live

    try:
        results = run_live(args.target, args.port, args.sessions, args.seed, args.speed, args.persona)
    except TargetNotAllowed as exc:
        print(f"REFUSED: {exc}", file=sys.stderr)
        return 2
    ok = sum(r.connected for r in results)
    logged = sum(r.logged_in for r in results)
    cmds = sum(r.commands_sent for r in results)
    print(f"live: {len(results)} sessions, {ok} connected, {logged} logged in, {cmds} commands sent")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
