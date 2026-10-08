#!/usr/bin/env python3
"""Create .env from .env.example with strong random passwords.

Why: copying .env.example and forgetting to change "change-me" passwords is the
most common beginner mistake. This script fills every *_PASSWORD with 24
random URL-safe characters from Python's ``secrets`` module (cryptographically
secure). It refuses to overwrite an existing .env.
"""

from __future__ import annotations

import contextlib
import secrets
import sys
from pathlib import Path

root = Path(__file__).resolve().parents[1]
example, target = root / ".env.example", root / ".env"
if target.exists() and "--force" not in sys.argv:
    sys.exit(".env already exists (use --force to replace it)")
lines = []
for line in example.read_text(encoding="utf-8").splitlines():
    key, sep, _ = line.partition("=")
    if sep and key.endswith("_PASSWORD") and not key.startswith("#"):
        line = f"{key}={secrets.token_urlsafe(18)}"
    lines.append(line)
target.write_text("\n".join(lines) + "\n", encoding="utf-8")
with contextlib.suppress(OSError):
    target.chmod(0o600)  # only you can read it (ignored on Windows)
print(f"wrote {target} with random passwords (keep it private; it is git-ignored)")
