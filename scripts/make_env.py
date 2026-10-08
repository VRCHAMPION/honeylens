#!/usr/bin/env python3
"""Create .env from .env.example with strong random passwords.

Why: copying .env.example and forgetting to change "change-me" passwords is the
most common beginner mistake. This script fills every *_PASSWORD with 32
random hex characters (128 bits) from Python's ``secrets`` module
(cryptographically secure). It refuses to overwrite an existing .env.

Why hex and not ``token_urlsafe``: the start-up check in
``honeylens.secretcheck`` rejects values that look like placeholders
("xxxx", "todo", "test"...). A random URL-safe token occasionally contains
such a word by chance (CI once generated one with "xXXX" in it) and the stack
would then refuse to start. Hex digits (0-9, a-f) cannot spell any of those
words. The loop also guarantees enough different characters.
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


def new_secret() -> str:
    """32 hex chars that always pass honeylens.secretcheck (no placeholder words, >= 6 distinct chars)."""
    while True:
        value = secrets.token_hex(16)
        if len(set(value)) >= 6:
            return value


lines = []
for line in example.read_text(encoding="utf-8").splitlines():
    key, sep, _ = line.partition("=")
    if sep and key.endswith("_PASSWORD") and not key.startswith("#"):
        line = f"{key}={new_secret()}"
    lines.append(line)
target.write_text("\n".join(lines) + "\n", encoding="utf-8")
with contextlib.suppress(OSError):
    target.chmod(0o600)  # only you can read it (ignored on Windows)
print(f"wrote {target} with random passwords (keep it private; it is git-ignored)")
