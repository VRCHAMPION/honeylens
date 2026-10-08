"""Fail closed on missing, short, or placeholder secrets.

Why: a honeypot that starts with ``change-me-admin-password`` is worse than one
that does not start at all. Every HoneyLens program that needs a password calls
:func:`require_secret` before it connects to anything, and the one-shot
``migrate`` service checks ALL secrets (including Grafana's admin password)
before any other service is allowed to start (Compose ``depends_on:
service_completed_successfully``).

A value is rejected when it is:

* missing or empty,
* shorter than ``MIN_LENGTH`` characters,
* one of the exact values shipped in ``.env.example``,
* an obvious placeholder: contains words such as ``change-me``, ``changeme``,
  ``placeholder``, ``example``, ``your-password``, ``todo``, ``replace``,
  ``secret`` or ``password``; is wrapped like ``<...>`` / ``${...}``; or
* low-variety (fewer than 6 distinct characters, e.g. ``aaaaaaaaaaaaaaaa`` or
  ``123412341234``).

``scripts/make_env.py`` generates 24-character random values with
``secrets.token_urlsafe`` which always pass.
"""

from __future__ import annotations

import os
import re

MIN_LENGTH = 12
MIN_DISTINCT = 6

SECRET_ENV_NAMES = (
    "POSTGRES_PASSWORD",
    "HL_PIPELINE_DB_PASSWORD",
    "HL_GRAFANA_DB_PASSWORD",
    "HL_REPORT_DB_PASSWORD",
    "GF_ADMIN_PASSWORD",
)

KNOWN_PLACEHOLDERS = frozenset(
    {
        "change-me-admin-password",
        "change-me-pipeline-password",
        "change-me-grafana-password",
        "change-me-report-password",
        "change-me-grafana-admin",
    }
)

_PLACEHOLDER_WORDS = re.compile(
    r"change[\W_]*me|placeholder|example|your[\W_]*(?:pass|secret|key)|todo|replace|"
    r"secret|password|passw0rd|p@ssw|default|dummy|sample|insert|fixme|xxxx|^admin|^test",
    re.IGNORECASE,
)
_WRAPPED = re.compile(r"^\s*(?:<.*>|\$\{.*\}|\{\{.*\}\}|\[.*\])\s*$")


class SecretError(SystemExit):
    """Raised (exit code 2) when a secret is unsafe. Never includes the value."""

    def __init__(self, message: str) -> None:
        super().__init__(2)
        self.message = message

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.message


def problem(value: str | None) -> str | None:
    """Return why ``value`` is unsafe, or ``None`` when it is acceptable."""
    if value is None or not value.strip():
        return "is missing or empty"
    v = value.strip()
    if v.lower() in KNOWN_PLACEHOLDERS:
        return "is still the placeholder from .env.example"
    if len(v) < MIN_LENGTH:
        return f"is shorter than {MIN_LENGTH} characters"
    if _WRAPPED.match(v) or _PLACEHOLDER_WORDS.search(v):
        return "looks like a placeholder"
    if len(set(v)) < MIN_DISTINCT:
        return f"uses fewer than {MIN_DISTINCT} different characters"
    return None


def require_secret(name: str, value: str | None = None) -> str:
    """Return the secret or stop the program with a clear (value-free) message."""
    if value is None:
        value = os.environ.get(name)
    why = problem(value)
    if why:
        msg = f"refusing to start: {name} {why}. Run: python scripts/make_env.py --force"
        print(msg)
        raise SecretError(msg)
    return str(value).strip()


def require_all(names: tuple[str, ...] = SECRET_ENV_NAMES) -> None:
    """Check every secret; report all problems at once, then fail."""
    bad = [f"{n} {why}" for n in names if (why := problem(os.environ.get(n)))]
    if bad:
        msg = "refusing to start, unsafe secrets: " + "; ".join(bad) + ". Run: python scripts/make_env.py --force"
        print(msg)
        raise SecretError(msg)
