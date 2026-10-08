"""Structured (JSON) logging.

Why JSON logs: one event per line with named fields is easy to search with
``jq`` or ``grep`` and easy to ship to a log platform later. Attacker text is
never put in log messages, only counts and IDs, so logs stay safe to view.
"""

from __future__ import annotations

import json
import logging
import os
import sys
from datetime import UTC, datetime

_STD = set(vars(logging.LogRecord("", 0, "", 0, "", None, None)).keys()) | {"message", "asctime"}


class JsonFormatter(logging.Formatter):
    """Format a log record as one JSON object per line."""

    def format(self, record: logging.LogRecord) -> str:
        """Render the record, including any ``extra={...}`` fields."""
        data: dict[str, object] = {
            "ts": datetime.fromtimestamp(record.created, UTC).isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in vars(record).items():
            if key not in _STD:
                data[key] = value
        if record.exc_info:
            data["exc"] = self.formatException(record.exc_info)
        return json.dumps(data, default=str)


def setup_logging() -> None:
    """Configure the root logger once (level from HL_LOG_LEVEL, default INFO)."""
    root = logging.getLogger()
    if any(isinstance(h.formatter, JsonFormatter) for h in root.handlers):
        return
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    root.handlers = [handler]
    root.setLevel(os.environ.get("HL_LOG_LEVEL", "INFO").upper())
