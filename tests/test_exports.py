"""Standalone export safety tests that do not need PostgreSQL."""

import csv
import io
from datetime import UTC, datetime

import pytest

from honeylens.reporting.data import ReportData, Window
from honeylens.reporting.exports import to_csv


@pytest.mark.parametrize("value", [
    "=1+1",
    " +cmd|' /C calc'!A0",
    "\t@SUM(1,1)",
    "\ufeff-1+1",
    "\r\n=1+1",
])
def test_csv_url_values_cannot_start_spreadsheet_formulas(value):
    now = datetime(2026, 10, 1, tzinfo=UTC)
    data = ReportData(
        window=Window(now, now),
        data_filter="simulated",
        ioc_urls=[{
            "url": value,
            "attempts": 1,
            "first_seen": now,
            "last_seen": now,
            "simulated": True,
        }],
    )

    rows = list(csv.reader(io.StringIO(to_csv(data))))

    assert rows[1][1].startswith("'")
