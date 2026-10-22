"""HL_IGNORE_IPS: the operator's own test IPs are kept but hidden from reports, exports and dashboards."""

import json

import psycopg
import pytest

from honeylens.config import Settings, ip_in, parse_networks
from honeylens.reporting import exports
from honeylens.reporting.data import load
from tests.conftest import role_dsn
from tests.test_ioc_commands import END, IGNORED, ioc_db  # noqa: F401  (fixture)
from tests.test_pipeline_db import q


def test_parse_networks_ips_and_cidrs():
    nets = parse_networks("192.0.2.10, 198.51.100.0/24 2001:db8::1")
    assert ip_in("192.0.2.10", nets) and ip_in("198.51.100.77", nets) and ip_in("2001:db8::1", nets)
    assert not ip_in("192.0.2.11", nets) and not ip_in(None, nets) and not ip_in("nope", nets)
    assert parse_networks("") == ()


def test_bad_entry_fails_loudly(monkeypatch):
    monkeypatch.setenv("HL_IGNORE_IPS", "192.0.2.1, not-an-ip")
    with pytest.raises(ValueError, match="not-an-ip"):
        _ = Settings().ignore_networks


@pytest.mark.db
def test_ignored_session_kept_but_flagged(ioc_db):  # noqa: F811
    migrated, _ = ioc_db
    assert q(migrated, "SELECT count(*) FROM honeylens.sessions WHERE src_ip = %s", IGNORED)[0][0] == 1
    assert q(migrated, "SELECT count(*) FROM honeylens.raw_events WHERE src_ip = %s", IGNORED)[0][0] == 3
    assert q(migrated, "SELECT session_id FROM honeylens.ignored_sessions") == [("mine01",)]
    assert q(migrated, "SELECT count(*) FROM honeylens.real_sessions WHERE src_ip = %s", IGNORED)[0][0] == 0


@pytest.mark.db
def test_reports_and_exports_exclude_ignored(ioc_db):  # noqa: F811
    _, d = ioc_db
    assert d.totals["sessions"] == 2 and d.totals["unique_ips"] == 2
    assert all(r["ip"] != IGNORED for r in d.ips + d.ioc_ips)
    assert all(s["session_id"] != "mine01" for s in d.notable)
    assert all("mytest" not in c["command"] for c in d.commands)
    assert IGNORED not in exports.to_csv(d) and IGNORED not in json.dumps(exports.to_stix(d))


@pytest.mark.db
def test_report_reads_ignore_list_from_env(ioc_db, monkeypatch):  # noqa: F811
    migrated, _ = ioc_db
    monkeypatch.setenv("HL_SENSOR_IP", "192.0.2.5")
    with psycopg.connect(role_dsn(migrated, "hl_report")) as conn:
        d = load(conn, END, 7, "all")
    assert not [r for r in d.ioc_cmd if r["value"] == "192.0.2.5"]


@pytest.mark.db
def test_dashboard_filter_sql_hides_ignored(ioc_db):  # noqa: F811
    import importlib.util

    from tests.conftest import ROOT
    spec = importlib.util.spec_from_file_location("build_dashboards", ROOT / "scripts" / "build_dashboards.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    migrated, _ = ioc_db
    where = mod.sim().replace("${data:sqlstring}", "'all'")
    with psycopg.connect(role_dsn(migrated, "hl_grafana")) as c:
        ips = {r[0] for r in c.execute(f"SELECT host(src_ip) FROM honeylens.sessions WHERE {where}").fetchall()}
        cmds = c.execute(f"SELECT count(*) FROM honeylens.commands WHERE {where} AND command LIKE '%%mytest%%'").fetchone()[0]
    assert IGNORED not in ips and ips and cmds == 0
