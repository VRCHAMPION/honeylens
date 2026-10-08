"""cowrie/userdb.txt must allow ONLY a fixed, documented list of fake credentials."""
from pathlib import Path

from honeylens.simulator.personas import PERSONAS
from honeylens.simulator.synthetic import _success

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {("root", "admin123"), ("root", "xc3511"), ("admin", "admin"), ("ubuntu", "ubuntu"), ("pi", "raspberry")}


def _entries() -> list[tuple[str, str]]:
    out = []
    for raw in (ROOT / "cowrie" / "userdb.txt").read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        user, _uid, pw = line.split(":", 2)
        out.append((user, pw))
    return out


def test_no_wildcard_regex_or_deny_lines():
    for user, pw in _entries():
        assert "*" not in (user, pw), f"wildcard found: {user}:{pw}"
        assert not pw.startswith("!"), "deny lines are not needed when nothing is wildcarded"
        assert not (pw.startswith("/") and pw.endswith("/")), "regex passwords are not allowed"
        assert pw, "empty password not allowed"


def test_exact_fixed_list():
    assert set(_entries()) == EXPECTED
    assert len(_entries()) == len(EXPECTED)


def test_list_is_documented():
    text = (ROOT / "cowrie" / "README.md").read_text() + (ROOT / "RUN_ON_LAPTOP.md").read_text()
    for user, pw in EXPECTED:
        assert f"{user}" in text and f"{pw}" in text, f"{user}/{pw} missing from docs"
    assert "any password works" not in (ROOT / "RUN_ON_LAPTOP.md").read_text()


def test_synthetic_mirror_matches_userdb():
    assert all(_success(PERSONAS[0], u, p) for u, p in EXPECTED)
    for u, p in [("root", "root"), ("root", "toor"), ("root", "anything"), ("admin", "password"), ("x", "y")]:
        assert not _success(PERSONAS[0], u, p)
