"""Missing or placeholder secrets must stop HoneyLens (fail closed)."""
import secrets
import subprocess
import sys
from pathlib import Path

import pytest

from honeylens.secretcheck import KNOWN_PLACEHOLDERS, SECRET_ENV_NAMES, SecretError, problem, require_all, require_secret

ROOT = Path(__file__).resolve().parents[1]


def test_missing_secret_fails(monkeypatch):
    monkeypatch.delenv("HL_DB_PASSWORD", raising=False)
    with pytest.raises(SecretError) as e:
        require_secret("HL_DB_PASSWORD")
    assert e.value.code == 2
    assert problem("") and problem("   ") and problem(None)


@pytest.mark.parametrize("value", sorted(KNOWN_PLACEHOLDERS))
def test_known_placeholders_fail(value):
    assert problem(value)
    assert problem(value.upper())


def test_every_example_password_is_known_placeholder():
    for line in (ROOT / ".env.example").read_text().splitlines():
        key, sep, val = line.partition("=")
        if sep and key.endswith("_PASSWORD"):
            assert val in KNOWN_PLACEHOLDERS, key
            assert problem(val)


@pytest.mark.parametrize("value", [
    "changeme123456", "CHANGE_ME_please_now", "<your-db-password>", "${POSTGRES_PASSWORD}",
    "password123456", "MySecret-value-99", "placeholder-value-1", "example-example-1",
    "todo-set-this-later", "aaaaaaaaaaaaaaaa", "121212121212121212", "short1!", "replace_me_with_real",
    "default-pass-word1", "xxxxxxxxxxxxxxxxxx", "{{ db_pass }}", "admin12345678",
])
def test_obvious_placeholders_fail(value):
    assert problem(value), value


def test_generated_secrets_pass(monkeypatch):
    for _ in range(500):  # same generator as scripts/make_env.py
        v = secrets.token_urlsafe(18)
        assert problem(v) is None, v
    good = secrets.token_urlsafe(18)
    monkeypatch.setenv("HL_DB_PASSWORD", good)
    assert require_secret("HL_DB_PASSWORD") == good


def test_require_all_reports_every_bad_name_without_values(monkeypatch, capsys):
    for n in SECRET_ENV_NAMES:
        monkeypatch.setenv(n, secrets.token_urlsafe(18))
    require_all()
    monkeypatch.setenv("GF_ADMIN_PASSWORD", "change-me-grafana-admin")
    monkeypatch.delenv("HL_REPORT_DB_PASSWORD")
    with pytest.raises(SecretError) as e:
        require_all()
    msg = str(e.value.message)
    assert "GF_ADMIN_PASSWORD" in msg and "HL_REPORT_DB_PASSWORD" in msg
    assert "change-me-grafana-admin" not in msg  # never echo the value


def test_make_env_output_passes(tmp_path):
    """scripts/make_env.py (the beginner path) must produce a .env that passes."""
    repo = tmp_path / "r"
    (repo / "scripts").mkdir(parents=True)
    (repo / ".env.example").write_text((ROOT / ".env.example").read_text())
    (repo / "scripts" / "make_env.py").write_text((ROOT / "scripts" / "make_env.py").read_text())
    subprocess.run([sys.executable, str(repo / "scripts" / "make_env.py")], check=True, capture_output=True)  # noqa: S603
    vals = dict(line.split("=", 1) for line in (repo / ".env").read_text().splitlines()
                if "=" in line and not line.startswith("#"))
    for n in SECRET_ENV_NAMES:
        assert problem(vals[n]) is None, n


@pytest.mark.parametrize("entry", ["honeylens.pipeline.runner", "honeylens.reporting.cli"])
def test_programs_refuse_placeholder(entry, monkeypatch):
    import importlib
    mod = importlib.import_module(entry)
    monkeypatch.setenv("HL_DB_PASSWORD", "change-me-pipeline-password")
    monkeypatch.setenv("HL_DB_HOST", "192.0.2.1")  # never reached: we must fail before connecting
    with pytest.raises(SystemExit) as e:
        mod.main(["--out", "/nonexistent"] if entry.endswith("cli") else [])
    assert e.value.code == 2


def test_migrate_refuses_placeholder(monkeypatch):
    from honeylens import migrate
    for n in SECRET_ENV_NAMES:
        monkeypatch.setenv(n, secrets.token_urlsafe(18))
    monkeypatch.setenv("POSTGRES_PASSWORD", "change-me-admin-password")
    monkeypatch.setenv("HL_DB_HOST", "192.0.2.1")
    with pytest.raises(SystemExit) as e:
        migrate.main()
    assert e.value.code == 2
