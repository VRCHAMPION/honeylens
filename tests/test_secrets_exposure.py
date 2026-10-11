"""The release/evidence secret-exposure check (scripts/check_secrets_exposure.py)."""
from __future__ import annotations

import importlib.util
import zipfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("cse", ROOT / "scripts" / "check_secrets_exposure.py")
cse = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cse)

SECRET = "Zq7-generated-Secret-9xPw2"  # test-only value  # gitleaks:allow
FAKE_KEY = b"-----BEGIN OPENSSH " + b"PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n"


def make_zip(tmp_path: Path, files: dict[str, bytes]) -> Path:
    z = tmp_path / "pkg.zip"
    with zipfile.ZipFile(z, "w") as zf:
        for name, data in files.items():
            zf.writestr(f"honeylens/{name}", data)
    return z


@pytest.fixture
def env_file(tmp_path: Path) -> Path:
    p = tmp_path / "local.env"
    p.write_text(f"POSTGRES_PASSWORD={SECRET}\nHL_BATCH_SIZE=500\nGF_ADMIN_PASSWORD=short\n")
    return p


def test_clean_zip_passes(tmp_path, env_file):
    z = make_zip(tmp_path, {"README.md": b"hello", ".env.example": b"POSTGRES_PASSWORD=change-me"})
    assert cse.main([str(z), "--env", str(env_file)]) == 0


def test_env_file_in_zip_fails(tmp_path):
    z = make_zip(tmp_path, {".env": b"X=1"})
    assert any(".env" in f for f in cse.scan(z, {}))


def test_env_example_allowed(tmp_path):
    assert cse.scan(make_zip(tmp_path, {".env.example": b"A=change-me"}), {}) == []


@pytest.mark.parametrize("name", ["id_rsa", "deploy/ssh_host_ed25519_key", "certs/server.pem",
                                  "geoip/dbip-city-lite.mmdb", ".git/config", ".coverage",
                                  ".env.production", "deploy/.env.staging", "db/local.sqlite3",
                                  "logs/pipeline.log", "archive.zip", "terraform.tfstate",
                                  "certs/server.crt", "keys/id_ed25519.ppk"])
def test_forbidden_names_fail(tmp_path, name):
    assert cse.scan(make_zip(tmp_path, {name: b"x"}), {})


def test_private_key_content_fails(tmp_path):
    f = cse.scan(make_zip(tmp_path, {"docs/notes.txt": FAKE_KEY}), {})
    assert f and "private key" in f[0]


def test_generated_secret_value_in_evidence_fails_and_is_not_printed(tmp_path, env_file, capsys):
    z = make_zip(tmp_path, {"docs/test-evidence/run.log": f"connecting with {SECRET}".encode()})
    assert cse.main([str(z), "--env", str(env_file)]) == 1
    out = capsys.readouterr().out
    assert "POSTGRES_PASSWORD" in out and SECRET not in out


def test_short_or_non_secret_values_ignored(env_file):
    secrets = cse.load_env_secrets(env_file)
    assert set(secrets) == {"POSTGRES_PASSWORD"}  # 'short' < 8 chars, batch size not a secret


def test_resolved_compose_config_in_evidence_fails(tmp_path):
    dump = b"services:\n  postgres:\n    environment:\n      POSTGRES_PASSWORD: " + b"x" * 13 + b"\n"  # built, not a literal
    assert cse.scan(make_zip(tmp_path, {"docs/test-evidence/compose.log": dump}), {})


def test_folder_scan_skips_only_top_level_env_when_allowed(tmp_path):
    (tmp_path / ".env").write_text("POSTGRES_PASSWORD=x")
    (tmp_path / ".env.production").write_text("POSTGRES_PASSWORD=local-only")
    assert cse.scan(tmp_path, {}, allow_local_env=True) == ["forbidden file in package: .env.production"]


def test_env_example_is_allowed_but_other_env_variants_are_not(tmp_path):
    (tmp_path / ".env.example").write_text("POSTGRES_PASSWORD=change-me")
    (tmp_path / ".env.local").write_text("POSTGRES_PASSWORD=secret")
    assert cse.scan(tmp_path, {}, allow_local_env=True) == ["forbidden file in package: .env.local"]


def test_repository_tree_is_clean():
    """The shipped tree itself: no forbidden files, keys, or compose dumps (local .env ignored)."""
    assert cse.scan(ROOT, {}, allow_local_env=True) == []


def test_validation_commands_use_quiet_compose_config():
    """CI and scripts must validate with 'docker compose config -q', never dump resolved config."""
    import re
    texts = [(ROOT / ".github/workflows/ci.yml").read_text(), (ROOT / "scripts/package.sh").read_text()]
    for t in texts:
        for m in re.finditer(r"docker compose[^\n|]*\bconfig\b([^\n]*)", t):
            line = m.group(0)
            # --images prints image names only (used to derive scan/service images).
            assert re.search(r"(\s-q\b|--quiet|--format json|--images\b)", line), line


def test_precommit_secret_hook_uses_working_gitleaks_and_env_rules():
    config = (ROOT / ".pre-commit-config.yaml").read_text()
    assert "rev: v8.30.0" in config
    assert "rev: v8.30.1" not in config
    assert ".env.*" in config and ".env.example" in config and "*.ppk" in config
