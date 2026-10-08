#!/usr/bin/env python3
"""Fail if a release ZIP, a folder, or test evidence could leak a real secret.

Checks (each one prints a line and the script exits 1 on any finding):
  1. no ``.env`` file (``.env.example`` is allowed: it only holds placeholders);
  2. no private key material (PEM/OpenSSH/PuTTY private keys, Cowrie/sshd host keys);
  3. no GeoIP database or other captured/generated artefacts that must not ship;
  4. none of the *actual* secret values from a local ``.env`` (``--env``) appears in any file,
     so generated passwords cannot slip into logs, screenshots' HTML, or evidence;
  5. no evidence/CI file contains output of a plain ``docker compose config`` (which prints
     resolved secrets). Validation must use ``docker compose config -q``.

Values are never printed: a finding names the file and the variable, not the secret.

Usage:
  python scripts/check_secrets_exposure.py honeylens-project.zip --env .env
  python scripts/check_secrets_exposure.py .            # a folder (add --allow-local-env to skip the
                                                        #  git-ignored .env, out/, geoip/ ...)
"""
from __future__ import annotations

import argparse
import re
import sys
import zipfile
from pathlib import Path, PurePosixPath

# Built from two parts so this file does not match its own pattern.
PRIVATE_KEY_RE = re.compile(
    rb"-----BEGIN (?:RSA |DSA |EC |OPENSSH |ENCRYPTED |)PRIVATE" + rb" KEY-----|PuTTY-User" + rb"-Key-File-"
)
FORBIDDEN_NAMES = re.compile(
    r"(^|/)(\.env(\..*)?|id_rsa.*|id_ed25519.*|id_ecdsa.*|ssh_host_[a-z0-9]+_key|.*\.(pem|key|p12|pfx|p7b|p7c|p7m|p7s|p8|p10|jks|keystore|ppk|crt|cer|der)"
    r"|.*\.mmdb(\.gz)?|.*\.(db|sqlite|sqlite3|log|pcap|zip|tar|tgz|gz|7z|rar)|.*\.tfstate(\.backup)?|\.coverage|\.git/.*)$",
    re.IGNORECASE,
)
# Lines that only a plain "docker compose config" prints for our services.
COMPOSE_DUMP_RE = re.compile(rb"^\s*POSTGRES_PASSWORD:\s*\S+|^\s*GF_SECURITY_ADMIN_PASSWORD:\s*\S+", re.M)
SECRET_KEY_HINT = re.compile(r"(PASSWORD|SECRET|TOKEN|KEY)", re.I)
SKIP_DIRS = {".venv", "venv", "__pycache__", ".pytest_cache", ".ruff_cache", "node_modules", ".terraform"}
# Git-ignored local artefacts that scripts/package.sh never ships (skipped with --allow-local-env).
LOCAL_ONLY = {".env", ".coverage", ".git", "out", "geoip", "backups", "captures", "htmlcov", "build", "dist"}
MIN_SECRET_LEN = 8


def load_env_secrets(path: Path) -> dict[str, str]:
    """Return {VAR: value} for secret-looking variables in a .env file."""
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, val = line.partition("=")
        key, val = key.strip(), val.strip().strip("'\"")
        if SECRET_KEY_HINT.search(key) and len(val) >= MIN_SECRET_LEN:
            out[key] = val
    return out


def iter_files(target: Path, allow_local_env: bool):
    """Yield (relative posix name, bytes) for every file in a ZIP or folder."""
    if target.is_file() and zipfile.is_zipfile(target):
        with zipfile.ZipFile(target) as zf:
            for info in zf.infolist():
                if not info.is_dir():
                    yield info.filename, zf.read(info)
        return
    for p in sorted(target.rglob("*")):
        if not p.is_file() or any(part in SKIP_DIRS for part in p.relative_to(target).parts):
            continue
        rel = p.relative_to(target).as_posix()
        if allow_local_env and rel.split("/", 1)[0] in LOCAL_ONLY:
            continue
        yield rel, p.read_bytes()


def scan(target: Path, secrets: dict[str, str], allow_local_env: bool = False) -> list[str]:
    findings: list[str] = []
    needles = {k: v.encode() for k, v in secrets.items()}
    for name, data in iter_files(target, allow_local_env):
        pure = PurePosixPath(name)
        stem = "/".join(pure.parts[1:]) if pure.parts and pure.parts[0] == "honeylens" else name
        if FORBIDDEN_NAMES.search(stem) and PurePosixPath(stem).name != ".env.example":
            findings.append(f"forbidden file in package: {name}")
        if PRIVATE_KEY_RE.search(data):
            findings.append(f"private key material: {name}")
        for var, needle in needles.items():
            if needle in data:
                findings.append(f"value of {var} from the local .env appears in: {name}")
        if "test-evidence/" in name and COMPOSE_DUMP_RE.search(data):
            findings.append(f"resolved 'docker compose config' output (secrets) in evidence: {name}")
    return findings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("target", type=Path, help="release ZIP or folder")
    ap.add_argument("--env", type=Path, help="local .env whose real values must not appear anywhere")
    ap.add_argument("--allow-local-env", action="store_true",
                    help="working-tree scan: skip git-ignored local files that package.sh never ships (.env, out/, ...)")
    args = ap.parse_args(argv)
    secrets = load_env_secrets(args.env) if args.env and args.env.exists() else {}
    findings = scan(args.target, secrets, args.allow_local_env)
    for f in findings:
        print("FAIL:", f)
    if findings:
        return 1
    print(f"PASS: {args.target} - no .env, no private keys, no forbidden files, "
          f"none of {len(secrets)} local secret values found, no resolved compose config in evidence")
    return 0


if __name__ == "__main__":
    sys.exit(main())
