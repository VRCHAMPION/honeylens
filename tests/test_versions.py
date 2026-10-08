"""Version pins have ONE source of truth; every other copy must agree with it.

* Image tags live in docker-compose.yml. CI reads them from
  ``docker compose config --images`` (Trivy scan, PostgreSQL service), so the
  workflow must not hard-code any of them again.
* The Python minor in the Dockerfile must be one CI tests, and the lowest CI
  version must be the ``requires-python`` floor (what the README badge claims).
* The Cowrie version quoted in the report must be the image that runs.
"""

import re
import tomllib
from pathlib import Path

import yaml

from honeylens.versions import COWRIE_VERSION

ROOT = Path(__file__).resolve().parents[1]
CI = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")


def _compose_images() -> dict[str, str]:
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text(encoding="utf-8"))
    out = {}
    for svc in compose["services"].values():
        image = svc.get("image", "")
        name, _, tag = image.partition(":")
        out[name] = tag
    return out


def _ci_test_matrix() -> list[str]:
    jobs = yaml.safe_load(CI)["jobs"]
    return [str(v) for v in jobs["test"]["strategy"]["matrix"]["python"]]


def _dockerfile_python_minor() -> str:
    tags = set(re.findall(r"^FROM python:(\d+\.\d+)\.\d+", (ROOT / "Dockerfile").read_text(encoding="utf-8"), re.M))
    assert len(tags) == 1, tags
    return tags.pop()


def test_ci_does_not_hard_code_compose_image_tags():
    for name, tag in _compose_images().items():
        if name == "honeylens":
            continue
        assert f"{name}:{tag}" not in CI, f"ci.yml hard-codes {name}:{tag}; read it from docker compose config --images"
    assert "config --images" in CI


def test_report_cowrie_version_matches_compose_image():
    assert _compose_images()["cowrie/cowrie"] == COWRIE_VERSION
    userdb = (ROOT / "scripts" / "check_cowrie_userdb.py").read_text(encoding="utf-8")
    assert not re.search(r"cowrie/cowrie:\d", userdb), "use the compose image, not a hard-coded tag"


def test_python_versions_agree():
    matrix = _ci_test_matrix()
    runtime = _dockerfile_python_minor()
    assert runtime in matrix, f"Dockerfile runs Python {runtime} but CI tests {matrix}"
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    floor = pyproject["project"]["requires-python"].removeprefix(">=")
    assert min(matrix, key=lambda v: tuple(map(int, v.split(".")))) == floor
    assert pyproject["tool"]["ruff"]["target-version"] == "py" + floor.replace(".", "")
    # single-version jobs (lint, compose) use the runtime version
    for v in re.findall(r'python-version: "(\d+\.\d+)"', CI):
        assert v == runtime
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert f"python-{floor}" in readme and "3.12" in readme  # badge names the tested range
