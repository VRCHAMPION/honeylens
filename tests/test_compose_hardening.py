"""Every Compose service follows the hardening rules (long-running vs one-shot)."""
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
LONG_RUNNING = {"postgres", "cowrie", "pipeline", "grafana", "report-scheduler"}
ONE_SHOT = {"migrate", "simulator", "synthetic", "report"}
GOOD = "Zq8vN3kLp2Xw7RtY4mBs9Cd1"


@pytest.fixture(scope="module")
def services():
    if not shutil.which("docker"):
        pytest.skip("docker CLI not installed")
    env = {"PATH": os.environ["PATH"], "POSTGRES_USER": "u", "POSTGRES_PASSWORD": GOOD,
           "HL_PIPELINE_DB_PASSWORD": GOOD, "HL_GRAFANA_DB_PASSWORD": GOOD,
           "HL_REPORT_DB_PASSWORD": GOOD, "GF_ADMIN_PASSWORD": GOOD}
    out = subprocess.run(["docker", "compose", "--profile", "sim", "--profile", "tools", "config"],  # noqa: S603,S607
                         cwd=ROOT, env=env, capture_output=True, text=True, check=True).stdout
    return yaml.safe_load(out)["services"]


def test_service_groups_are_complete(services):
    assert set(services) == LONG_RUNNING | ONE_SHOT


@pytest.mark.parametrize("name", sorted(LONG_RUNNING | ONE_SHOT))
def test_common_hardening(services, name):
    s = services[name]
    assert "no-new-privileges:true" in s.get("security_opt", [])
    assert s.get("cap_drop") == ["ALL"]
    assert not s.get("privileged")
    assert s.get("network_mode") != "host"
    assert s["logging"]["driver"] == "json-file"
    assert s["logging"]["options"]["max-size"] and s["logging"]["options"]["max-file"]
    lim = s["deploy"]["resources"]["limits"]
    assert lim.get("cpus") and lim.get("memory") and lim.get("pids")
    for v in s.get("volumes", []):
        assert "docker.sock" not in str(v.get("source", ""))
    if name != "postgres":  # postgres' entrypoint must chown its data folder first
        assert s.get("read_only") is True, name
        assert s.get("cap_add") in (None, []), name


@pytest.mark.parametrize("name", sorted(LONG_RUNNING))
def test_long_running_have_healthcheck_and_restart(services, name):
    s = services[name]
    assert s.get("healthcheck", {}).get("test"), name
    assert s.get("restart") == "unless-stopped"


@pytest.mark.parametrize("name", sorted(ONE_SHOT))
def test_one_shots_do_not_restart_or_healthcheck(services, name):
    s = services[name]
    assert s.get("restart") == "no"
    assert "healthcheck" not in s or s["healthcheck"].get("disable")


def test_non_root_users(services):
    assert services["cowrie"]["user"] == "999:999"
    assert services["grafana"]["user"].startswith("472")
    # honeylens image runs as UID 10001 (Dockerfile USER); report overrides with the host UID
    assert "USER 10001:10001" in (ROOT / "Dockerfile").read_text()


def test_only_postgres_adds_capabilities_and_only_minimum(services):
    assert set(services["postgres"]["cap_add"]) == {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"}
