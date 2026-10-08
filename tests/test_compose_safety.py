import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("check_ports", ROOT / "scripts" / "check_ports.py")
cp = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cp)


def svc(ports=None, **kw):
    d = {"ports": ports or []}
    d.update(kw)
    return d


def test_static_checker_flags_bad_configs(tmp_path):
    f = tmp_path / "c.yml"
    f.write_text("services: {}\n")
    bad = {"services": {
        "cowrie": svc([{"host_ip": "0.0.0.0", "target": 2222, "published": "2222"}]),
        "postgres": svc([{"host_ip": "127.0.0.1", "target": 5432, "published": "5432"}]),
        "x": svc(network_mode="host", privileged=True, volumes=[{"source": "/var/run/docker.sock", "target": "/s"}]),
    }}
    problems = "\n".join(cp.check_static(bad, [str(f)], cp.ALLOWED, True))
    for needle in ("127.0.0.1", "postgres", "host", "privileged", "socket"):
        assert needle in problems
    f.write_text("version: '3'\nservices: {}\n")
    assert any("version" in p for p in cp.check_static({"services": {}}, [str(f)], cp.ALLOWED, True))


@pytest.mark.skipif(not shutil.which("docker"), reason="docker CLI not installed")
def test_real_compose_files_pass():
    for args in (["scripts/check_ports.py"],
                 ["scripts/check_ports.py", "-f", "docker-compose.yml", "-f", "docker-compose.cloud.yml", "--cloud"]):
        r = subprocess.run(["python3", *args], cwd=ROOT, capture_output=True, text=True,
                           env={"PATH": "/usr/bin:/bin:/usr/local/bin", "POSTGRES_USER": "u", "POSTGRES_PASSWORD": "p",
                                "HL_PIPELINE_DB_PASSWORD": "x" * 12, "HL_GRAFANA_DB_PASSWORD": "x" * 12,
                                "HL_REPORT_DB_PASSWORD": "x" * 12, "GF_ADMIN_PASSWORD": "x" * 12})
        assert r.returncode == 0, r.stdout + r.stderr
        assert "PASS" in r.stdout


def test_repo_hygiene():
    gi = (ROOT / ".gitignore").read_text()
    for pattern in (".env", ".env.*", "*.mmdb", "*.crt", "*.ppk", "*.tfstate", "__pycache__/"):
        assert pattern in gi
    assert "eol=lf" in (ROOT / ".gitattributes").read_text()
    assert "end_of_line = lf" in (ROOT / ".editorconfig").read_text()
    for f in ROOT.rglob("*"):
        if f.is_file() and f.suffix in {".py", ".yml", ".yaml", ".sql", ".sh", ".md", ".json", ".cfg"} and ".venv" not in f.parts:
            assert b"\r\n" not in f.read_bytes(), f"CRLF in {f}"


def test_only_pipeline_has_external_network_access():
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    networks = compose["networks"]
    services = compose["services"]
    assert networks["backend"]["internal"] is True
    assert networks["edge"]["internal"] is True
    assert networks["egress"].get("internal", False) is False
    assert set(services["pipeline"]["networks"]) == {"backend", "egress"}
    assert all("egress" not in service.get("networks", []) for name, service in services.items() if name != "pipeline")
