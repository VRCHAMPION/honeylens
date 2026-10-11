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
    internal_only = {"networks": {"edge": {"internal": True}},
                     "services": {"grafana": svc([{"host_ip": "127.0.0.1", "target": 3000, "published": "3000"}],
                                                 networks={"edge": None})}}
    assert any("internal networks" in p for p in cp.check_static(internal_only, [str(f)], cp.ALLOWED, True))
    ok_nets = {"networks": {"edge": {"internal": True}, "ui": {}},
               "services": {"grafana": svc([{"host_ip": "127.0.0.1", "target": 3000, "published": "3000"}],
                                           networks={"edge": None, "ui": None})}}
    assert cp.check_static(ok_nets, [str(f)], cp.ALLOWED, True) == []
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


class _ComposeLoader(yaml.SafeLoader):
    """safe_load plus Compose's custom tags (!override, !reset) kept as plain values."""


def _any_tag(loader, _suffix, node):
    if isinstance(node, yaml.SequenceNode):
        return loader.construct_sequence(node)
    if isinstance(node, yaml.MappingNode):
        return loader.construct_mapping(node)
    return loader.construct_scalar(node)


_ComposeLoader.add_multi_constructor("!", _any_tag)


def load_compose(name):
    return yaml.load((ROOT / name).read_text(), Loader=_ComposeLoader)  # noqa: S506  # nosec B506 - SafeLoader subclass


def _nets(service):
    nets = service.get("networks", [])
    return list(nets) if isinstance(nets, (list, dict)) else []


def _no_nat(net):
    return (net or {}).get("driver_opts", {}).get("com.docker.network.bridge.enable_ip_masquerade") == "false"


def test_no_service_has_internet_by_default():
    compose = load_compose("docker-compose.yml")
    networks = compose["networks"]
    assert networks["backend"]["internal"] is True
    assert "egress" not in networks
    for name, net in networks.items():
        # every network is either internal or has outbound NAT switched off
        assert (net or {}).get("internal") is True or _no_nat(net), name
    for name, service in compose["services"].items():
        assert "egress" not in _nets(service), name


def test_published_services_are_on_a_non_internal_network():
    # Docker silently skips port publishing for a container attached only to
    # internal networks, so 127.0.0.1:2222 / :3000 would never bind.
    base = load_compose("docker-compose.yml")
    cloud = load_compose("docker-compose.cloud.yml")
    for compose_networks, services in (
        (base["networks"], base["services"]),
        ({**base["networks"], **cloud["networks"]},
         {k: {**v, **cloud["services"].get(k, {})} for k, v in base["services"].items()}),
    ):
        for name, service in services.items():
            if not service.get("ports"):
                continue
            usable = [n for n in _nets(service) if not (compose_networks.get(n) or {}).get("internal")]
            assert usable, f"{name} publishes ports but is only on internal networks"
    assert set(_nets(base["services"]["grafana"])) == {"backend", "ui"}
    assert _nets(base["services"]["cowrie"]) == ["edge"]
    assert "backend" not in _nets(base["services"]["cowrie"])  # attacker-facing service never reaches the DB
    assert _no_nat(cloud["networks"]["cowrie_net"])


def test_pipeline_egress_is_opt_in_override():
    base = load_compose("docker-compose.yml")
    enrich = load_compose("docker-compose.enrich.yml")
    assert _nets(base["services"]["pipeline"]) == ["backend"]
    assert set(enrich["services"]) == {"pipeline"}
    assert set(_nets(enrich["services"]["pipeline"])) == {"backend", "egress"}
    assert (enrich["networks"]["egress"] or {}).get("internal", False) is False


def test_live_check_requires_published_ports(monkeypatch):
    class R:
        stdout = "honeylens-cowrie-1\t\nhoneylens-grafana-1\t127.0.0.1:3000->3000/tcp\n"
    monkeypatch.setattr(cp.subprocess, "run", lambda *a, **k: R())
    problems = cp.check_live()
    assert any("cowrie" in p and "not published" in p for p in problems)
    assert not any("grafana" in p for p in problems)
    R.stdout = "honeylens-cowrie-1\t127.0.0.1:2222->2222/tcp\nhoneylens-grafana-1\t127.0.0.1:3000->3000/tcp\n"
    assert cp.check_live() == []
    R.stdout = "honeylens-cowrie-1\t0.0.0.0:22->2222/tcp\nhoneylens-grafana-1\t127.0.0.1:3000->3000/tcp\n"
    assert cp.check_live() != [] and cp.check_live(cloud=True) == []


def test_live_cloud_check_allows_only_public_22_to_2222(monkeypatch):
    class R:
        stdout = ""
    monkeypatch.setattr(cp.subprocess, "run", lambda *a, **k: R())
    grafana = "honeylens-grafana-1\t127.0.0.1:3000->3000/tcp\n"
    R.stdout = "honeylens-cowrie-1\t0.0.0.0:22->2222/tcp, [::]:22->2222/tcp\n" + grafana
    assert cp.check_live(cloud=True) == []
    for stray in ("0.0.0.0:2223->2223/tcp", "0.0.0.0:2222->2222/tcp", "0.0.0.0:23->2223/tcp"):
        R.stdout = f"honeylens-cowrie-1\t0.0.0.0:22->2222/tcp, {stray}\n" + grafana
        assert any(stray in p for p in cp.check_live(cloud=True)), stray
    R.stdout = "honeylens-cowrie-1\t0.0.0.0:22->2222/tcp\nhoneylens-grafana-1\t0.0.0.0:3000->3000/tcp\n"
    assert any("grafana" in p for p in cp.check_live(cloud=True))
