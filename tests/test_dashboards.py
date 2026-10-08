"""Grafana dashboards: generated JSON is up to date and template variables are escaped."""
import importlib.util
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DASH = ROOT / "grafana" / "dashboards"


def _raw_sql():
    for f in sorted(DASH.glob("*.json")):
        board = json.loads(f.read_text(encoding="utf-8"))
        for panel in board.get("panels", []):
            for target in panel.get("targets", []):
                if "rawSql" in target:
                    yield f.name, target["rawSql"]


def test_template_variables_use_sqlstring_format():
    seen = 0
    for name, sql in _raw_sql():
        seen += 1
        # $__timeFilter etc. are Grafana macros, not user-controlled variables
        for var in re.findall(r"\$\{([^}]*)\}|\$(?!__)([A-Za-z_]\w*)", sql):
            text = var[0] or var[1]
            assert text.endswith(":sqlstring"), f"{name}: unescaped template variable {text!r} in {sql[:80]}"
    assert seen > 30


def test_generated_dashboards_match_generator(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location("build_dashboards", ROOT / "scripts" / "build_dashboards.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    monkeypatch.setattr(mod, "OUT", tmp_path)
    mod.main()
    for f in sorted(DASH.glob("*.json")):
        assert (tmp_path / f.name).read_text(encoding="utf-8") == f.read_text(encoding="utf-8"), \
            f"{f.name} is stale: run python scripts/build_dashboards.py"


def test_every_dropdown_is_used_by_a_query():
    for f in sorted(DASH.glob("*.json")):
        board = json.loads(f.read_text(encoding="utf-8"))
        sql = " ".join(t.get("rawSql", "") for p in board.get("panels", []) for t in p.get("targets", []))
        for var in board.get("templating", {}).get("list", []):
            name = var["name"]
            assert f"${{{name}" in sql or f"${name}" in sql, f"{f.name}: dropdown {name!r} is not used by any panel"
