"""ATT&CK Navigator layers follow the official layer format 4.5."""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

from honeylens.mitre.attack import navigator_layer

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("validate_navigator", ROOT / "scripts" / "validate_navigator.py")
vn = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vn)


@pytest.mark.parametrize("name", ["attack-navigator-layer.json", "attack-navigator-coverage-layer.json"])
def test_samples_valid(name):
    assert vn.validate(json.loads((ROOT / "docs" / "samples" / name).read_text())) > 0


def test_generated_layers_valid():
    assert vn.validate(navigator_layer()) > 0
    assert vn.validate(navigator_layer({"T1110.001": 5, "T1059.004": 2})) >= 2
    assert navigator_layer()["versions"] == {"attack": "19", "navigator": "5.3.2", "layer": "4.5"}


@pytest.mark.parametrize("breaker", [
    lambda d: d.pop("name"),
    lambda d: d.__setitem__("domain", "enterprise"),
    lambda d: d["versions"].__setitem__("layer", "4.4"),
    lambda d: d["versions"].__setitem__("navigator", "4.8.0"),
    lambda d: d["versions"].__setitem__("attack", "15"),
    lambda d: d["gradient"].__setitem__("maxValue", 0),
    lambda d: d["gradient"].__setitem__("colors", ["#fff"]),
    lambda d: d["techniques"][0].__setitem__("techniqueID", "T99999"),
    lambda d: d["techniques"][0].__setitem__("techniqueID", "T9999"),
    lambda d: d["techniques"][0].__setitem__("tactic", "impact-xyz"),
    lambda d: d["techniques"][0].__setitem__("score", "high"),
])
def test_rejects_broken_layers(breaker):
    d = copy.deepcopy(navigator_layer())
    breaker(d)
    with pytest.raises((ValueError, KeyError)):
        vn.validate(d)


def test_rejects_revoked_technique():
    from honeylens.mitre.attack import load_snapshot
    revoked = next(t for t, i in load_snapshot()["techniques"].items() if i.get("revoked"))
    d = navigator_layer()
    d["techniques"][0] = {"techniqueID": revoked}
    with pytest.raises(ValueError, match="revoked"):
        vn.validate(d)
