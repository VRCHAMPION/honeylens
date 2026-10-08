"""STIX 2.1 output validated with the real OASIS ``stix2`` library."""
import copy
import importlib.util
import json
from pathlib import Path

import pytest

stix2 = pytest.importorskip("stix2")  # pinned in the [dev] extra
ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("validate_stix", ROOT / "scripts" / "validate_stix.py")
vs = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(vs)

SAMPLE = ROOT / "docs" / "samples" / "iocs.stix.json"


def test_bundled_sample_is_valid_stix21():
    counts = vs.validate(SAMPLE.read_text())
    assert counts["indicator"] > 0 and counts["report"] == 1


def _sample():
    return json.loads(SAMPLE.read_text())


def _first(b, kind):
    return next(o for o in b["objects"] if o["type"] == kind)


@pytest.mark.parametrize("breaker", [
    lambda b: _first(b, "indicator").pop("pattern"),
    lambda b: _first(b, "indicator").__setitem__("valid_from", "yesterday"),
    lambda b: _first(b, "indicator").__setitem__("pattern", "[ipv4-addr:value = '1.2.3.4'"),
    lambda b: _first(b, "indicator").__setitem__("pattern", "[nonsense]"),
    lambda b: _first(b, "indicator").__setitem__("spec_version", "2.0"),
    lambda b: _first(b, "indicator").__setitem__("id", "indicator--not-a-uuid"),
    lambda b: _first(b, "indicator").__setitem__("x_unknown", 1),
    lambda b: _first(b, "report").__setitem__("object_refs", ["indicator--00000000-0000-4000-8000-000000000000"]),
    lambda b: b["objects"].append(copy.deepcopy(b["objects"][0])),
])
def test_validator_really_rejects_broken_bundles(breaker):
    b = _sample()
    breaker(b)
    with pytest.raises(Exception):  # noqa: B017 - stix2 raises several exception types
        vs.validate(json.dumps(b))


def test_cli(capsys):
    assert vs.main([str(SAMPLE)]) == 0
    assert "VALID" in capsys.readouterr().out
