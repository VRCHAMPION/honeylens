"""Map attacker commands to MITRE ATT&CK techniques with YAML rules.

What is ATT&CK? MITRE ATT&CK (Adversarial Tactics, Techniques, and Common
Knowledge) is a public catalogue of attacker behaviour. A *tactic* is the
attacker's goal (for example "Discovery"); a *technique* is how they reach it
(for example T1082 "System Information Discovery").

How this module works:

1. Load the bundled, pinned ATT&CK snapshot (IDs, names, tactics, revoked flags).
2. Load ``rules.yaml`` and VALIDATE every rule: the technique must exist and must
   not be revoked or deprecated. A bad rule stops startup, so a typo can never
   silently produce wrong reports.
3. For each command, run every rule's regex and return all matches.
4. Commands that match nothing are "unmapped" - we count them so a human can
   write new rules (this is how detection coverage grows in a real SOC).
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from functools import lru_cache
from importlib import resources
from typing import Any

import yaml

from honeylens.pipeline.sanitize import FIELD_LIMITS

SNAPSHOT_FILE = "enterprise-attack-19.2.min.json"
VALID_CONFIDENCE = {"high", "medium", "low"}
REQUIRED_TACTICS = {
    "discovery",
    "execution",
    "persistence",
    "stealth",  # "defense evasion" part 1 (v19 rename)
    "defense-impairment",  # "defense evasion" part 2 (v19 split)
    "credential-access",
    "command-and-control",
    "impact",  # resource hijacking lives here
    "reconnaissance",
}


class RuleError(ValueError):
    """A detection rule is invalid (bad regex, unknown or revoked technique...)."""


@dataclass(frozen=True)
class Rule:
    """One detection rule loaded from YAML."""

    id: str
    regex: re.Pattern[str]
    technique: str
    technique_name: str
    tactic: str
    confidence: str
    rationale: str
    positive: tuple[str, ...]
    negative: tuple[str, ...]


@dataclass(frozen=True)
class Match:
    """A rule that fired on one command."""

    rule_id: str
    technique: str
    technique_name: str
    tactic: str
    confidence: str


@lru_cache(maxsize=1)
def load_snapshot() -> dict[str, Any]:
    """Return the bundled ATT&CK snapshot as a dict (cached)."""
    text = resources.files("honeylens.mitre").joinpath("data", SNAPSHOT_FILE).read_text("utf-8")
    data: dict[str, Any] = json.loads(text)
    return data


def _load_yaml(text: str | None = None) -> dict[str, Any]:
    if text is None:
        text = resources.files("honeylens.mitre").joinpath("rules.yaml").read_text("utf-8")
    data = yaml.safe_load(text)  # safe_load never runs code from YAML
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        raise RuleError("rules file must contain a 'rules' list")
    return data


def parse_rules(text: str | None = None) -> list[Rule]:
    """Load and validate rules. Raises :class:`RuleError` on any problem."""
    snap = load_snapshot()
    techniques: dict[str, Any] = snap["techniques"]
    data = _load_yaml(text)
    rules: list[Rule] = []
    seen: set[str] = set()
    for raw in data["rules"]:
        for key in ("id", "regex", "technique", "tactic", "confidence", "rationale"):
            if not raw.get(key):
                raise RuleError(f"rule {raw.get('id', '?')} is missing '{key}'")
        rid = str(raw["id"])
        if rid in seen:
            raise RuleError(f"duplicate rule id {rid}")
        seen.add(rid)
        tech_id = str(raw["technique"])
        tech = techniques.get(tech_id)
        if tech is None:
            raise RuleError(f"{rid}: unknown technique {tech_id}")
        if tech["revoked"]:
            raise RuleError(f"{rid}: technique {tech_id} is REVOKED in ATT&CK {snap['attack_version']}")
        if tech["deprecated"]:
            raise RuleError(f"{rid}: technique {tech_id} is DEPRECATED in ATT&CK {snap['attack_version']}")
        tactic = str(raw["tactic"])
        if tactic not in tech["tactics"]:
            raise RuleError(f"{rid}: tactic '{tactic}' is not a tactic of {tech_id} {tech['tactics']}")
        if raw["confidence"] not in VALID_CONFIDENCE:
            raise RuleError(f"{rid}: confidence must be one of {sorted(VALID_CONFIDENCE)}")
        try:
            pattern = re.compile(str(raw["regex"]), re.IGNORECASE)
        except re.error as exc:
            raise RuleError(f"{rid}: bad regex: {exc}") from exc
        rules.append(
            Rule(
                id=rid,
                regex=pattern,
                technique=tech_id,
                technique_name=str(tech["name"]),
                tactic=tactic,
                confidence=str(raw["confidence"]),
                rationale=str(raw["rationale"]),
                positive=tuple(raw.get("positive") or ()),
                negative=tuple(raw.get("negative") or ()),
            )
        )
    return rules


@lru_cache(maxsize=1)
def default_rules() -> tuple[Rule, ...]:
    """The validated bundled rules (cached)."""
    return tuple(parse_rules())


def match_command(command: str, rules: tuple[Rule, ...] | None = None) -> list[Match]:
    """Return every rule that matches ``command`` (one match per rule)."""
    rules = rules if rules is not None else default_rules()
    text = command[: FIELD_LIMITS["command"]]
    return [
        Match(r.id, r.technique, r.technique_name, r.tactic, r.confidence)
        for r in rules
        if r.regex.search(text)
    ]


def coverage(rules: tuple[Rule, ...] | None = None) -> dict[str, Any]:
    """Summarise which tactics and techniques the rules cover.

    "Coverage %" here = distinct techniques we have at least one rule for,
    divided by the techniques in the tactics we target that are relevant to a
    Linux SSH honeypot. It is a rough planning number, not a quality score.
    """
    rules = rules if rules is not None else default_rules()
    snap = load_snapshot()
    techs = {r.technique for r in rules}
    tactics = sorted({r.tactic for r in rules})
    per_tactic: dict[str, int] = {}
    for r in rules:
        per_tactic[r.tactic] = per_tactic.get(r.tactic, 0) + 1
    active = [
        tid
        for tid, t in snap["techniques"].items()
        if not t["revoked"] and not t["deprecated"] and set(t["tactics"]) & set(tactics)
    ]
    return {
        "attack_version": snap["attack_version"],
        "rules": len(rules),
        "techniques_covered": sorted(techs),
        "tactics_covered": tactics,
        "rules_per_tactic": dict(sorted(per_tactic.items())),
        "active_techniques_in_covered_tactics": len(active),
        "coverage_percent": round(100.0 * len(techs) / max(len(active), 1), 1),
    }


def navigator_layer(
    technique_counts: dict[str, int] | None = None,
    name: str = "HoneyLens detections",
    description: str = "Techniques HoneyLens can detect from honeypot commands.",
) -> dict[str, Any]:
    """Build an ATT&CK Navigator layer (JSON) for https://mitre-attack.github.io/attack-navigator/.

    With ``technique_counts`` the colour shows how often each technique was
    SEEN; without it the layer shows which techniques we can DETECT.
    """
    snap = load_snapshot()
    rules = default_rules()
    if technique_counts is None:
        technique_counts = {r.technique: 1 for r in rules}
    max_count = max(technique_counts.values(), default=1)
    entries = []
    for tid, count in sorted(technique_counts.items()):
        tech = snap["techniques"].get(tid)
        if not tech:
            continue
        for tactic in tech["tactics"]:
            entries.append(
                {
                    "techniqueID": tid,
                    "tactic": tactic,
                    "score": count,
                    "comment": f"{tech['name']}: {count}",
                    "enabled": True,
                }
            )
    return {
        "name": name,
        "versions": {"attack": snap["attack_version"].split(".")[0], "navigator": "5.3.2", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": description,
        "techniques": entries,
        "gradient": {"colors": ["#fff3b0", "#e09f3e", "#9e2a2b"], "minValue": 0, "maxValue": max_count},
        "legendItems": [],
        "showTacticRowBackground": True,
        "selectTechniquesAcrossTactics": True,
    }
