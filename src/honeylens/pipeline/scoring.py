"""Transparent severity scoring, behaviour classes and the bot-vs-human guess.

Design goal: an analyst (or reviewer) must be able to see EXACTLY why a
session got its score. So the score is a sum of named points, every point is
written to ``score_reasons``, and there is no machine learning black box.

These are HEURISTICS (rules of thumb). They will sometimes be wrong; the
reasons list lets a human check them.
"""

from __future__ import annotations

import statistics
from dataclasses import dataclass, field
from datetime import datetime

# Points table. Keep in sync with docs/ANALYST_PLAYBOOK.md.
POINTS = {
    "login_success": 10,
    "per_10_failed_logins": 2,  # capped at FAILED_CAP
    "per_command": 1,  # capped at COMMAND_CAP
    "per_tactic": 5,  # capped at TACTIC_CAP
    "high_confidence_technique": 3,  # per distinct technique, capped at HIGH_CAP
    "download_attempt": 15,
    "persistence": 10,
    "defense_impairment": 10,
    "resource_hijacking": 15,
    "data_destruction": 15,
}
FAILED_CAP, COMMAND_CAP, TACTIC_CAP, HIGH_CAP = 10, 10, 25, 15

CLASSES = (
    "cryptominer-like",
    "malware-dropper",
    "honeypot-prober",
    "intruder",
    "brute-forcer",
    "scanner",
    "unknown",
)


@dataclass
class SessionFacts:
    """Everything the scorer needs to know about one session."""

    login_failures: int = 0
    login_success: bool = False
    login_success_ts: datetime | None = None
    command_ts: list[datetime] = field(default_factory=list)
    downloads: int = 0
    techniques: set[str] = field(default_factory=set)
    high_conf_techniques: set[str] = field(default_factory=set)
    tactics: set[str] = field(default_factory=set)
    client_version: str = ""


@dataclass
class ScoreResult:
    """Output of :func:`score_session`."""

    severity: int
    label: str
    classification: str
    reasons: list[dict[str, object]]
    actor_type: str
    median_gap_s: float | None


def severity_label(score: int) -> str:
    """Map 0-100 to low / medium / high / critical."""
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def actor_type(facts: SessionFacts) -> tuple[str, float | None]:
    """Guess bot vs human from timing between commands.

    Bots paste whole scripts, so commands arrive less than a second apart and
    the first command comes almost instantly after login. Humans type, read
    output and think, so gaps are several seconds and uneven.
    Needs at least 3 commands; otherwise 'unknown'.
    """
    times = sorted(facts.command_ts)
    if len(times) < 3:
        return "unknown", None
    gaps = [(b - a).total_seconds() for a, b in zip(times, times[1:], strict=False)]
    median = statistics.median(gaps)
    first_gap = None
    if facts.login_success_ts is not None:
        first_gap = (times[0] - facts.login_success_ts).total_seconds()
    if median < 1.0 and (first_gap is None or first_gap < 3.0):
        return "bot", round(median, 3)
    if median >= 2.0 and (max(gaps) - min(gaps)) >= 2.0:
        return "human", round(median, 3)
    return "unknown", round(median, 3)


def classify(facts: SessionFacts) -> str:
    """Pick ONE behaviour class, checking the most specific first."""
    if "T1496.001" in facts.techniques or "T1496" in facts.techniques:
        return "cryptominer-like"
    if facts.downloads > 0 or "T1105" in facts.techniques:
        return "malware-dropper"
    if "T1497.001" in facts.techniques and len(facts.command_ts) <= 6:
        return "honeypot-prober"
    if facts.login_success and facts.command_ts:
        return "intruder"
    if facts.login_failures >= 3:
        return "brute-forcer"
    if not facts.command_ts and facts.login_failures + int(facts.login_success) <= 2:
        return "scanner"
    return "unknown"


def score_session(facts: SessionFacts) -> ScoreResult:
    """Compute severity (0-100) with an explanation for every point."""
    reasons: list[dict[str, object]] = []

    def add(rule: str, points: int, detail: str) -> None:
        if points > 0:
            reasons.append({"rule": rule, "points": points, "detail": detail})

    if facts.login_success:
        add("login_success", POINTS["login_success"], "attacker got a shell with a fake password")
    add(
        "failed_logins",
        min(FAILED_CAP, (facts.login_failures // 10) * POINTS["per_10_failed_logins"]),
        f"{facts.login_failures} failed logins",
    )
    add(
        "commands",
        min(COMMAND_CAP, len(facts.command_ts) * POINTS["per_command"]),
        f"{len(facts.command_ts)} commands run",
    )
    add(
        "tactics",
        min(TACTIC_CAP, len(facts.tactics) * POINTS["per_tactic"]),
        f"{len(facts.tactics)} ATT&CK tactics: {', '.join(sorted(facts.tactics))}",
    )
    add(
        "high_confidence_techniques",
        min(HIGH_CAP, len(facts.high_conf_techniques) * POINTS["high_confidence_technique"]),
        f"{len(facts.high_conf_techniques)} high-confidence techniques",
    )
    if facts.downloads:
        add("download_attempt", POINTS["download_attempt"], f"{facts.downloads} download attempts")
    if "persistence" in facts.tactics:
        add("persistence", POINTS["persistence"], "tried to survive reboot / keep access")
    if "defense-impairment" in facts.tactics:
        add("defense_impairment", POINTS["defense_impairment"], "tried to blind defenders (logs, firewall, agents)")
    if facts.techniques & {"T1496", "T1496.001"}:
        add("resource_hijacking", POINTS["resource_hijacking"], "cryptominer indicators")
    if "T1485" in facts.techniques:
        add("data_destruction", POINTS["data_destruction"], "tried to destroy data")
    total = min(100, sum(int(r["points"]) for r in reasons))  # type: ignore[call-overload]
    kind, median = actor_type(facts)
    return ScoreResult(total, severity_label(total), classify(facts), reasons, kind, median)
