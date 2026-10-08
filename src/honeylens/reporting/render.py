"""Render the weekly HTML report and write all export files.

Security: Jinja2 runs with ``autoescape=True``, so attacker text such as
``<script>`` is shown as text, never executed. URLs and IPs are defanged.
The page has a strict Content-Security-Policy and no JavaScript at all.
"""

from __future__ import annotations

import html
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape

from honeylens import __version__
from honeylens.config import DISPLAY_TZ
from honeylens.mitre.attack import default_rules, load_snapshot
from honeylens.pipeline.sanitize import defang, mask_ip, mask_ips_in_text
from honeylens.reporting import exports
from honeylens.reporting.data import ReportData

KPIS = [
    ("sessions", "Sessions"),
    ("unique_ips", "Unique source IPs"),
    ("login_attempts", "Login attempts"),
    ("successful_logins", "Successful (fake) logins"),
    ("commands", "Commands run"),
    ("downloads", "Download attempts"),
    ("high_or_critical", "High/critical sessions"),
    ("techniques", "ATT&CK techniques"),
]


def ist(dt: datetime | None) -> str:
    """Format a UTC datetime in IST for display."""
    if dt is None:
        return ""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(DISPLAY_TZ).strftime("%Y-%m-%d %H:%M IST")


def pct_change(cur: float, prev: float) -> dict[str, str]:
    """Week-over-week change as text plus a CSS class."""
    if not prev:
        return {"text": "new" if cur else "no change", "cls": ""}
    change = 100.0 * (cur - prev) / prev
    sign = "+" if change >= 0 else ""
    return {"text": f"{sign}{change:.0f}%", "cls": "up" if change > 0 else ("down" if change < 0 else "")}


def daily_svg(rows: list[dict[str, Any]]) -> str:
    """A small inline SVG bar chart (no JavaScript, no external library)."""
    if not rows:
        return ""
    width, height, pad_l, pad_t = 930, 110, 34, 14
    peak = max(int(r["sessions"]) for r in rows) or 1
    bar_w = (width - pad_l) / len(rows)
    base = pad_t + height
    parts = [f'<svg viewBox="0 0 {width} {base + 22}" width="100%" role="img" aria-label="sessions per day" '
             'font-family="ui-monospace,Menlo,Consolas,monospace" font-size="10" fill="#59636e">']
    for frac in (0.5, 1.0):  # light gridlines with the scale on the left
        y = base - height * frac
        parts.append(f'<line x1="{pad_l}" x2="{width}" y1="{y:.1f}" y2="{y:.1f}" stroke="#e5e9ee"/>')
        parts.append(f'<text x="{pad_l - 6}" y="{y + 3:.1f}" text-anchor="end">{round(peak * frac)}</text>')
    parts.append(f'<line x1="{pad_l}" x2="{width}" y1="{base}" y2="{base}" stroke="#8c959f"/>')
    for i, r in enumerate(rows):
        h = height * int(r["sessions"]) / peak
        x = pad_l + i * bar_w + bar_w * 0.2
        y = base - h
        label = r["day"].strftime("%d %b")
        parts.append(f'<rect x="{x:.1f}" y="{y:.1f}" width="{bar_w * 0.6:.1f}" height="{h:.1f}" fill="#57606a"/>')
        parts.append(f'<text x="{x + bar_w * 0.3:.1f}" y="{y - 3:.1f}" text-anchor="middle" fill="#1f2328">{int(r["sessions"])}</text>')
        parts.append(f'<text x="{x + bar_w * 0.3:.1f}" y="{base + 14}" text-anchor="middle">{html.escape(label)}</text>')
    parts.append("</svg>")
    return "".join(parts)


def takeaways(d: ReportData) -> list[str]:
    """Plain-English defender advice driven by what was actually seen."""
    out: list[str] = []
    techs = {t["technique_id"] for t in d.techniques}
    if d.totals.get("login_attempts"):
        top_users = ", ".join(u["username"] for u in d.usernames[:3])
        out.append(f"Password guessing is constant ({d.totals['login_attempts']} attempts; top usernames: {top_users}). "
                   "Disable SSH password login and use keys (PasswordAuthentication no), or at least fail2ban.")
    if "T1098.004" in techs:
        out.append("Attackers wrote their own key into authorized_keys. Monitor ~/.ssh/authorized_keys for changes "
                   "(file integrity monitoring) and remove unknown keys.")
    if techs & {"T1496.001", "T1496"}:
        out.append("Cryptominer behaviour seen (stratum URLs, huge pages, killing rival miners). Alert on sustained high CPU "
                   "and block outbound mining-pool ports such as 3333/4444 at the firewall.")
    if "T1105" in techs:
        out.append("Attackers try to download tools with wget/curl/tftp right after login. Restrict outbound traffic "
                   "from servers (egress filtering) so downloads fail.")
    if techs & {"T1685.006", "T1070.003", "T1690"}:
        out.append("Log and history wiping seen. Ship logs off the server in real time so a local wipe cannot erase evidence.")
    if "T1053.003" in techs or "T1543.002" in techs:
        out.append("Persistence via cron/systemd. Review crontabs and new services after any suspected compromise.")
    if not out:
        out.append("Little activity this week. Keep the honeypot running; patterns appear over weeks, not days.")
    out.append("Treat IOCs (Indicators of Compromise) from a honeypot as low-confidence: block-list them for a short time only, "
               "because the IPs often belong to hacked third-party machines.")
    return out


def summary_text(d: ReportData) -> str:
    """Two-sentence executive summary."""
    t = d.totals
    top_class = d.classes[0]["classification"] if d.classes else "none"
    top_tech = f"{d.techniques[0]['technique_id']} {d.techniques[0]['technique_name']}" if d.techniques else "none"
    return (f"The honeypot recorded {t.get('sessions', 0)} sessions from {t.get('unique_ips', 0)} source IPs, "
            f"with {t.get('successful_logins', 0)} fake-successful logins and {t.get('commands', 0)} commands. "
            f"The most common behaviour was '{top_class}' and the most widespread ATT&CK technique was {top_tech}.")


def render_html(d: ReportData, mask_ips: bool = False, days: int = 7) -> str:
    """Return the full self-contained HTML document."""
    env = Environment(
        loader=PackageLoader("honeylens.reporting", "templates"),
        autoescape=select_autoescape(["html"], default=True),
        trim_blocks=True,
        lstrip_blocks=True,
    )

    def show_ip(value: str | None) -> str:
        if not value:
            return ""
        return mask_ip(value) if mask_ips else defang(value)

    def show_text(value: str | None) -> str:
        # Commands and URLs: with --mask-ips, IPs inside the text are masked too.
        if not value:
            return ""
        return defang(mask_ips_in_text(value) if mask_ips else value)

    def show_summary(value: str | None) -> str:
        if not value:
            return ""
        if not mask_ips:
            return value
        ip_part, _, rest = value.partition(" ")
        if "[.]" in ip_part or ":" in ip_part:
            value = "[masked IP] " + rest
        return mask_ips_in_text(value)

    tpl = env.get_template("weekly.html")
    return tpl.render(
        d=d,
        mask_ips=mask_ips,
        days=days,
        kpis=KPIS,
        change=lambda k: pct_change(float(d.totals.get(k) or 0), float(d.prev_totals.get(k) or 0)),
        w_start=ist(d.window.start),
        w_end=ist(d.window.end),
        generated=ist(datetime.now(UTC)),
        ist=ist,
        ip=show_ip,
        defang=show_text,
        summary=show_summary,
        daily_svg=daily_svg(d.daily),
        summary_text=summary_text(d),
        takeaways=takeaways(d),
        attack_version=load_snapshot()["attack_version"],
        rule_count=len(default_rules()),
        cowrie_version="3.1.1",
        version=__version__,
    )


def write_all(d: ReportData, out_dir: Path, mask_ips: bool = False, days: int = 7) -> dict[str, Path]:
    """Write report.html, iocs.csv, iocs.stix.json and attack-navigator-layer.json."""
    out_dir.mkdir(parents=True, exist_ok=True)
    files = {
        "html": out_dir / "weekly-report.html",
        "csv": out_dir / "iocs.csv",
        "stix": out_dir / "iocs.stix.json",
        "navigator": out_dir / "attack-navigator-layer.json",
    }
    files["html"].write_text(render_html(d, mask_ips, days), encoding="utf-8")
    files["csv"].write_text(exports.to_csv(d, mask_ips), encoding="utf-8")
    files["stix"].write_text(exports.dumps(exports.to_stix(d, mask_ips)), encoding="utf-8")
    files["navigator"].write_text(exports.dumps(exports.to_navigator(d)), encoding="utf-8")
    return files
