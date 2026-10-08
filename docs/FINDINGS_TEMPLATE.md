# Finding: [short title, e.g. "Cryptominer dropper campaign using renamed kswapd0"]

| Field | Value |
|---|---|
| Finding ID | HL-YYYY-NNN |
| Date range (IST) | |
| Data type | REAL / SIMULATED (pick one - never mix) |
| Analyst | |
| Confidence | low / medium / high (and why) |
| Severity (HoneyLens score range) | |

## 1. Summary (2-3 sentences)

What happened, how often, why it matters to a defender.

## 2. Evidence

* Sessions: [count], session IDs: [list a few]
* Source IPs (defanged or masked): `203[.]0[.]113[.]x`
* Client versions / HASSH:
* Commands (verbatim, in a code block, defanged):

```text
```

* Screenshot: Session Explorer → "Why this score"

## 3. ATT&CK mapping

| Technique | Tactic | Rule | Evidence command |
|---|---|---|---|

## 4. Indicators (low confidence, honeypot-observed)

| Type | Value (defanged) | First seen (IST) | Count |
|---|---|---|---|

## 5. Assessment

What the actor was probably trying to do. **No attribution** - say what the data shows, not who did it.

## 6. Defender recommendations

Concrete, testable actions (e.g. "disable PasswordAuthentication", "alert on writes to authorized_keys").

## 7. Limitations

Honeypot bias, emulated shell, GeoIP ≠ identity, sample size, anything filtered.

## 8. Reproduce

Dashboard + time range + Data filter, or the SQL you ran (read-only role).
