# Architecture

**What:** HoneyLens is a chain of small, separate parts: a fake SSH server writes JSON logs, a Python
pipeline turns them into clean database rows, and two read-only consumers (Grafana and the report)
show them.

**Why this shape:** each part does one job, can be restarted alone, and has only the permissions it
needs. If Grafana is compromised it can only *read*; if the pipeline crashes Cowrie keeps logging and
nothing is lost, because the pipeline resumes from saved offsets.

## 1. Components and data flow

```mermaid
flowchart TD
    subgraph edge["Docker network: edge (bridge, masquerade off: no outbound NAT)"]
      SIM["simulator (profile: sim)<br/>live SSH sessions"]
      COW["cowrie 3.1.1<br/>uid 999, read-only rootfs<br/>127.0.0.1:2222 -> 2222"]
    end
    subgraph ui["Docker network: ui (bridge, masquerade off)"]
      GRA["grafana 12.4.12<br/>uid 472, read-only rootfs<br/>127.0.0.1:3000"]
    end
    subgraph backend["Docker network: backend (internal database network)"]
      MIG["migrate (one-shot)<br/>roles + SQL migrations"]
      PIPE["pipeline<br/>uid 10001, read-only rootfs"]
      PG[("postgres 18.6<br/>no published port")]
      REP["report (profile: tools)"]
      GRA
    end
    EGRESS["egress network (opt-in override<br/>docker-compose.enrich.yml), pipeline only"]
    SYN["synthetic (profile: sim)<br/>network_mode: none"]
    SIM -->|SSH| COW
    COW -->|writes cowrie.json| VOL[(volume cowrie_var)]
    SYN -->|writes JSON lines| SVOL[(volume hl_synthetic)]
    VOL -->|read-only mount| PIPE
    SVOL -->|read-only mount| PIPE
    MIG -->|superuser, once| PG
    PIPE -->|hl_pipeline: read/write| PG
    PIPE -->|optional IPInfo API only| EGRESS
    GRA -->|hl_grafana: read-only| PG
    REP -->|hl_report: read-only| PG
    REP --> OUT[./out: HTML, CSV, STIX, Navigator]
```

## 2. Inside the pipeline (one batch = one transaction)

```mermaid
sequenceDiagram
    participant T as Tailer
    participant P as parse + sanitize
    participant DB as PostgreSQL (one transaction)
    T->>T: find files by glob, identify by device:inode
    T->>P: up to 500 complete lines after saved offset
    P->>P: JSON? valid eventid/session/time? strip ANSI/control chars, cut lengths
    P->>DB: INSERT raw_events ON CONFLICT DO NOTHING (dedupe by SHA-256 of line)
    P->>DB: INSERT logins / commands (+ATT&CK matches) / downloads for NEW events
    P->>DB: upsert sessions (start/end, IP, client, hassh)
    P->>DB: recount totals, enrich IP (cache -> MMDB -> API), score + classify, summary
    P->>DB: save file offsets (same transaction)
    DB-->>T: COMMIT ok -> advance in-memory offsets
    Note over T,DB: on any error: ROLLBACK, wait 1-30 s (exponential back-off), retry the SAME lines
```

| Stage | File | Key idea |
|---|---|---|
| Tail | `pipeline/tailer.py` | inode identity survives rotation; partial lines wait; oversized lines skipped in chunks |
| Parse + sanitize | `pipeline/events.py`, `pipeline/sanitize.py` | whitelist the fields we trust, keep a scrubbed raw copy |
| Store | `pipeline/store.py` | idempotent inserts, sessions rebuilt from child tables (always consistent) |
| Enrich | `enrich/geo.py` | special ranges first, then cache, then local MMDB, then optional API |
| ATT&CK | `mitre/attack.py`, `mitre/rules.yaml` | validated YAML regex rules |
| Score | `pipeline/scoring.py` | points table with reasons; classes; bot-vs-human from timing |
| Loop | `pipeline/runner.py` | batching, back-off, SIGTERM-safe stop, metrics row per batch, heartbeat file, daily retention |

## 3. Database

```mermaid
erDiagram
    raw_events ||--o{ sessions : "grouped by session_id"
    sessions ||--o{ login_attempts : has
    sessions ||--o{ commands : has
    sessions ||--o{ downloads : has
    sessions ||--o{ attack_matches : has
    sessions ||--|| session_summaries : summarised_by
    commands ||--o{ attack_matches : "event_uid"
    sessions }o--|| enrichment_cache : "src_ip"
    raw_events { bigint id PK
        text event_uid UK "SHA-256 of raw line"
        text eventid
        text session_id
        inet src_ip
        timestamptz ts
        bool is_simulated
        jsonb payload }
    sessions { text session_id PK
        inet src_ip
        timestamptz start_ts
        int login_attempts
        int commands_count
        text classification
        int severity "0-100"
        jsonb score_reasons
        text actor_type "bot/human/unknown"
        bool is_simulated }
    attack_matches { text event_uid
        text rule_id
        text technique_id
        text tactic
        text confidence }
    enrichment_cache { inet ip PK
        text country
        int asn
        text source
        timestamptz expires_at }
    pipeline_stats { timestamptz ts
        int events_ingested
        int duplicates
        int malformed
        int oversized
        int ignored
        float batch_ms }
    ingest_offsets { text file_key PK "device:inode"
        text path
        bigint byte_offset }
```

Full column list: [DATA_DICTIONARY.md](DATA_DICTIONARY.md).

## 4. Cloud isolation (UNVERIFIED - see DEPLOY_CLOUD.md)

```mermaid
flowchart TB
    subgraph tenancy["Cloud account"]
      subgraph comp["Dedicated compartment 'honeylens' (nothing else)"]
        subgraph vcn["Dedicated VCN / VPC"]
          SL{{"Security List / Security Group<br/>IN: 22/tcp from anywhere (Cowrie)<br/>no public rule for 22022<br/>(fallback only: 22022 from YOUR IP)"}}
          subgraph vm["VM (Ampere A1, Ubuntu 24.04)"]
            sshd["real sshd :22022<br/>keys only, no root<br/>allowed on tailscale0 / from bastion"]
            cow["Cowrie :2222 published as :22<br/>subnet 172.31.250.0/24"]
            ipt["iptables DOCKER-USER + INPUT:<br/>DROP NEW from 172.31.250.0/24 / hl-cowrie0"]
            int["internal network:<br/>pipeline + PostgreSQL"]
            gra["Grafana 127.0.0.1:3000"]
          end
        end
      end
      bud["Budget alert (1% of 1 unit)"]
    end
    att((Attackers)) --> SL --> cow
    me((You)) -->|"Tailscale or OCI Bastion / EC2 Instance Connect Endpoint"| sshd
    me -. "SSH tunnel -L 3000" .-> gra
    cow -. blocked .-> ipt
```

## 5. Trade-offs we chose

| Choice | Benefit | Cost |
|---|---|---|
| Tail files instead of Cowrie's PostgreSQL output plugin | Cowrie never gets DB credentials; we control sanitising and replay | must handle rotation/offsets ourselves (tested) |
| Batches of 500 in one transaction | fast, all-or-nothing | a poison batch is retried (malformed lines are filtered before the DB so this is rare) |
| Recount session totals from child tables | always correct even after replays/out-of-order lines | a few more queries per batch |
| Regex rules instead of ML (Machine Learning) | explainable, testable, no training data | misses obfuscated commands; needs rule upkeep |
| Offline MMDB GeoIP | private and free | location ≠ attacker identity; monthly refresh |
| PostgreSQL + Grafana | real SQL skills, familiar SOC tooling | heavier than SQLite (~1.3 GB images) |

## In 30 seconds

HoneyLens is an event pipeline. Cowrie writes JSON, a Python service tails the log with
crash-safe offsets stored in the same Postgres transaction as the data, deduplicates by a hash of
each line, enriches IPs offline, maps commands to ATT&CK with validated regex rules, scores each
session with explainable points, and Grafana plus an HTML report read it through read-only roles.
Everything runs in hardened containers and only loopback ports are exposed on a laptop.
In the laptop Compose stack, Cowrie and the live simulator share the `edge` network and Grafana has
its own `ui` network (plus the internal `backend` network for read-only DB access). `edge` and `ui`
are ordinary bridges, because Docker does not publish ports for a container attached only to
`internal: true` networks, but both have IP masquerading switched off, so there is no outbound NAT
and no working route to the internet. No container has internet access by default. Only with the
opt-in `docker-compose.enrich.yml` override does the pipeline join a normal `egress` network for the
IPInfo provider. The pipeline never shares a network with Cowrie and reads its log volume read-only.
