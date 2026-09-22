# Mini SOC — Security Monitoring & Detection Lab

A small but functioning Security Operations Center (SOC) pipeline, built as a portfolio project to
demonstrate practical skills in detection engineering, backend development, and system design.

The system simulates a small organization's infrastructure, runs controlled attacks against it, and
detects the resulting malicious activity through a real log collection → detection → alerting pipeline.

## Status

**Phases completed:**
- ✅ Phase 0 — Docker lab environment (attacker + target containers)
- ✅ Phase 1 — Log collection & normalization (Python → PostgreSQL)
- ✅ Phase 2 — Detection engine (SSH brute-force rule, MITRE ATT&CK tagging)

**Next up:**
- ⬜ Phase 3 — REST API (FastAPI) exposing alerts and events
- ⬜ Phase 4 — Dashboard (React) for browsing alerts and incident timelines
- ⬜ Phase 5+ — Additional attack scenarios, event correlation, incident view, full documentation

## Architecture (current)

```
[Attacker container: Kali + Hydra + nmap]
        │  SSH brute-force attack
        ▼
[Target container: Ubuntu + sshd + rsyslog]
        │  writes /var/log/auth.log
        ▼
[Host-mounted log volume]
        │
        ▼
[log-collector/parser.py]  — tails auth.log, parses lines with regex,
        │                     normalizes into structured events
        ▼
[PostgreSQL: events table]
        │
        ▼
[detection-engine/detector.py]  — polls events every 5s,
        │                          applies threshold-based brute-force rule
        ▼
[PostgreSQL: alerts table]  — tagged with MITRE ATT&CK technique (e.g. T1110)
```

## Components

| Component | Tech | Purpose |
|---|---|---|
| `ssh-target` | Docker, Ubuntu, OpenSSH, rsyslog | Simulated vulnerable Linux server |
| `attacker` | Docker, Kali Linux, Hydra, nmap | Controlled attack execution |
| `postgres` | PostgreSQL 16 | Stores structured events and alerts |
| `log-collector/parser.py` | Python, psycopg2 | Tails auth.log, parses and normalizes SSH log lines into the `events` table |
| `detection-engine/detector.py` | Python, psycopg2 | Polls `events`, applies detection rules, writes `alerts` |

## Running it locally

Requires Docker and Docker Compose.

```bash
docker compose up -d --build
```

This starts the SSH target, attacker container, and PostgreSQL.

Then, in separate terminals (each with its own venv):

```bash
# Terminal 1 — log collector
cd log-collector && source venv/bin/activate && python3 parser.py

# Terminal 2 — detection engine
cd detection-engine && source venv/bin/activate && python3 detector.py
```

To trigger a brute-force attack scenario:

```bash
docker exec -it attacker bash
hydra -l testuser -P /attacks/passwords.txt ssh://ssh-target
```

Within a few seconds, the detection engine should print an `ALERT: ssh_brute_force` line, and a
corresponding row will appear in the `alerts` table.

## Design notes

- **SSH host keys persist** across container rebuilds via a named Docker volume, so repeated
  `docker compose up --build` cycles don't require clearing `known_hosts` each time.
- **Log files are shared via a host-mounted volume** rather than read from inside the container,
  so the Python log collector can tail them like a real external log shipper would.
- **Detection runs on a polling loop**, decoupled from ingestion — closer to how real detection
  engines/SIEMs operate as independent scheduled jobs rather than being triggered inline by ingestion.
- **Deduplication** currently excludes only exact previously-alerted event IDs; a known limitation
  is that overlapping time windows can cause event counts to be recounted across alerts. A more
  precise version would track which specific events have already contributed to an alert.

## Roadmap

See the phase list above. Planned attack scenarios beyond SSH brute-force include port scanning,
suspicious HTTP requests, and privilege escalation, each mapped to relevant MITRE ATT&CK techniques.
