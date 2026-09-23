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
- ✅ Phase 3 — REST API (FastAPI) exposing alerts, alert detail with evidence trail, and raw events
- ✅ Phase 4 — Dashboard (React) — alert list, click-through incident timeline showing raw evidence

**Next up:**
- ⬜ Phase 5+ — Additional attack scenarios (port scanning, HTTP attacks), event correlation,
  live auto-refresh, full documentation

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
        │
        ▼
[api/main.py]  — FastAPI REST API
        │          GET /alerts, /alerts/{id}, /events
        ▼
[dashboard/]  — React (Vite) frontend
               alert list + click-through incident timeline
```

## Components

| Component | Tech | Purpose |
|---|---|---|
| `ssh-target` | Docker, Ubuntu, OpenSSH, rsyslog | Simulated vulnerable Linux server |
| `attacker` | Docker, Kali Linux, Hydra, nmap | Controlled attack execution |
| `postgres` | PostgreSQL 16 | Stores structured events and alerts |
| `log-collector/parser.py` | Python, psycopg2 | Tails auth.log, parses and normalizes SSH log lines into the `events` table |
| `detection-engine/detector.py` | Python, psycopg2 | Polls `events`, applies detection rules, writes `alerts` |
| `api/main.py` | Python, FastAPI, uvicorn | REST API exposing alerts, alert detail with linked events, and raw events |
| `dashboard/` | React, Vite | Web UI — alert list and incident timeline showing raw evidence per alert |

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

# Terminal 3 — API
cd api && source venv/bin/activate && uvicorn main:app --reload --port 8000


# Terminal 4 — dashboard
cd dashboard && npm run dev
```

To trigger a brute-force attack scenario:

```bash
docker exec -it attacker bash
hydra -l testuser -P /attacks/passwords.txt ssh://ssh-target
```

Within a few seconds, the detection engine should print an `ALERT: ssh_brute_force` line, and a
corresponding row will appear in the `alerts` table — visible live in the dashboard at
`http://localhost:5173`, retrievable via `curl http://localhost:8000/alerts`, or browsed via the
auto-generated API docs at `http://localhost:8000/docs`. Click an alert in the dashboard to see its
full incident timeline — the exact raw log lines that triggered it.

## Design notes

- **SSH host keys persist** across container rebuilds via a named Docker volume, so repeated
  `docker compose up --build` cycles don't require clearing `known_hosts` each time.
- **Log files are shared via a host-mounted volume** rather than read from inside the container,
  so the Python log collector can tail them like a real external log shipper would.
- **Detection runs on a polling loop**, decoupled from ingestion — closer to how real detection
  engines/SIEMs operate as independent scheduled jobs rather than being triggered inline by ingestion.
- **Deduplication** is handled via an `alerted` boolean flag directly on each event row. When an
  alert is created, every event that contributed to it is marked `alerted = TRUE` in the same
  transaction as the alert insert, so events are never double-counted across overlapping detection
  windows and the two tables can never drift out of sync with each other.
- **The database schema is tracked in `db/schema.sql`** as the single source of truth, so the
  project can be set up from scratch without relying on manually-run `ALTER TABLE` commands.

## Roadmap

See the phase list above. Planned attack scenarios beyond SSH brute-force include port scanning,
suspicious HTTP requests, and privilege escalation, each mapped to relevant MITRE ATT&CK techniques.
