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
- ✅ Phase 5 — Additional attack scenarios: SSH reconnaissance/banner-grab detection, and a web
  target with signature-based detection of suspicious HTTP requests (SQLi, path traversal,
  sensitive-file probing)
- ✅ Phase 6 — Live dashboard auto-refresh (polls the API every 5s, no manual refresh needed)

**Next up:**
- ⬜ Phase 7+ — Event correlation across multiple attack stages, privilege escalation / file-change
  scenarios, packet-level scan detection, full test coverage, one-command demo script

## Detection rules

| Rule | Trigger | MITRE Technique | Data source |
|---|---|---|---|
| `ssh_brute_force` | 4+ failed SSH logins from one IP within 60s | T1110 — Brute Force | `ssh-target` auth.log |
| `ssh_recon_scan` | 2+ SSH banner-grab/recon probes from one IP within 60s | T1595 — Active Scanning | `ssh-target` auth.log |
| `web_attack_probing` | 3+ suspicious HTTP requests from one IP within 60s | T1190 — Exploit Public-Facing Application | `web-target` access.log |

## Architecture (current)

```
[Attacker container: Kali + Hydra + nmap + curl]
        │
        ├─ SSH brute-force / recon ──────────┐
        │                                     ▼
        │                     [ssh-target: Ubuntu + sshd + rsyslog]
        │                                     │ writes /var/log/auth.log
        │                                     ▼
        │                          [Host-mounted log volume]
        │
        └─ Suspicious HTTP requests ─────────┐
                                              ▼
                              [web-target: nginx]
                                              │ writes /var/log/nginx/access.log
                                              ▼
                                   [Host-mounted log volume]
                                              │
                                              ▼
                         [log-collector/parser.py]  — one thread per log source,
                         │                             each with its own DB connection;
                         │                             parses lines, normalizes into events
                         ▼
                [PostgreSQL: events table]
                         │
                         ▼
          [detection-engine/detector.py]  — polls events every 5s,
          │                                  applies 3 threshold-based rules
          ▼
[PostgreSQL: alerts table]  — tagged with MITRE ATT&CK technique
          │
          ▼
   [api/main.py]  — FastAPI REST API
          │          GET /alerts, /alerts/{id}, /events
          ▼
   [dashboard/]  — React (Vite) frontend
                  polls /alerts every 5s; alert list + click-through incident timeline
```

## Components

| Component | Tech | Purpose |
|---|---|---|
| `ssh-target` | Docker, Ubuntu, OpenSSH, rsyslog | Simulated vulnerable Linux server |
| `web-target` | Docker, nginx | Simulated web server; access log used for signature-based attack detection |
| `attacker` | Docker, Kali Linux, Hydra, nmap, curl | Controlled attack execution |
| `postgres` | PostgreSQL 16 | Stores structured events and alerts |
| `log-collector/parser.py` | Python, psycopg2, threading | Tails auth.log and access.log concurrently, parses and normalizes log lines into the `events` table |
| `detection-engine/detector.py` | Python, psycopg2 | Polls `events`, applies detection rules, writes `alerts` |
| `api/main.py` | Python, FastAPI, uvicorn | REST API exposing alerts, alert detail with linked events, and raw events |
| `dashboard/` | React, Vite | Web UI — live-polling alert list and incident timeline showing raw evidence per alert |

## Running it locally

Requires Docker and Docker Compose.

```bash
docker compose up -d --build
```

This starts the SSH target, web target, attacker container, and PostgreSQL.

Then, in separate terminals (each with its own venv):

```bash
# Terminal 1 — log collector (watches both auth.log and access.log)
cd log-collector && source venv/bin/activate && python3 parser.py

# Terminal 2 — detection engine
cd detection-engine && source venv/bin/activate && python3 detector.py

# Terminal 3 — API
cd api && source venv/bin/activate && uvicorn main:app --reload --port 8000

# Terminal 4 — dashboard
cd dashboard && npm run dev
```

### Attack scenarios

**SSH brute force:**
```bash
docker exec -it attacker bash
hydra -l testuser -P /attacks/passwords.txt ssh://ssh-target
```

**SSH reconnaissance / banner grab:**
```bash
docker exec -it attacker bash
nmap -sV -p 22 ssh-target
nmap -sV -p 22 ssh-target
```

**Suspicious HTTP requests (SQLi, path traversal, sensitive-file probing):**
```bash
docker exec -it attacker bash
curl "http://web-target/index.html?id=1%27%20OR%20%271%27%3D%271"
curl "http://web-target/.env"
curl "http://web-target/wp-login.php"
```

With the dashboard open at `http://localhost:5173`, alerts appear automatically within a few seconds
of an attack — no manual refresh needed. Click an alert to see its full incident timeline: the exact
raw log lines that triggered it. Alerts are also retrievable via `curl http://localhost:8000/alerts`,
or browsed via the auto-generated API docs at `http://localhost:8000/docs`.

## Design notes

- **SSH host keys persist** across container rebuilds via a named Docker volume, so repeated
  `docker compose up --build` cycles don't require clearing `known_hosts` each time.
- **Log files are shared via host-mounted volumes** rather than read from inside the container,
  so the Python log collector can tail them like a real external log shipper would.
- **Detection runs on a polling loop**, decoupled from ingestion — closer to how real detection
  engines/SIEMs operate as independent scheduled jobs rather than being triggered inline by ingestion.
  The dashboard itself also polls the API on the same principle, rather than requiring a manual
  refresh or a more complex push mechanism (e.g. WebSockets), which wasn't justified for this scale.
- **Deduplication** is handled via an `alerted` boolean flag directly on each event row. When an
  alert is created, every event that contributed to it is marked `alerted = TRUE` in the same
  transaction as the alert insert, so events are never double-counted across overlapping detection
  windows and the two tables can never drift out of sync with each other.
- **The database schema is tracked in `db/schema.sql`** as the single source of truth, so the
  project can be set up from scratch without relying on manually-run `ALTER TABLE` commands.
- **SSH recon detection required correlating two separate log lines** (a `Connection from ...` line
  carrying the source IP, followed later by a `kex_exchange_identification` error when the client
  disconnects before completing the handshake). The parser tracks source IPs by sshd process ID in
  a short-lived in-memory dictionary, popping the entry once it's used — a small example of
  stateful log parsing, as opposed to the single-line pattern matching used for brute-force events.
- **HTTP attack detection is signature-based**: incoming request paths are URL-decoded (attackers
  often percent-encode payloads specifically to evade naive string matching) and checked against a
  known list of malicious patterns (SQL injection fragments, path traversal, sensitive file paths).
  This is deliberately simple — closer to a basic WAF ruleset than a general-purpose anomaly
  detector — and is explainable end-to-end, which was prioritized over sophistication for v1.
- **Raw TCP port scans are not detectable from `sshd`'s own logs**, even at maximum log verbosity —
  `sshd` only logs a connection once a client begins the SSH protocol handshake, so a bare
  `nmap -sT`/`-sS` scan that never speaks SSH leaves no trace in `auth.log`. This is a genuine,
  documented limitation of host-based application logging, not a gap in this project's detection
  logic — real SOCs address it with network-level telemetry (firewall/flow logs, an IDS such as
  Suricata) rather than relying on application logs alone. What this project detects instead is
  the SSH-level *banner-grab*, a lighter-weight but very common reconnaissance action that does
  reach the SSH protocol layer and therefore does get logged.
- **The log collector runs one thread per log source**, each with its own PostgreSQL connection
  (connections are not safe to share across threads), so adding a new log source in the future
  means adding a new parse function and a new thread — the collector doesn't need to be rearchitected.
- **The attacker's password wordlist is baked into its Docker image** (via a `RUN printf` step in
  its Dockerfile) rather than created manually in a running container — an earlier version created
  it by hand, which silently disappeared every time the image was rebuilt, breaking the brute-force
  scenario until the file was recreated. Baking it into the image makes the attacker container fully
  reproducible from a clean build, with no manual setup steps.

## Roadmap

- Event correlation: linking related alerts across attack stages (e.g. a recon scan followed by a
  brute-force attempt from the same IP) into a single incident narrative
- Privilege escalation and file-integrity monitoring scenarios
- Packet-level scan detection (raw SYN scans), likely via a lightweight `tcpdump`/`tshark` capture
  and threshold-based SYN/FIN counting, as a more complete alternative to the SSH-log-based approach
- Expanded automated test coverage and a one-command `./attack.sh` demo script
