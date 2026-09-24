import re
import time
import threading
from datetime import datetime, timezone
from urllib.parse import unquote
import psycopg2

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "soc",
    "user": "soc",
    "password": "socpassword",
}

# ---------------------------------------------------------------------------
# SSH log parsing (auth.log)
# ---------------------------------------------------------------------------

FAILED_LOGIN_RE = re.compile(
    r"^(?P<timestamp>\w+ +\d+ \d+:\d+:\d+) (?P<host>\S+) sshd\[\d+\]: "
    r"Failed password for (?P<user>\S+) from (?P<ip>\S+) port \d+"
)

ACCEPTED_LOGIN_RE = re.compile(
    r"^(?P<timestamp>\w+ +\d+ \d+:\d+:\d+) (?P<host>\S+) sshd\[\d+\]: "
    r"Accepted password for (?P<user>\S+) from (?P<ip>\S+) port \d+"
)

CONNECTION_FROM_RE = re.compile(
    r"^(?P<timestamp>\w+ +\d+ \d+:\d+:\d+) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: "
    r"Connection from (?P<ip>\S+) port \d+ on \S+ port \d+"
)

RECON_PROBE_RE = re.compile(
    r"^(?P<timestamp>\w+ +\d+ \d+:\d+:\d+) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: "
    r"error: kex_exchange_identification: Connection closed by remote host"
)

# Tracks the source IP for each active sshd process (PID), so we can correlate
# a later "kex_exchange_identification" line back to the connection that caused it.
pid_to_ip = {}

def parse_ssh_line(line):
    """Try to match an auth.log line against known SSH patterns. Returns a dict or None."""
    match = FAILED_LOGIN_RE.match(line)
    if match:
        return {
            "event_type": "ssh_failed_login",
            "username": match.group("user"),
            "source_ip": match.group("ip"),
            "source_host": match.group("host"),
            "event_time": parse_syslog_timestamp(match.group("timestamp")),
        }

    match = ACCEPTED_LOGIN_RE.match(line)
    if match:
        return {
            "event_type": "ssh_accepted_login",
            "username": match.group("user"),
            "source_ip": match.group("ip"),
            "source_host": match.group("host"),
            "event_time": parse_syslog_timestamp(match.group("timestamp")),
        }

    match = CONNECTION_FROM_RE.match(line)
    if match:
        pid_to_ip[match.group("pid")] = match.group("ip")
        return None

    match = RECON_PROBE_RE.match(line)
    if match:
        pid = match.group("pid")
        source_ip = pid_to_ip.pop(pid, None)
        return {
            "event_type": "ssh_recon_probe",
            "username": None,
            "source_ip": source_ip,
            "source_host": match.group("host"),
            "event_time": parse_syslog_timestamp(match.group("timestamp")),
        }

    return None

def parse_syslog_timestamp(timestamp_str):
    """Syslog timestamps have no year, so we assume the current year."""
    current_year = datetime.now().year
    dt = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
    return dt.replace(tzinfo=timezone.utc)

# ---------------------------------------------------------------------------
# HTTP log parsing (nginx access.log)
# ---------------------------------------------------------------------------

HTTP_LOG_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<timestamp>[^\]]+)\] '
    r'"(?P<method>\S+) (?P<path>\S+) HTTP/[^"]+" (?P<status>\d+) \d+'
)

# Known malicious/reconnaissance patterns commonly seen in web attack request paths.
# This is a simple signature list, similar in spirit to a basic WAF ruleset.
SUSPICIOUS_PATTERNS = [
    "union select", "select * from", "' or '1'='1", "or 1=1", "drop table",
    "<script", "../", "..%2f", "/etc/passwd", ".env", "wp-login", "wp-admin",
    ".git/config", "phpmyadmin", "eval(", "base64_decode",
]

def is_suspicious_path(path):
    decoded = unquote(path).lower()
    return any(pattern in decoded for pattern in SUSPICIOUS_PATTERNS)

def parse_http_line(line):
    """Try to match an access.log line and flag suspicious request paths."""
    match = HTTP_LOG_RE.match(line)
    if not match:
        return None

    path = match.group("path")
    if not is_suspicious_path(path):
        return None

    return {
        "event_type": "http_suspicious_request",
        "username": None,
        "source_ip": match.group("ip"),
        "source_host": "web-target",
        "event_time": parse_nginx_timestamp(match.group("timestamp")),
    }

def parse_nginx_timestamp(timestamp_str):
    """nginx timestamps include their own timezone offset, e.g. 23/Sep/2026:22:52:16 +0000."""
    return datetime.strptime(timestamp_str, "%d/%b/%Y:%H:%M:%S %z")

# ---------------------------------------------------------------------------
# Raw packet capture parsing (tcpdump SYN capture on ssh-target)
# ---------------------------------------------------------------------------

# Matches a tcpdump line for a bare SYN packet (SYN set, ACK not set - i.e. a
# connection *attempt*, not a reply). tcpdump's own startup banner lines
# ("tcpdump: verbose output suppressed...", "listening on eth0...") simply
# won't match this and are silently skipped, same as any other unmatched line.
SYN_PROBE_RE = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) IP "
    r"(?P<src_ip>\d+\.\d+\.\d+\.\d+)\.\d+ > \d+\.\d+\.\d+\.\d+\.(?P<dst_port>\d+): Flags \[S\]"
)

def parse_synscan_line(line):
    """Try to match a tcpdump SYN-capture line. Returns a dict or None."""
    match = SYN_PROBE_RE.match(line)
    if not match:
        return None

    return {
        "event_type": "syn_probe",
        "username": None,
        "source_ip": match.group("src_ip"),
        "source_host": "ssh-target",
        "event_time": parse_tcpdump_timestamp(match.group("timestamp")),
        "dest_port": int(match.group("dst_port")),
    }

def parse_tcpdump_timestamp(timestamp_str):
    """tcpdump -tttt timestamps carry no timezone; the container clock runs in UTC."""
    dt = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S.%f")
    return dt.replace(tzinfo=timezone.utc)

# ---------------------------------------------------------------------------
# Shared insert + tail logic
# ---------------------------------------------------------------------------

def insert_event(conn, parsed, raw_line):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO events (source_host, source_ip, event_type, username, raw_log, event_time, dest_port)
            VALUES (%s, %s, %s, %s, %s, %s, %s)
            """,
            (
                parsed["source_host"],
                parsed["source_ip"],
                parsed["event_type"],
                parsed["username"],
                raw_line.strip(),
                parsed["event_time"],
                parsed.get("dest_port"),
            ),
        )
    conn.commit()

def tail_log(filepath, parse_fn, label):
    """Follow a log file like `tail -f`, parsing and inserting new lines as they appear.
    Runs with its own DB connection, so it can safely run in its own thread."""
    conn = psycopg2.connect(**DB_CONFIG)
    print(f"[{label}] Connected to database. Watching {filepath} ...")
    with open(filepath, "r") as f:
        f.seek(0, 2)  # jump to end of file, we only care about new lines
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            parsed = parse_fn(line)
            if parsed:
                insert_event(conn, parsed, line)
                print(f"[{label}] Inserted: {parsed['event_type']} - {parsed['source_ip']}")

if __name__ == "__main__":
    ssh_thread = threading.Thread(
        target=tail_log,
        args=("../logs/ssh-target/auth.log", parse_ssh_line, "ssh"),
        daemon=True,
    )
    http_thread = threading.Thread(
        target=tail_log,
        args=("../logs/web-target/access.log", parse_http_line, "http"),
        daemon=True,
    )
    synscan_thread = threading.Thread(
        target=tail_log,
        args=("../logs/ssh-target/tcpdump-syn.log", parse_synscan_line, "synscan"),
        daemon=True,
    )

    ssh_thread.start()
    http_thread.start()
    synscan_thread.start()

    # Keep the main thread alive while the three workers run in the background
    ssh_thread.join()
    http_thread.join()
    synscan_thread.join()
