import re
import time
from datetime import datetime, timezone
import psycopg2

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "soc",
    "user": "soc",
    "password": "socpassword",
}

# Matches lines like:
# Sep 22 21:19:04 hostname sshd[33]: Failed password for testuser from 172.18.0.3 port 60338 ssh2
FAILED_LOGIN_RE = re.compile(
    r"^(?P<timestamp>\w+ +\d+ \d+:\d+:\d+) (?P<host>\S+) sshd\[\d+\]: "
    r"Failed password for (?P<user>\S+) from (?P<ip>\S+) port \d+"
)

# Matches lines like:
# Sep 22 21:19:04 hostname sshd[34]: Accepted password for testuser from 172.18.0.3 port 60330 ssh2
ACCEPTED_LOGIN_RE = re.compile(
    r"^(?P<timestamp>\w+ +\d+ \d+:\d+:\d+) (?P<host>\S+) sshd\[\d+\]: "
    r"Accepted password for (?P<user>\S+) from (?P<ip>\S+) port \d+"
)

# Matches lines like:
# Sep 23 20:50:05 hostname sshd[43]: Connection from 172.18.0.2 port 38288 on 172.18.0.3 port 22 rdomain ""
CONNECTION_FROM_RE = re.compile(
    r"^(?P<timestamp>\w+ +\d+ \d+:\d+:\d+) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: "
    r"Connection from (?P<ip>\S+) port \d+ on \S+ port \d+"
)

# Matches lines like:
# Sep 23 20:50:05 hostname sshd[43]: error: kex_exchange_identification: Connection closed by remote host
RECON_PROBE_RE = re.compile(
    r"^(?P<timestamp>\w+ +\d+ \d+:\d+:\d+) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: "
    r"error: kex_exchange_identification: Connection closed by remote host"
)

# Tracks the source IP for each active sshd process (PID), so we can correlate
# a later "kex_exchange_identification" line back to the connection that caused it.
pid_to_ip = {}


def parse_line(line):
    """Try to match a log line against known patterns. Returns a dict or None."""
    match = FAILED_LOGIN_RE.match(line)
    if match:
        return {
            "event_type": "ssh_failed_login",
            "username": match.group("user"),
            "source_ip": match.group("ip"),
            "source_host": match.group("host"),
            "timestamp_str": match.group("timestamp"),
        }

    match = ACCEPTED_LOGIN_RE.match(line)
    if match:
        return {
            "event_type": "ssh_accepted_login",
            "username": match.group("user"),
            "source_ip": match.group("ip"),
            "source_host": match.group("host"),
            "timestamp_str": match.group("timestamp"),
        }

    match = CONNECTION_FROM_RE.match(line)
    if match:
        # Remember this PID's source IP for later correlation; not an event on its own.
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
            "timestamp_str": match.group("timestamp"),
        }

    return None


def parse_timestamp(timestamp_str):
    """Syslog timestamps have no year, so we assume the current year."""
    current_year = datetime.now().year
    dt = datetime.strptime(f"{current_year} {timestamp_str}", "%Y %b %d %H:%M:%S")
    return dt.replace(tzinfo=timezone.utc)


def insert_event(conn, parsed, raw_line):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO events (source_host, source_ip, event_type, username, raw_log, event_time)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                parsed["source_host"],
                parsed["source_ip"],
                parsed["event_type"],
                parsed["username"],
                raw_line.strip(),
                parse_timestamp(parsed["timestamp_str"]),
            ),
        )
    conn.commit()


def tail_log(filepath, conn):
    """Follow a log file like `tail -f`, parsing and inserting new lines as they appear."""
    with open(filepath, "r") as f:
        f.seek(0, 2)  # jump to end of file, we only care about new lines
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue

            parsed = parse_line(line)
            if parsed:
                insert_event(conn, parsed, line)
                print(f"Inserted: {parsed['event_type']} - {parsed['username']} from {parsed['source_ip']}")


if __name__ == "__main__":
    conn = psycopg2.connect(**DB_CONFIG)
    print("Connected to database. Watching log file...")
    tail_log("../logs/ssh-target/auth.log", conn)
