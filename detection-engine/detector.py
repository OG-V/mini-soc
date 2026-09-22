import time
from datetime import timedelta
import psycopg2

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "soc",
    "user": "soc",
    "password": "socpassword",
}

# Rule parameters: N failed logins from the same IP within this many seconds
FAILED_LOGIN_THRESHOLD = 4
TIME_WINDOW_SECONDS = 60

POLL_INTERVAL_SECONDS = 5


def find_brute_force_candidates(conn):
    """
    Groups recent ssh_failed_login events by source_ip, counting how many
    occurred within the time window, and returns IPs that cross the threshold
    and don't already have an alert covering their most recent failed event.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT source_ip,
                   COUNT(*) AS failure_count,
                   MIN(id) AS first_id,
                   MAX(id) AS last_id,
                   array_agg(username ORDER BY id DESC) AS usernames
            FROM events
            WHERE event_type = 'ssh_failed_login'
              AND event_time > now() - (%s || ' seconds')::interval
              AND id NOT IN (
                  SELECT last_event_id FROM alerts
                  WHERE rule_name = 'ssh_brute_force' AND last_event_id IS NOT NULL
              )
            GROUP BY source_ip
            HAVING COUNT(*) >= %s
            """,
            (TIME_WINDOW_SECONDS, FAILED_LOGIN_THRESHOLD),
        )
        return cur.fetchall()


def create_alert(conn, source_ip, failure_count, first_id, last_id, username):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO alerts (rule_name, mitre_technique, source_ip, username,
                                 description, first_event_id, last_event_id, event_count)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                "ssh_brute_force",
                "T1110",
                source_ip,
                username,
                f"{failure_count} failed SSH logins from {source_ip} within {TIME_WINDOW_SECONDS}s",
                first_id,
                last_id,
                failure_count,
            ),
        )
    conn.commit()


def run():
    conn = psycopg2.connect(**DB_CONFIG)
    print("Detection engine started. Polling for brute-force patterns...")
    while True:
        candidates = find_brute_force_candidates(conn)
        for source_ip, failure_count, first_id, last_id, usernames in candidates:
            username = usernames[0]
            create_alert(conn, source_ip, failure_count, first_id, last_id, username)
            print(f"ALERT: ssh_brute_force from {source_ip} ({failure_count} failures)")
        time.sleep(POLL_INTERVAL_SECONDS)


if __name__ == "__main__":
    run()
