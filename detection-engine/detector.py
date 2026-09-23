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
RECON_THRESHOLD = 2
RECON_WINDOW_SECONDS = 60
WEB_ATTACK_THRESHOLD = 3
WEB_ATTACK_WINDOW_SECONDS = 60

def find_brute_force_candidates(conn):
    """
    Groups recent, not-yet-alerted ssh_failed_login events by source_ip,
    returning IPs that cross the threshold within the time window.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT source_ip,
                   COUNT(*) AS failure_count,
                   MIN(id) AS first_id,
                   MAX(id) AS last_id,
                   array_agg(id) AS event_ids,
                   array_agg(username ORDER BY id DESC) AS usernames
            FROM events
            WHERE event_type = 'ssh_failed_login'
              AND alerted = FALSE
              AND event_time > now() - (%s || ' seconds')::interval
            GROUP BY source_ip
            HAVING COUNT(*) >= %s
            """,
            (TIME_WINDOW_SECONDS, FAILED_LOGIN_THRESHOLD),
        )
        return cur.fetchall()

def find_recon_candidates(conn):
    """
    Groups recent, not-yet-alerted ssh_recon_probe events by source_ip,
    returning IPs that cross the threshold within the time window.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT source_ip,
                   COUNT(*) AS probe_count,
                   MIN(id) AS first_id,
                   MAX(id) AS last_id,
                   array_agg(id) AS event_ids
            FROM events
            WHERE event_type = 'ssh_recon_probe'
              AND alerted = FALSE
              AND event_time > now() - (%s || ' seconds')::interval
            GROUP BY source_ip
            HAVING COUNT(*) >= %s
            """,
            (RECON_WINDOW_SECONDS, RECON_THRESHOLD),
        )
        return cur.fetchall()


def create_recon_alert(conn, source_ip, probe_count, first_id, last_id, event_ids):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO alerts (rule_name, mitre_technique, source_ip, username,
                                 description, first_event_id, last_event_id, event_count)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                "ssh_recon_scan",
                "T1595",
                source_ip,
                None,
                f"{probe_count} SSH banner-grab/recon probes from {source_ip} within {RECON_WINDOW_SECONDS}s",
                first_id,
                last_id,
                probe_count,
            ),
        )
        cur.execute(
            "UPDATE events SET alerted = TRUE WHERE id = ANY(%s)",
            (event_ids,),
        )
    conn.commit()

def find_web_attack_candidates(conn):
    """
    Groups recent, not-yet-alerted http_suspicious_request events by source_ip,
    returning IPs that cross the threshold within the time window.
    """
    with conn.cursor() as cur:
        cur.execute(
            """
            SELECT source_ip,
                   COUNT(*) AS request_count,
                   MIN(id) AS first_id,
                   MAX(id) AS last_id,
                   array_agg(id) AS event_ids
            FROM events
            WHERE event_type = 'http_suspicious_request'
              AND alerted = FALSE
              AND event_time > now() - (%s || ' seconds')::interval
            GROUP BY source_ip
            HAVING COUNT(*) >= %s
            """,
            (WEB_ATTACK_WINDOW_SECONDS, WEB_ATTACK_THRESHOLD),
        )
        return cur.fetchall()


def create_web_attack_alert(conn, source_ip, request_count, first_id, last_id, event_ids):
    with conn.cursor() as cur:
        cur.execute(
            """
            INSERT INTO alerts (rule_name, mitre_technique, source_ip, username,
                                 description, first_event_id, last_event_id, event_count)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            """,
            (
                "web_attack_probing",
                "T1190",
                source_ip,
                None,
                f"{request_count} suspicious HTTP requests from {source_ip} within {WEB_ATTACK_WINDOW_SECONDS}s",
                first_id,
                last_id,
                request_count,
            ),
        )
        cur.execute(
            "UPDATE events SET alerted = TRUE WHERE id = ANY(%s)",
            (event_ids,),
        )
    conn.commit()

def create_alert(conn, source_ip, failure_count, first_id, last_id, event_ids, username):
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
        # Mark every event that contributed to this alert so it's never double-counted
        cur.execute(
            "UPDATE events SET alerted = TRUE WHERE id = ANY(%s)",
            (event_ids,),
        )
    conn.commit()

def run():
    conn = psycopg2.connect(**DB_CONFIG)
    print("Detection engine started. Polling for brute-force, recon, and web attack patterns...")
    while True:
        candidates = find_brute_force_candidates(conn)
        for source_ip, failure_count, first_id, last_id, event_ids, usernames in candidates:
            username = usernames[0]
            create_alert(conn, source_ip, failure_count, first_id, last_id, event_ids, username)
            print(f"ALERT: ssh_brute_force from {source_ip} ({failure_count} failures)")

        recon_candidates = find_recon_candidates(conn)
        for source_ip, probe_count, first_id, last_id, event_ids in recon_candidates:
            create_recon_alert(conn, source_ip, probe_count, first_id, last_id, event_ids)
            print(f"ALERT: ssh_recon_scan from {source_ip} ({probe_count} probes)")

        web_candidates = find_web_attack_candidates(conn)
        for source_ip, request_count, first_id, last_id, event_ids in web_candidates:
            create_web_attack_alert(conn, source_ip, request_count, first_id, last_id, event_ids)
            print(f"ALERT: web_attack_probing from {source_ip} ({request_count} requests)")

        time.sleep(POLL_INTERVAL_SECONDS)

if __name__ == "__main__":
    run()
