from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import psycopg2
import psycopg2.extras

DB_CONFIG = {
    "host": "localhost",
    "port": 5432,
    "dbname": "soc",
    "user": "soc",
    "password": "socpassword",
}

app = FastAPI(title="Mini SOC API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_connection():
    return psycopg2.connect(**DB_CONFIG)


@app.get("/alerts")
def list_alerts():
    """Return all alerts, most recent first."""
    conn = get_connection()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT id, rule_name, mitre_technique, source_ip, username,
                   description, event_count, created_at, incident_id
            FROM alerts
            ORDER BY created_at DESC
            """
        )
        rows = cur.fetchall()
    conn.close()
    return rows


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: int):
    """Return one alert plus the raw events that triggered it (the evidence trail)."""
    conn = get_connection()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM alerts WHERE id = %s", (alert_id,))
        alert = cur.fetchone()

        if alert is None:
            conn.close()
            raise HTTPException(status_code=404, detail="Alert not found")

        cur.execute(
            """
            SELECT id, event_type, username, source_ip, raw_log, event_time
            FROM events
            WHERE id BETWEEN %s AND %s
            ORDER BY id
            """,
            (alert["first_event_id"], alert["last_event_id"]),
        )
        events = cur.fetchall()

    conn.close()
    alert["events"] = events
    return alert


@app.get("/incidents")
def list_incidents():
    """Return all incidents, most recently active first."""
    conn = get_connection()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT id, source_ip, alert_count, mitre_techniques, status,
                   first_seen, last_seen
            FROM incidents
            ORDER BY last_seen DESC
            """
        )
        rows = cur.fetchall()
    conn.close()
    return rows


@app.get("/incidents/{incident_id}")
def get_incident(incident_id: int):
    """Return one incident plus every alert correlated into it."""
    conn = get_connection()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM incidents WHERE id = %s", (incident_id,))
        incident = cur.fetchone()

        if incident is None:
            conn.close()
            raise HTTPException(status_code=404, detail="Incident not found")

        cur.execute(
            """
            SELECT id, rule_name, mitre_technique, source_ip, username,
                   description, event_count, created_at
            FROM alerts
            WHERE incident_id = %s
            ORDER BY created_at
            """,
            (incident_id,),
        )
        alerts = cur.fetchall()

    conn.close()
    incident["alerts"] = alerts
    return incident


@app.get("/events")
def list_events(limit: int = 50):
    """Return the most recent raw events, newest first."""
    conn = get_connection()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(
            """
            SELECT id, event_type, username, source_ip, raw_log, event_time, alerted
            FROM events
            ORDER BY id DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cur.fetchall()
    conn.close()
    return rows
