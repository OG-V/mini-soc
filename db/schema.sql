CREATE TABLE IF NOT EXISTS events (
    id SERIAL PRIMARY KEY,
    source_host TEXT NOT NULL,
    source_ip TEXT,
    event_type TEXT NOT NULL,
    username TEXT,
    raw_log TEXT NOT NULL,
    event_time TIMESTAMPTZ NOT NULL,
    ingested_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    alerted BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS alerts (
    id SERIAL PRIMARY KEY,
    rule_name TEXT NOT NULL,
    mitre_technique TEXT,
    source_ip TEXT,
    username TEXT,
    description TEXT NOT NULL,
    first_event_id INTEGER REFERENCES events(id),
    last_event_id INTEGER REFERENCES events(id),
    event_count INTEGER NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
