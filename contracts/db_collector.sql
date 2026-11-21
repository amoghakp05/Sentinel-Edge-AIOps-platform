-- ============================================================
-- C5: Collector-local SQLite schema (WAL mode)
-- ============================================================

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

-- Raw telemetry as received — secrets stay here, never egressed.
CREATE TABLE IF NOT EXISTS raw_events (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    received_at TEXT    NOT NULL,          -- ISO-8601 UTC, set by normalize.py
    source      TEXT    NOT NULL,          -- real host / IP (stays local)
    source_tz   TEXT    NOT NULL DEFAULT 'UTC',
    category    TEXT    NOT NULL,
    value       REAL,                      -- NULL for text-only events (e.g. syslog)
    unit        TEXT,
    raw_text    TEXT,                      -- verbatim line / JSON blob
    adapter     TEXT    NOT NULL           -- 'psutil' | 'sim' | 'syslog'
);

CREATE INDEX IF NOT EXISTS idx_raw_events_received_at
    ON raw_events (received_at DESC);

-- Local reverse mapping of pseudonymous references (NEVER leaves local collector)
CREATE TABLE IF NOT EXISTS source_mapping (
    real_source TEXT PRIMARY KEY,
    source_ref  TEXT NOT NULL UNIQUE,
    created_at  TEXT NOT NULL
);

-- Outbox: written BEFORE sending; marked 'sent' only after SaaS ACK (Phase 3).
CREATE TABLE IF NOT EXISTS outbox (
    payload_id  TEXT PRIMARY KEY,
    body_json   TEXT    NOT NULL,
    status      TEXT    NOT NULL DEFAULT 'pending', -- pending | sent | failed
    attempts    INTEGER NOT NULL DEFAULT 0,
    next_try_at TEXT,                               -- ISO-8601 UTC
    created_at  TEXT    NOT NULL
);

-- Egress log: append-only cryptographic proof of exactly what left the box.
CREATE TABLE IF NOT EXISTS egress_log (
    seq         INTEGER PRIMARY KEY AUTOINCREMENT,
    payload_id  TEXT    NOT NULL,
    ts_utc      TEXT    NOT NULL,
    exact_json  TEXT    NOT NULL,
    sha256      TEXT    NOT NULL,
    destination TEXT    NOT NULL,
    status      TEXT    NOT NULL,          -- sent | error
    saas_ack_hash TEXT                     -- SHA-256 of SaaS response body
);

-- Records payloads blocked by the allow-list policy.
CREATE TABLE IF NOT EXISTS blocked_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts_utc      TEXT    NOT NULL,
    reason      TEXT    NOT NULL,
    payload_id  TEXT
);
