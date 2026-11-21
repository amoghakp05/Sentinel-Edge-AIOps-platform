-- ============================================================
-- C4: SaaS database schema (Postgres-compatible; works with SQLite for dev)
-- ============================================================

-- Tenants
CREATE TABLE IF NOT EXISTS tenants (
    id     TEXT PRIMARY KEY,
    name   TEXT NOT NULL,
    region TEXT NOT NULL
);

-- Registered collectors per tenant
CREATE TABLE IF NOT EXISTS collectors (
    id              TEXT PRIMARY KEY,
    tenant_id       TEXT NOT NULL REFERENCES tenants(id),
    api_key_hash    TEXT NOT NULL,  -- bcrypt / argon2 hash of the API key
    hmac_secret_ref TEXT NOT NULL,  -- reference to secret store key (never the value)
    last_seen       TEXT,
    version         TEXT,
    status          TEXT NOT NULL DEFAULT 'unknown',
    cpu             REAL,
    mem             REAL,
    queue_depth     INTEGER,
    config_hash     TEXT
);

-- Time-series metrics (primary key deduplicates on tenant + payload)
CREATE TABLE IF NOT EXISTS metrics (
    tenant_id       TEXT NOT NULL,
    payload_id      TEXT NOT NULL,
    collector_id    TEXT NOT NULL,
    source_ref      TEXT NOT NULL,
    category        TEXT NOT NULL,
    value           REAL,
    unit            TEXT,
    event_time_utc  TEXT NOT NULL,
    received_at     TEXT NOT NULL,
    PRIMARY KEY (tenant_id, payload_id)
);

-- General event stream (alerts, heartbeats, security summaries)
CREATE TABLE IF NOT EXISTS events (
    tenant_id       TEXT NOT NULL,
    payload_id      TEXT NOT NULL,
    kind            TEXT NOT NULL,
    category        TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    context         TEXT,
    event_time_utc  TEXT NOT NULL,
    received_at     TEXT NOT NULL,
    UNIQUE (tenant_id, payload_id)
);

-- Current health state per entity
CREATE TABLE IF NOT EXISTS health_state (
    tenant_id  TEXT NOT NULL,
    entity_id  TEXT NOT NULL,  -- collector_id or source_ref
    state      TEXT NOT NULL,  -- Excellent | Good | Fair | Poor
    reason     TEXT NOT NULL,
    updated_utc TEXT NOT NULL,
    PRIMARY KEY (tenant_id, entity_id)
);

-- Health state transitions (append-only audit trail)
CREATE TABLE IF NOT EXISTS health_history (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id  TEXT NOT NULL,
    entity_id  TEXT NOT NULL,
    from_state TEXT NOT NULL,
    to_state   TEXT NOT NULL,
    reason     TEXT NOT NULL,
    at_utc     TEXT NOT NULL
);

-- Per-tenant configurable thresholds
CREATE TABLE IF NOT EXISTS thresholds (
    tenant_id   TEXT NOT NULL,
    category    TEXT NOT NULL,
    fair_at     REAL NOT NULL,
    poor_at     REAL NOT NULL,
    stale_fair_s  INTEGER NOT NULL DEFAULT 30,
    stale_poor_s  INTEGER NOT NULL DEFAULT 60,
    PRIMARY KEY (tenant_id, category)
);

-- EWMA anomalies detected on the collector or SaaS side
CREATE TABLE IF NOT EXISTS anomalies (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id        TEXT NOT NULL,
    source_ref       TEXT NOT NULL,
    category         TEXT NOT NULL,
    observed         REAL NOT NULL,
    baseline         REAL NOT NULL,
    zscore           REAL NOT NULL,
    contributing_json TEXT,
    confidence       REAL NOT NULL DEFAULT 0.0,
    at_utc           TEXT NOT NULL
);

-- Persistent baselines across restarts (EWMA, rolling median/MAD, 168h diurnal buckets)
CREATE TABLE IF NOT EXISTS baselines (
    tenant_id    TEXT NOT NULL,
    source_ref   TEXT NOT NULL,
    category     TEXT NOT NULL,
    state_json   TEXT NOT NULL,
    updated_utc  TEXT NOT NULL,
    PRIMARY KEY (tenant_id, source_ref, category)
);

-- AIOps incidents (correlated from multiple alerts)
CREATE TABLE IF NOT EXISTS incidents (
    id                   TEXT PRIMARY KEY,
    tenant_id            TEXT NOT NULL,
    title                TEXT NOT NULL,
    severity             TEXT NOT NULL,
    status               TEXT NOT NULL DEFAULT 'open',
    root_cause_candidate TEXT,
    affected_json        TEXT,
    suppressed_count     INTEGER NOT NULL DEFAULT 0,
    opened_utc           TEXT NOT NULL,
    updated_utc          TEXT NOT NULL
);

-- Maps individual payload events to incidents (many-to-many)
CREATE TABLE IF NOT EXISTS incident_events (
    incident_id TEXT NOT NULL,
    payload_id  TEXT NOT NULL,
    PRIMARY KEY (incident_id, payload_id)
);

-- Explainable recommendations attached to incidents
CREATE TABLE IF NOT EXISTS recommendations (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id   TEXT NOT NULL,
    pattern       TEXT NOT NULL,
    likely_cause  TEXT NOT NULL,
    action        TEXT NOT NULL,
    signals_json  TEXT,
    confidence    REAL NOT NULL DEFAULT 0.0,
    reasoning_json TEXT
);

-- Governed remediation actions (simulated only)
CREATE TABLE IF NOT EXISTS remediation_actions (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id        TEXT NOT NULL DEFAULT 'acme',
    incident_id      TEXT,
    recommendation_id INTEGER,
    action_name      TEXT NOT NULL DEFAULT '',
    target_entity    TEXT NOT NULL DEFAULT '',
    scope            TEXT NOT NULL DEFAULT 'single_host',
    state            TEXT NOT NULL DEFAULT 'proposed', -- proposed|awaiting_approval|approved|executed|rejected|rolled_back|blocked
    policy_result    TEXT,
    approved_by      TEXT,
    approved_at      TEXT,
    rollback_plan    TEXT,
    executed_at      TEXT,
    execution_result TEXT,
    rolled_back_at   TEXT,
    created_at       TEXT,
    updated_at       TEXT
);

-- Immutable audit log
CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id   TEXT NOT NULL,
    actor       TEXT NOT NULL,
    action      TEXT NOT NULL,
    detail_json TEXT,
    at_utc      TEXT NOT NULL
);
