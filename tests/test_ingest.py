"""
tests/test_ingest.py
────────────────────
Phase 4 Ingest Endpoint & Validation Tests:
- Key authentication & credential-derived tenancy (rejects unknown keys with 401)
- Deduplication idempotency (same batch sent twice -> row count unchanged)
- Server-side allow-list validation (extra "password" field returns 400 + audit log)
- Secret scanner rejection (tripped pattern returns 400 + audit log)
- Heartbeat state tracking (updates collectors.last_seen, version, status)
"""

import hashlib
import hmac
import json
import os
import pytest

from collector.uuidv7 import uuidv7
from saas.auth import authenticate_collector
from saas.db import get_connection, init_db
from saas.ingest import handle_ingest
from saas.tenancy import get_scoped_query


def sign_payload(body_bytes: bytes, secret: str = "secret-acme-eu1") -> str:
    """Computes genuine HMAC-SHA256 signature for test requests."""
    return hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()


@pytest.fixture(autouse=True)
def setup_saas_db(tmp_path, monkeypatch):
    """Isolate SaaS DB for test execution."""
    test_db = tmp_path / "saas_test_eu.db"
    monkeypatch.setenv("SAAS_DB_PATH", str(test_db))
    monkeypatch.setenv("REGION", "eu")
    init_db("eu")
    yield


def test_tenant_derivation_from_key():
    auth = authenticate_collector("key-acme-eu1-dev")
    assert auth is not None
    assert auth == "acme"
    assert auth.tenant_id == "acme"
    assert auth.collector_id == "col-acme-eu-1"


def test_invalid_key_fails():
    auth = authenticate_collector("invalid-key-999")
    assert auth is None


def test_duplicate_batch_sent_twice_row_count_unchanged():
    """Requirement: same batch sent twice -> row count unchanged; acks returned for both."""
    pid1 = uuidv7()
    pid2 = uuidv7()

    batch = {
        "payloads": [
            {
                "payload_id": pid1,
                "schema_version": 1,
                "collector_id": "col-acme-eu-1",
                "event_time_utc": "2026-11-20T10:00:00Z",
                "source_tz": "Europe/Berlin",
                "sent_time_utc": "2026-11-20T10:00:01Z",
                "source_ref": "h_11223344",
                "kind": "metric",
                "category": "cpu",
                "severity": "info",
                "value": 45.2,
                "unit": "percent",
            },
            {
                "payload_id": pid2,
                "schema_version": 1,
                "collector_id": "col-acme-eu-1",
                "event_time_utc": "2026-11-20T10:00:05Z",
                "source_tz": "Europe/Berlin",
                "sent_time_utc": "2026-11-20T10:00:06Z",
                "source_ref": "h_11223344",
                "kind": "metric",
                "category": "memory",
                "severity": "info",
                "value": 68.0,
                "unit": "percent",
            },
        ]
    }
    body_bytes = json.dumps(batch).encode("utf-8")

    # First send
    code1, resp1 = handle_ingest("key-acme-eu1-dev", sign_payload(body_bytes), body_bytes)
    assert code1 == 200
    assert len(resp1["acked"]) == 2
    assert resp1["acked"][0]["payload_id"] == pid1

    # Check metrics count in DB
    rows1 = get_scoped_query("acme", table="metrics")
    assert len(rows1) == 2

    # Resend the exact same batch
    code2, resp2 = handle_ingest("key-acme-eu1-dev", sign_payload(body_bytes), body_bytes)
    assert code2 == 200
    assert len(resp2["acked"]) == 2
    assert resp2["acked"][0]["payload_id"] == pid1
    assert resp2["acked"][0]["ack_hash"] == resp1["acked"][0]["ack_hash"]

    # Verify row count is UNCHANGED (no duplicate rows)
    rows2 = get_scoped_query("acme", table="metrics")
    assert len(rows2) == 2


def test_payload_with_extra_password_field_returns_400():
    """Requirement: payload with extra 'password' field returns 400 plus an audit entry."""
    pid = uuidv7()
    bad_batch = {
        "payloads": [
            {
                "payload_id": pid,
                "schema_version": 1,
                "collector_id": "col-acme-eu-1",
                "event_time_utc": "2026-11-20T10:00:00Z",
                "source_tz": "Europe/Berlin",
                "sent_time_utc": "2026-11-20T10:00:01Z",
                "source_ref": "h_11223344",
                "kind": "metric",
                "category": "cpu",
                "severity": "info",
                "value": 50.0,
                "password": "leaked_super_secret",  # Forbidden unknown field
            }
        ]
    }
    body_bytes = json.dumps(bad_batch).encode("utf-8")

    code, resp = handle_ingest("key-acme-eu1-dev", sign_payload(body_bytes), body_bytes)
    assert code == 400
    assert "password" in resp["error"]

    # Check that an audit log record was created
    audit_rows = get_scoped_query("acme", table="audit_log", where_clause="action = 'VALIDATION_FAILED'")
    assert len(audit_rows) >= 1
    assert "password" in audit_rows[0]["detail_json"]


def test_payload_tripping_secret_scanner_returns_400():
    """Server-side secret scanning rejects strings containing secrets."""
    pid = uuidv7()
    bad_batch = {
        "payloads": [
            {
                "payload_id": pid,
                "schema_version": 1,
                "collector_id": "col-acme-eu-1",
                "event_time_utc": "2026-11-20T10:00:00Z",
                "source_tz": "Europe/Berlin",
                "sent_time_utc": "2026-11-20T10:00:01Z",
                "source_ref": "h_11223344",
                "kind": "alert",
                "severity": "critical",
                "context": "Failed login for admin with password=SuperSecretPassword123",
            }
        ]
    }
    body_bytes = json.dumps(bad_batch).encode("utf-8")

    code, resp = handle_ingest("key-acme-eu1-dev", sign_payload(body_bytes), body_bytes)
    assert code == 400
    assert "secret scanner" in resp["error"].lower()

    # Verify audit log
    audit_rows = get_scoped_query("acme", table="audit_log", where_clause="action = 'VALIDATION_FAILED'")
    assert len(audit_rows) >= 1


def test_heartbeat_updates_collector_state():
    """Heartbeat payloads update collectors.last_seen, version, and status."""
    pid = uuidv7()
    heartbeat_batch = {
        "payloads": [
            {
                "payload_id": pid,
                "schema_version": 1,
                "collector_id": "col-acme-eu-1",
                "event_time_utc": "2026-11-20T12:00:00Z",
                "source_tz": "Europe/Berlin",
                "sent_time_utc": "2026-11-20T12:00:00Z",
                "source_ref": "h_11223344",
                "kind": "heartbeat",
                "category": "connectivity",
                "severity": "info",
                "value": 1.0,
                "unit": "boolean",
                "context": "v1.4.2 cpu=18.5% mem=48.2MB queue=4 cfg=a1b2c3d4",
            }
        ]
    }
    body_bytes = json.dumps(heartbeat_batch).encode("utf-8")

    code, resp = handle_ingest("key-acme-eu1-dev", sign_payload(body_bytes), body_bytes)
    assert code == 200

    collectors = get_scoped_query("acme", table="collectors", where_clause="id = ?", params=["col-acme-eu-1"])
    assert len(collectors) == 1
    col = collectors[0]
    assert col["status"] == "active"
    assert col["version"] == "1.4.2"
    assert col["cpu"] == 18.5
    assert col["mem"] == 48.2
    assert col["queue_depth"] == 4
    assert col["last_seen"] is not None
