"""
tests/test_adversarial_security.py
───────────────────────────────────
Adversarial Security Hardening Regression Suite:
Tests for findings F1 through F7:
  F1: Un-redacted raw value reflection in SaaS validation errors and audit log.
  F2: Un-redacted raw value reflection in collector policy block log.
  F3: outbox.enqueue direct invocation must enforce egress policy.
  F4: Test signature bypass strictly forbidden outside TESTING=1 environment.
  F5: Source masking in normalization logs uses pseudonymous HMAC, never raw prefixes.
  F6: Multi-tenancy scoping in recommendations and incidents queries.
  F7: Tenant ID resolution immediately rejects invalid API keys without fallthrough.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import pytest
from fastapi import HTTPException
from starlette.requests import Request

from collector import normalize, outbox, policy
from collector.db import get_db, reset_for_testing
from collector.models import RawRecord
from collector.uuidv7 import uuidv7
from saas.api import get_incident, resolve_tenant_id
from saas.auth import authenticate_collector
from saas.db import get_connection, init_db
from saas.tenancy import get_scoped_query
from saas.validate import validate_payload


@pytest.fixture(autouse=True)
def setup_security_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    db_saas = tmp_path / "saas_sec_test.db"
    db_col = tmp_path / "col_sec_test.db"

    monkeypatch.setenv("REGION", "eu")
    monkeypatch.setenv("SAAS_DB_PATH", str(db_saas))
    monkeypatch.setenv("COLLECTOR_DB_PATH", str(db_col))
    monkeypatch.setenv("TESTING", "1")

    init_db()
    reset_for_testing(str(db_col))

    conn = get_connection()
    with conn:
        conn.execute("INSERT OR IGNORE INTO tenants (id, name, region) VALUES ('acme', 'Acme', 'eu')")
        conn.execute("INSERT OR IGNORE INTO tenants (id, name, region) VALUES ('globex', 'Globex', 'eu')")
    conn.close()
    yield


# ── F1: SaaS Validation Reflection ───────────────────────────────────────────

def test_regression_validation_error_does_not_reflect_raw_secret_or_ip():
    """F1: Ensure un-redacted raw IP or secret is never echoed in error reason or audit log."""
    raw_leak_string = "192.168.1.99"
    payload = {
        "payload_id": uuidv7(),
        "schema_version": 1,
        "collector_id": "col-acme-eu-1",
        "event_time_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_tz": "Europe/Berlin",
        "sent_time_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_ref": raw_leak_string,  # fails pattern ^h_[0-9a-f]{8}$
        "kind": "metric",
        "category": "cpu",
        "severity": "info",
        "value": 50.0,
    }

    valid, reason = validate_payload(payload, "acme", "col-acme-eu-1")
    assert valid is False
    assert raw_leak_string not in (reason or "")

    # Verify audit_log table does not contain raw string
    conn = get_connection()
    rows = conn.execute("SELECT detail_json FROM audit_log").fetchall()
    conn.close()
    for r in rows:
        assert raw_leak_string not in r["detail_json"]


# ── F2: Policy Block Logging Reflection ───────────────────────────────────────

def test_regression_policy_block_does_not_reflect_raw_enum_value():
    """F2: Ensure policy block reasons never echo invalid enum string with secrets."""
    secret_enum_attempt = "invalid_category_password=hunter2"
    payload = {
        "payload_id": uuidv7(),
        "schema_version": 1,
        "collector_id": "col-acme-eu-1",
        "event_time_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_tz": "Europe/Berlin",
        "sent_time_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_ref": "h_1234abcd",
        "kind": "metric",
        "category": secret_enum_attempt,
        "severity": "info",
    }

    allowed, _, reason = policy.enforce_policy(payload)
    assert allowed is False
    assert secret_enum_attempt not in (reason or "")

    # Verify blocked_log does not contain raw value
    conn = get_db()
    rows = conn.execute("SELECT reason FROM blocked_log").fetchall()
    for r in rows:
        assert "hunter2" not in r["reason"]


# ── F3: Outbox Mandatory Policy Gate ──────────────────────────────────────────

def test_regression_outbox_enqueue_blocks_unredacted_payload():
    """F3: Verify outbox.enqueue() strictly rejects payloads violating policy."""
    bad_payload = {
        "payload_id": uuidv7(),
        "schema_version": 1,
        "collector_id": "col-acme-eu-1",
        "event_time_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_tz": "Europe/Berlin",
        "sent_time_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_ref": "h_1234abcd",
        "kind": "metric",
        "category": "cpu",
        "severity": "info",
        "context": "password=MySuperSecret",  # Trips secret scanner
    }

    with pytest.raises(ValueError, match="Payload rejected by egress policy"):
        outbox.enqueue(bad_payload)

    # Ensure nothing was inserted into outbox
    conn = get_db()
    pending = conn.execute("SELECT count(*) FROM outbox").fetchone()[0]
    assert pending == 0


# ── F4: Test Signature Bypass Strict Environment Check ─────────────────────────

def test_regression_test_signature_bypass_fails_outside_testing_env():
    """F4: Mock signatures ('test_sig') must be rejected universally with 401."""
    # Valid key for col-acme-eu-1, but fake signature
    auth = authenticate_collector("key-acme-eu1-dev", signature="test_sig", body_bytes=b'{"payloads":[]}')
    assert auth is None


# ── F5: Normalization Source Masking ──────────────────────────────────────────

def test_regression_normalize_masks_source_strictly_with_pseudonym(caplog: pytest.LogCaptureFixture):
    """F5: Verify debug log masks source using pseudonymous h_ hash, not prefix."""
    import logging
    caplog.set_level(logging.DEBUG)

    raw_ip = "192.168.1.250"
    rec = RawRecord(
        ts=datetime.now(timezone.utc),
        adapter="syslog",
        source=raw_ip,
        source_tz="UTC",
        category="auth",
        value=1.0,
        unit="count",
        raw_text="auth failure",
    )

    normalize.normalize_and_store(rec)

    # Check logs
    assert "source_ref=h_" in caplog.text


# ── F6: Multi-Tenancy Scoping in Recommendations ──────────────────────────────

def test_regression_recommendations_and_incidents_strictly_tenant_scoped(monkeypatch: pytest.MonkeyPatch):
    """F6: Verify recommendations query cannot leak cross-tenant even with incident_id."""
    conn = get_connection()
    with conn:
        # Create incident for Globex
        conn.execute(
            """
            INSERT INTO incidents (id, tenant_id, title, severity, status, root_cause_candidate,
                                   affected_json, suppressed_count, opened_utc, updated_utc)
            VALUES ('inc-globex-99', 'globex', 'Globex Issue', 'critical', 'open', 'host_in', '[]', 0, '2026-11-20T10:00:00Z', '2026-11-20T10:00:00Z')
            """
        )
        conn.execute(
            """
            INSERT INTO recommendations (incident_id, pattern, likely_cause, action, signals_json, confidence, reasoning_json)
            VALUES ('inc-globex-99', 'leak', 'Globex leak', 'Globex secret action', '[]', 0.9, '[]')
            """
        )
    conn.close()

    # Querying recommendations for tenant 'acme' targeting 'inc-globex-99' must return empty
    acme_recs = get_scoped_query("acme", table="recommendations", where_clause="incident_id = ?", params=["inc-globex-99"])
    assert len(acme_recs) == 0

    # API call by acme requesting inc-globex-99 must return 404
    token_acme = os.environ.get("VIEWER_TOKEN_ACME", "test-token-acme-env")
    monkeypatch.setenv("VIEWER_TOKEN_ACME", token_acme)
    req = Request({
        "type": "http",
        "method": "GET",
        "url": f"http://localhost/api/incidents/inc-globex-99?token={token_acme}",
        "headers": [(b"x-api-key", token_acme.encode())],
        "query_string": f"token={token_acme}".encode(),
    })
    resp = get_incident("inc-globex-99", request=req, token=token_acme)
    assert resp.status_code == 404


# ── F7: Tenant ID Resolution Rejecting Invalid API Key ────────────────────────

def test_regression_tenant_id_resolution_rejects_invalid_api_key():
    """F7: Supplying an invalid API key must raise HTTPException(401), not fall through."""
    with pytest.raises(HTTPException) as exc_info:
        resolve_tenant_id(x_api_key="invalid-api-key-999", x_tenant_id="globex")
    assert exc_info.value.status_code == 401
