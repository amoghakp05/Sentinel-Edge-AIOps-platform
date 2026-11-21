"""
tests/test_policy.py
────────────────────
Tests for collector/policy.py.

Verifies:
- Unknown fields (like "password", "tenant_id", "internal_ip") are DROPPED.
- Required fields are strictly enforced.
- Secret scanner on all outgoing strings catches leaked keys and blocks the payload.
- Blocked events are written to the 'blocked_log' SQLite table with the reason (never the secret).
"""

from __future__ import annotations

import pytest
from collector.db import get_db
from collector.policy import enforce_policy


@pytest.fixture
def valid_payload():
    return {
        "payload_id": "019349a2-5b98-7c80-87ef-3d9284157a1b",
        "schema_version": 1,
        "collector_id": "col-acme-eu-1",
        "event_time_utc": "2026-11-20T10:00:05Z",
        "source_tz": "Europe/Berlin",
        "sent_time_utc": "2026-11-20T10:00:06Z",
        "source_ref": "h_9f3a1c2e",
        "kind": "metric",
        "category": "cpu",
        "severity": "info",
        "value": 45.2,
        "unit": "percent",
        "window_s": 5,
        "context": "CPU utilisation 45.2% nominal",
    }


def test_valid_payload_passes(valid_payload, tmp_db):
    allowed, filtered, reason = enforce_policy(valid_payload)
    assert allowed is True
    assert reason is None
    assert filtered is not None
    assert filtered["payload_id"] == valid_payload["payload_id"]


def test_drops_injected_password_and_unknown_fields(valid_payload, tmp_db):
    """
    Hard Rule 1: Allow-list, never block-list. Unknown fields are dropped.
    """
    dirty_payload = dict(valid_payload)
    dirty_payload["password"] = "AdminPassword123"
    dirty_payload["tenant_id"] = "acme"
    dirty_payload["internal_ip"] = "192.168.1.1"

    allowed, filtered, reason = enforce_policy(dirty_payload)
    assert allowed is True
    assert "password" not in filtered
    assert "tenant_id" not in filtered
    assert "internal_ip" not in filtered


def test_blocks_payload_with_leaked_key_in_context(valid_payload, tmp_db):
    """
    If a secret pattern appears inside an allow-listed field (e.g. context),
    the policy gate MUST block transmission.
    """
    leaked_payload = dict(valid_payload)
    leaked_payload["context"] = "Error connecting to db password=LeakedSecretKey123 on host"

    allowed, filtered, reason = enforce_policy(leaked_payload)
    assert allowed is False
    assert filtered is None
    assert "Secret pattern detected" in reason

    # Verify blocked_log recorded the rejection without exposing the secret
    conn = get_db()
    row = conn.execute("SELECT reason, payload_id FROM blocked_log ORDER BY id DESC LIMIT 1").fetchone()
    assert row is not None
    assert row["payload_id"] == valid_payload["payload_id"]
    assert "LeakedSecretKey123" not in row["reason"]
    assert "Secret pattern detected" in row["reason"]


def test_blocks_payload_with_raw_ip_in_context(valid_payload, tmp_db):
    """
    Raw IP addresses must not leak into context strings.
    """
    leaked_payload = dict(valid_payload)
    leaked_payload["context"] = "Connection from 192.168.1.15 timed out"

    allowed, filtered, reason = enforce_policy(leaked_payload)
    assert allowed is False
    assert "Secret pattern detected" in reason


def test_missing_required_field_fails(valid_payload, tmp_db):
    bad_payload = dict(valid_payload)
    del bad_payload["collector_id"]

    allowed, filtered, reason = enforce_policy(bad_payload)
    assert allowed is False
    assert "Missing required allow-listed field: 'collector_id'" in reason


def test_invalid_source_ref_pattern_fails(valid_payload, tmp_db):
    bad_payload = dict(valid_payload)
    bad_payload["source_ref"] = "invalid_ref_format"

    allowed, filtered, reason = enforce_policy(bad_payload)
    assert allowed is False
    assert "failed regex pattern" in reason


def test_invalid_enum_fails(valid_payload, tmp_db):
    bad_payload = dict(valid_payload)
    bad_payload["kind"] = "unsupported_kind"

    allowed, filtered, reason = enforce_policy(bad_payload)
    assert allowed is False
    assert "not in allowed enums" in reason
