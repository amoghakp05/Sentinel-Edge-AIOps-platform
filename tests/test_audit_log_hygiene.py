"""
tests/test_audit_log_hygiene.py
───────────────────────────────
Audit verification test suite:
Ensures that no logger.*, print(), traceback, or exception handler in /collector
or /saas outputs a payload body, raw text, source IP/hostname, context string, or secret,
even during forced failure scenarios across the entire pipeline.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import pytest

from collector.db import get_db
from collector.models import RawRecord
from collector.normalize import normalize_and_store
from collector.outbox import enqueue as outbox_enqueue
from collector.policy import enforce_policy
from collector.uuidv7 import uuidv7
from saas.db import get_connection as get_saas_connection, init_db as init_saas_db
from saas.ingest import handle_ingest, reset_ingest_state_for_tests


def compute_hmac_sig(body_bytes: bytes, secret: str = "secret-acme-eu1") -> str:
    """Computes genuine HMAC-SHA256 signature."""
    return hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()


@pytest.fixture(autouse=True)
def setup_isolated_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Configures isolated databases and testing environment."""
    col_db = tmp_path / "collector_hygiene.db"
    saas_db = tmp_path / "saas_hygiene.db"

    monkeypatch.setenv("COLLECTOR_DB_PATH", str(col_db))
    monkeypatch.setenv("SAAS_DB_PATH", str(saas_db))
    monkeypatch.setenv("REGION", "eu")
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("VIEWER_TOKEN_ACME", "tok-acme-test-secret-safe-1234")
    monkeypatch.setenv("VIEWER_TOKEN_GLOBEX", "tok-globex-test-secret-safe-5678")

    get_db()
    init_saas_db()
    reset_ingest_state_for_tests()


def test_fake_secret_and_ip_pipeline_leak_audit(caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture):
    """
    Sends a payload containing a fake secret and a fake IP through the entire pipeline
    (including forced failures), asserting neither string appears anywhere in
    captured logs (all levels down to DEBUG), stdout, or stderr.
    """
    caplog.set_level(logging.DEBUG)

    FAKE_SECRET_AWS = "AKIAIOSFODNN7EXAMPLE"
    FAKE_SECRET_PWD = "SuperSecretP@ssw0rd999!"
    FAKE_IP = "198.51.100.42"
    FAKE_HOSTNAME = "db-primary.confidential-internal.net"

    # ──────────────────────────────────────────────────────────────────────────
    # 1. Collector Normalization (Raw Record with Fake IP & Secret)
    # ──────────────────────────────────────────────────────────────────────────
    raw_rec = RawRecord(
        ts=datetime.now(timezone.utc),
        adapter="syslog",
        source=FAKE_IP,
        source_tz="UTC",
        category="auth",
        value=1.0,
        unit="count",
        raw_text=f"Failed password for invalid user root from {FAKE_IP} port 5432 ssh2 with key {FAKE_SECRET_AWS}",
    )
    normalize_and_store(raw_rec)

    # ──────────────────────────────────────────────────────────────────────────
    # 2. Collector Egress Policy Validation & Forced Block
    # ──────────────────────────────────────────────────────────────────────────
    bad_payload: Dict[str, Any] = {
        "payload_id": uuidv7(),
        "schema_version": 1,
        "collector_id": "col-acme-eu-1",
        "event_time_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_tz": "UTC",
        "sent_time_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_ref": "h_1234abcd",
        "kind": "alert",
        "category": "auth",
        "severity": "critical",
        "value": 1.0,
        "unit": "count",
        "window_s": 5,
        "context": f"alert on host {FAKE_HOSTNAME} with secret {FAKE_SECRET_PWD} from ip {FAKE_IP}",
    }

    # Policy enforcement must reject this payload
    allowed, filtered, reason = enforce_policy(bad_payload)
    assert allowed is False
    assert "Secret pattern detected" in (reason or "")

    # Forced Outbox enqueue failure
    with pytest.raises(ValueError, match="Payload rejected by egress policy"):
        outbox_enqueue(bad_payload)

    # ──────────────────────────────────────────────────────────────────────────
    # 3. SaaS Ingestion Forced Failures
    # ──────────────────────────────────────────────────────────────────────────
    # Failure A: Ingest payload with secret tripping secret scanner
    ingest_body_secret = json.dumps({
        "payloads": [
            {
                "payload_id": uuidv7(),
                "collector_id": "col-acme-eu-1",
                "category": "auth",
                "event_time_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "value": 1.0,
                "context": f"secret token {FAKE_SECRET_AWS} leaked from {FAKE_IP}",
            }
        ]
    }).encode("utf-8")

    code, resp = handle_ingest(
        api_key="key-acme-eu1-dev",
        signature=compute_hmac_sig(ingest_body_secret),
        body_bytes=ingest_body_secret,
    )
    assert code == 400
    assert "tripped secret scanner" in resp.get("error", "")

    # Failure B: Ingest payload with unknown key containing fake IP and fake secret
    ingest_body_unknown_key = json.dumps({
        "payloads": [
            {
                "payload_id": uuidv7(),
                "collector_id": "col-acme-eu-1",
                "category": "cpu",
                "value": 45.0,
                FAKE_IP: FAKE_SECRET_PWD,  # Malicious attacker key
            }
        ]
    }).encode("utf-8")

    code, resp = handle_ingest(
        api_key="key-acme-eu1-dev",
        signature=compute_hmac_sig(ingest_body_unknown_key),
        body_bytes=ingest_body_unknown_key,
    )
    assert code == 400
    assert "unknown field" in resp.get("error", "").lower()

    # Failure C: Ingest with bad signature (Authentication failure)
    code, resp = handle_ingest(
        api_key="key-acme-eu1-dev",
        signature="invalid_bad_sig_12345",
        body_bytes=ingest_body_secret,
    )
    assert code == 401

    # Failure D: Ingest with malformed JSON embedding fake secret and fake IP
    malformed_body = f'{{"payloads": [{{"secret": "{FAKE_SECRET_AWS}", "ip": "{FAKE_IP}"}}, broken'.encode("utf-8")
    code, resp = handle_ingest(
        api_key="key-acme-eu1-dev",
        signature=compute_hmac_sig(malformed_body),
        body_bytes=malformed_body,
    )
    assert code == 400
    assert resp.get("error") == "Invalid JSON body format"

    # ──────────────────────────────────────────────────────────────────────────
    # 4. SaaS Clean Ingestion & AIOps Evaluation
    # ──────────────────────────────────────────────────────────────────────────
    clean_ingest_body = json.dumps({
        "payloads": [
            {
                "payload_id": uuidv7(),
                "collector_id": "col-acme-eu-1",
                "category": "cpu",
                "event_time_utc": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "value": 42.0,
                "kind": "metric",
                "source_ref": "h_9f3a1c2e",
            }
        ]
    }).encode("utf-8")

    code, resp = handle_ingest(
        api_key="key-acme-eu1-dev",
        signature=compute_hmac_sig(clean_ingest_body),
        body_bytes=clean_ingest_body,
    )
    assert code == 200

    # ──────────────────────────────────────────────────────────────────────────
    # 5. Strict Assertions: Zero Leaks in Logs, Stdout, or Stderr
    # ──────────────────────────────────────────────────────────────────────────
    captured = capsys.readouterr()
    stdout_text = captured.out
    stderr_text = captured.err
    log_text = caplog.text

    all_emitted_text = f"{log_text}\n{stdout_text}\n{stderr_text}"

    # Assert neither fake secret nor fake IP/hostname appears in any emitted stream
    assert FAKE_SECRET_AWS not in all_emitted_text, f"Leak detected: {FAKE_SECRET_AWS} found in logs/output!"
    assert FAKE_SECRET_PWD not in all_emitted_text, f"Leak detected: {FAKE_SECRET_PWD} found in logs/output!"
    assert FAKE_IP not in all_emitted_text, f"Leak detected: {FAKE_IP} found in logs/output!"
    assert FAKE_HOSTNAME not in all_emitted_text, f"Leak detected: {FAKE_HOSTNAME} found in logs/output!"
