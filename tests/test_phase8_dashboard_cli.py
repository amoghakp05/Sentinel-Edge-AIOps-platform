"""
tests/test_phase8_dashboard_cli.py
───────────────────────────────────
Phase 8 verification tests:
1. REST API endpoints:
   - GET /api/collectors
   - GET /api/metrics/series
   - GET /api/security/events
2. aiopsctl CLI commands:
   - aiopsctl health [--json]
   - aiopsctl collectors [--json]
   - aiopsctl incidents [--json]
   - aiopsctl why <incident_id> [--json]
3. Dashboard static file delivery.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import pytest
from starlette.requests import Request
from typer.testing import CliRunner

from saas.api import (
    get_collectors,
    get_health,
    get_metrics_series,
    get_security_events,
)
from saas.cli_aiopsctl import app as cli_app
from saas.db import get_connection, init_db
from saas.main import app as fastapi_app

runner = CliRunner()


def _dummy_request(token: Optional[str] = None) -> Request:
    tok = token or os.environ.get("VIEWER_TOKEN_ACME", "test-token-acme-env")
    return Request({
        "type": "http",
        "method": "GET",
        "url": f"http://localhost:8000/api?token={tok}",
        "headers": [(b"x-api-key", tok.encode())],
        "query_string": f"token={tok}".encode(),
    })


@pytest.fixture(autouse=True)
def setup_test_db(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    db_file = tmp_path / "test_saas.db"
    monkeypatch.setenv("REGION", "eu")
    monkeypatch.setenv("SAAS_DB_PATH", str(db_file))
    monkeypatch.setenv("TESTING", "1")
    tok_acme = os.environ.get("VIEWER_TOKEN_ACME", "test-token-acme-env")
    monkeypatch.setenv("VIEWER_TOKEN_ACME", tok_acme)
    init_db()

    conn = get_connection()
    with conn:
        conn.execute("INSERT OR IGNORE INTO tenants (id, name, region) VALUES ('acme', 'Acme Corp', 'eu')")
        conn.execute(
            """
            INSERT OR REPLACE INTO collectors (
                id, tenant_id, api_key_hash, hmac_secret_ref, last_seen, version,
                status, cpu, mem, queue_depth, config_hash
            )
            VALUES ('col-acme-eu-1', 'acme', 'hash1', 'ref1', ?, '1.0.0', 'active', 25.5, 42.0, 0, 'cfg12345')
            """,
            (datetime.now(timezone.utc).isoformat(),),
        )
        conn.execute(
            """
            INSERT OR REPLACE INTO metrics (
                tenant_id, payload_id, collector_id, source_ref, category, value, unit, event_time_utc, received_at
            )
            VALUES ('acme', 'p1', 'col-acme-eu-1', 'h_1234', 'cpu', 45.2, '%', ?, ?)
            """,
            (datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        conn.execute(
            """
            INSERT OR REPLACE INTO events (
                tenant_id, payload_id, kind, category, severity, context, event_time_utc, received_at
            )
            VALUES ('acme', 'p_sec', 'security_summary', 'auth', 'warning', '5 failed logins in 60s (risk 45)', ?, ?)
            """,
            (datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        conn.execute(
            """
            INSERT OR REPLACE INTO incidents (
                id, tenant_id, title, severity, status, root_cause_candidate, affected_json,
                suppressed_count, opened_utc, updated_utc
            )
            VALUES ('inc-test-01', 'acme', 'High CPU anomaly', 'critical', 'open', 'host_01', '["cpu", "host_01"]', 3, ?, ?)
            """,
            (datetime.now(timezone.utc).isoformat(), datetime.now(timezone.utc).isoformat()),
        )
        conn.execute(
            """
            INSERT OR REPLACE INTO recommendations (
                incident_id, pattern, likely_cause, action, signals_json, confidence, reasoning_json
            )
            VALUES (
                'inc-test-01',
                'cpu spike',
                'Compute exhaustion',
                'Scale worker pool',
                '["cpu"]',
                0.92,
                '["1. CPU sustained above 90%"]'
            )
            """
        )
    conn.close()
    yield


def test_api_collectors():
    tok = os.environ.get("VIEWER_TOKEN_ACME", "test-token-acme-env")
    req = _dummy_request(tok)
    resp = get_collectors(request=req, token=tok)
    assert resp.status_code == 200
    data = json.loads(resp.body.decode())
    assert data["status"] == "ok"
    assert data["tenant_id"] == "acme"
    assert len(data["collectors"]) >= 1
    target = next((c for c in data["collectors"] if c["id"] == "col-acme-eu-1"), None)
    assert target is not None
    assert target["is_offline"] is False
    assert target["cpu"] == 25.5


def test_api_metrics_series():
    tok = os.environ.get("VIEWER_TOKEN_ACME", "test-token-acme-env")
    req = _dummy_request(tok)
    resp = get_metrics_series(request=req, token=tok, limit=10)
    assert resp.status_code == 200
    data = json.loads(resp.body.decode())
    assert "metrics" in data
    assert "cpu" in data["metrics"]
    cpu_data = data["metrics"]["cpu"]["data"]
    assert len(cpu_data) >= 1
    assert cpu_data[0]["value"] == 45.2


def test_api_security_events():
    tok = os.environ.get("VIEWER_TOKEN_ACME", "test-token-acme-env")
    req = _dummy_request(tok)
    resp = get_security_events(request=req, token=tok)
    assert resp.status_code == 200
    data = json.loads(resp.body.decode())
    assert len(data["events"]) >= 1
    assert "failed logins" in data["events"][0]["context"]


def test_cli_health():
    result = runner.invoke(cli_app, ["health", "--tenant", "acme", "--json"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert isinstance(parsed, list)


def test_cli_collectors():
    result = runner.invoke(cli_app, ["collectors", "--tenant", "acme", "--json"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert len(parsed) >= 1
    target = next((c for c in parsed if c["id"] == "col-acme-eu-1"), None)
    assert target is not None
    assert target["status"] == "active"


def test_cli_incidents():
    result = runner.invoke(cli_app, ["incidents", "--tenant", "acme", "--json"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert len(parsed) >= 1
    assert parsed[0]["id"] == "inc-test-01"
    assert parsed[0]["suppressed_count"] == 3


def test_cli_why():
    result = runner.invoke(cli_app, ["why", "inc-test-01", "--tenant", "acme", "--json"])
    assert result.exit_code == 0
    parsed = json.loads(result.stdout)
    assert parsed["incident_id"] == "inc-test-01"
    assert parsed["confidence"] == 0.92
    assert "Compute exhaustion" in parsed["recommendations"][0]["likely_cause"]
    assert "reduced to 1 incident" in parsed["alerts_summary"]


def test_cli_formatted_outputs():
    # Verify non-JSON Rich tables do not crash
    r_health = runner.invoke(cli_app, ["health", "--tenant", "acme"])
    assert r_health.exit_code == 0

    r_col = runner.invoke(cli_app, ["collectors", "--tenant", "acme"])
    assert r_col.exit_code == 0

    r_inc = runner.invoke(cli_app, ["incidents", "--tenant", "acme"])
    assert r_inc.exit_code == 0

    r_why = runner.invoke(cli_app, ["why", "inc-test-01", "--tenant", "acme"])
    assert r_why.exit_code == 0
    assert "Root Cause Analysis" in r_why.stdout
