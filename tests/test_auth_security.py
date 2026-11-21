"""
tests/test_auth_security.py
───────────────────────────
Regression suite for security token authentication, tenant binding, and DOM purge.

Requirements Tested:
1. No token, wrong token, and expired token return 401 on EVERY API route including SSE.
2. Single-use short-lived SSE ticket mechanics (no secret tokens in URLs/logs, single-use, expiry).
3. Acme token cannot read Globex data:
   - Queries with Acme token return zero Globex records.
   - Using Acme token with Globex selected (X-Tenant-Id: globex) returns 403 Forbidden.
4. After failed login or logout, the DOM purges all charts, tables, counters, and storage (UI test).
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Generator

import pytest
from starlette.exceptions import HTTPException
from starlette.requests import Request

from saas.api import (
    _SSE_TICKETS,
    api_reset_remediation,
    approve_remediation,
    create_sse_ticket,
    get_collectors,
    get_health,
    get_health_history,
    get_incident,
    get_metrics_series,
    get_mock_infra_state,
    get_remediation_audit,
    get_remediations,
    get_security_events,
    get_thresholds,
    get_whoami,
    health_stream,
    list_incidents,
    propose_remediation,
    reject_remediation,
    resolve_tenant_id,
    rollback_remediation,
    update_thresholds,
)
from saas.db import get_connection, init_db
from saas.ingest import handle_ingest
from tests.test_tenant_isolation import sign_payload


@pytest.fixture(autouse=True)
def setup_test_environment(tmp_path: Path, monkeypatch) -> Generator[None, None, None]:
    db_file = tmp_path / "saas_auth_security_test.db"
    monkeypatch.setenv("TESTING", "1")
    monkeypatch.setenv("SAAS_DB_PATH", str(db_file))
    monkeypatch.setenv("REGION", "eu")
    monkeypatch.setenv("VIEWER_TOKEN_ACME", "test-token-acme-secret-999")
    monkeypatch.setenv("VIEWER_TOKEN_GLOBEX", "test-token-globex-secret-888")

    init_db("eu")
    _SSE_TICKETS.clear()
    yield
    _SSE_TICKETS.clear()


ENDPOINT_CALLS = [
    ("get_health", lambda req: get_health(request=req, evaluate_now=False)),
    ("get_health_history", lambda req: get_health_history(request=req)),
    ("get_thresholds", lambda req: get_thresholds(request=req)),
    ("update_thresholds", lambda req: update_thresholds(request=req, body=[])),
    ("list_incidents", lambda req: list_incidents(request=req)),
    ("get_incident", lambda req: get_incident("inc-test-01", request=req)),
    ("get_collectors", lambda req: get_collectors(request=req)),
    ("get_metrics_series", lambda req: get_metrics_series(request=req)),
    ("get_security_events", lambda req: get_security_events(request=req)),
    ("get_remediations", lambda req: get_remediations(request=req)),
    ("propose_remediation", lambda req: propose_remediation(request=req, payload={"action_name": "restart_service"})),
    ("approve_remediation", lambda req: approve_remediation(1, request=req)),
    ("reject_remediation", lambda req: reject_remediation(1, request=req)),
    ("rollback_remediation", lambda req: rollback_remediation(1, request=req)),
    ("get_remediation_audit", lambda req: get_remediation_audit(request=req)),
    ("get_mock_infra_state", lambda req: get_mock_infra_state(request=req)),
    ("api_reset_remediation", lambda req: api_reset_remediation(request=req)),
    ("create_sse_ticket", lambda req: create_sse_ticket(request=req)),
    ("get_whoami", lambda req: get_whoami(request=req)),
]


def make_request(headers: list[tuple[bytes, bytes]] | None = None, query: str = "") -> Request:
    return Request({
        "type": "http",
        "method": "GET",
        "url": f"http://localhost:8000/api?{query}",
        "headers": headers or [],
        "query_string": query.encode("utf-8"),
    })


def run_coroutine(coro):
    """Executes coroutine synchronously up to first yield/exception (no asyncio loop needed)."""
    try:
        coro.send(None)
    except StopIteration as exc:
        return exc.value


# ── 1. Every route returns 401 for Missing, Wrong, and Expired Tokens ──────────

@pytest.mark.parametrize("name,call_fn", ENDPOINT_CALLS)
def test_all_routes_reject_missing_token_with_401(name: str, call_fn):
    """Calling any protected endpoint without credentials must return 401."""
    req = make_request(headers=[])
    with pytest.raises(HTTPException) as exc_info:
        call_fn(req)
    assert exc_info.value.status_code == 401, f"{name} did not return 401 on missing token"


@pytest.mark.parametrize("name,call_fn", ENDPOINT_CALLS)
def test_all_routes_reject_wrong_token_with_401(name: str, call_fn):
    """Calling any protected endpoint with an invalid token must return 401."""
    req = make_request(headers=[(b"x-api-key", b"completely-invalid-bogus-token-xyz")])
    with pytest.raises(HTTPException) as exc_info:
        call_fn(req)
    assert exc_info.value.status_code == 401, f"{name} did not return 401 on invalid token"


@pytest.mark.parametrize("name,call_fn", ENDPOINT_CALLS)
def test_all_routes_reject_expired_token_with_401(name: str, call_fn):
    """Calling any protected endpoint with an expired token must return 401."""
    req = make_request(headers=[(b"x-api-key", b"viewer-token-expired-at-epoch-1234")])
    with pytest.raises(HTTPException) as exc_info:
        call_fn(req)
    assert exc_info.value.status_code == 401, f"{name} did not return 401 on expired token"


# ── 2. SSE Authentication & Single-Use Short-Lived Ticket Tests ────────────────

def test_sse_stream_rejects_missing_wrong_and_expired_credentials():
    """SSE endpoint health_stream rejects missing, wrong, and expired tickets/headers with 401."""
    # A. Missing credentials
    with pytest.raises(HTTPException) as exc_a:
        run_coroutine(health_stream(make_request()))
    assert exc_a.value.status_code == 401

    # B. Wrong ticket in query parameter
    with pytest.raises(HTTPException) as exc_b:
        run_coroutine(health_stream(make_request(), ticket="bogus-random-ticket"))
    assert exc_b.value.status_code == 401

    # C. Expired ticket
    _SSE_TICKETS["expired-ticket-test"] = ("acme", time.time() - 10.0)
    with pytest.raises(HTTPException) as exc_c:
        run_coroutine(health_stream(make_request(), ticket="expired-ticket-test"))
    assert exc_c.value.status_code == 401

    # D. Wrong X-Api-Key header
    with pytest.raises(HTTPException) as exc_d:
        run_coroutine(health_stream(make_request(headers=[(b"x-api-key", b"invalid-token")])))
    assert exc_d.value.status_code == 401

    # E. Expired token in header
    with pytest.raises(HTTPException) as exc_e:
        run_coroutine(health_stream(make_request(headers=[(b"x-api-key", b"token-expired")])))
    assert exc_e.value.status_code == 401


def test_sse_ticket_generation_and_single_use_enforcement():
    """SSE ticket can be requested via POST, used once to connect, and cannot be replayed."""
    acme_tok = os.environ["VIEWER_TOKEN_ACME"]
    auth_req = make_request(headers=[(b"x-api-key", acme_tok.encode())])

    # 1. Request ticket via POST with token in header
    ticket_resp = create_sse_ticket(auth_req)
    assert ticket_resp.status_code == 200
    ticket_data = json.loads(ticket_resp.body.decode("utf-8"))
    assert ticket_data["status"] == "ok"
    ticket = ticket_data["ticket"]
    assert ticket.startswith("sse-")

    # 2. Connect with ticket: stream opens successfully
    stream_resp = run_coroutine(health_stream(make_request(), ticket=ticket))
    assert stream_resp.status_code == 200

    # 3. Attempting to replay the exact same ticket MUST fail with 401 (single-use!)
    with pytest.raises(HTTPException) as exc_replay:
        run_coroutine(health_stream(make_request(), ticket=ticket))
    assert exc_replay.value.status_code == 401


def test_sse_ticket_cross_tenant_mismatch_returns_403():
    """An SSE ticket for Acme used while Globex is selected (tenant=globex) returns 403."""
    acme_tok = os.environ["VIEWER_TOKEN_ACME"]
    ticket_resp = create_sse_ticket(make_request(headers=[(b"x-api-key", acme_tok.encode())]))
    ticket = json.loads(ticket_resp.body.decode("utf-8"))["ticket"]

    # Request with tenant=globex mismatch
    with pytest.raises(HTTPException) as exc_info:
        run_coroutine(health_stream(make_request(), ticket=ticket, tenant="globex"))
    assert exc_info.value.status_code == 403


# ── 3. Tenant Binding: Acme Token Cannot Read Globex Data ──────────────────────

def test_acme_token_cannot_read_globex_data_and_tenant_mismatch_returns_403():
    """
    Requirements:
    - Ingest data under Globex.
    - Querying with Acme token returns 0 Globex items.
    - Querying with Acme token while Globex is selected (X-Tenant-Id: globex) returns 403.
    """
    # 1. Seed Globex metrics and collectors in DB
    conn = get_connection()
    conn.execute(
        """
        INSERT OR REPLACE INTO metrics (tenant_id, payload_id, collector_id, source_ref, category, value, unit, event_time_utc, received_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "globex",
            "018d9f10-1111-7000-8000-000000000001",
            "col-globex-in-1",
            "srv-globex-in-01",
            "cpu",
            78.5,
            "%",
            "2026-11-20T12:00:00Z",
            "2026-11-20T12:00:01Z",
        ),
    )
    conn.execute(
        """
        INSERT OR REPLACE INTO collectors (id, tenant_id, api_key_hash, hmac_secret_ref, version, status, last_seen, config_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "col-globex-in-1",
            "globex",
            "dummy_hash",
            "dummy_secret",
            "1.0.0",
            "active",
            "2026-11-20T12:00:00Z",
            "conf123",
        ),
    )
    conn.commit()
    conn.close()

    acme_tok = os.environ["VIEWER_TOKEN_ACME"]
    globex_tok = os.environ["VIEWER_TOKEN_GLOBEX"]

    # 2. Globex token can read Globex metrics
    globex_req = make_request(headers=[(b"x-api-key", globex_tok.encode())])
    globex_resp = get_metrics_series(request=globex_req)
    assert globex_resp.status_code == 200
    globex_metrics = json.loads(globex_resp.body.decode("utf-8"))["metrics"]
    assert len(globex_metrics["cpu"]["data"]) == 1

    # 3. Acme token querying metrics gets ZERO Globex records
    acme_req = make_request(headers=[(b"x-api-key", acme_tok.encode())])
    acme_resp = get_metrics_series(request=acme_req)
    assert acme_resp.status_code == 200
    acme_metrics = json.loads(acme_resp.body.decode("utf-8"))["metrics"]
    assert len(acme_metrics["cpu"]["data"]) == 0

    # 4. Acme token querying collectors gets ZERO Globex collectors
    col_resp = get_collectors(request=acme_req)
    assert col_resp.status_code == 200
    collectors = json.loads(col_resp.body.decode("utf-8"))["collectors"]
    assert not any(c["id"] == "col-globex-in-1" for c in collectors)

    # 5. Using Acme token while Globex is selected (X-Tenant-Id: globex) MUST return 403 Forbidden
    mismatch_req = make_request(headers=[
        (b"x-api-key", acme_tok.encode()),
        (b"x-tenant-id", b"globex"),
    ])
    with pytest.raises(HTTPException) as exc_info:
        get_health(request=mismatch_req, evaluate_now=False)
    assert exc_info.value.status_code == 403

    # 6. /api/whoami returns 403 when token does not match selected tenant
    with pytest.raises(HTTPException) as exc_whoami:
        get_whoami(request=mismatch_req)
    assert exc_whoami.value.status_code == 403


# ── 4. UI DOM Test: Failed Login Purges All Rendered Data ─────────────────────

@pytest.mark.skipif(not shutil.which("node"), reason="Node.js is not installed on this host")
def test_after_failed_login_ui_dom_contains_no_previous_data():
    """
    Executes the headless dashboard DOM test via Node.js:
    Verifies that after failed login:
    - Stored token is cleared from sessionStorage
    - All Chart.js charts have their labels and datasets cleared
    - All tables (health, collectors, incidents, history, security, thresholds, remediation)
      have their previous rows purged and replaced with the Unauthorized placeholder
    - Fleet and security counters are reset to 0
    - Active SSE connection is closed
    """
    script_path = Path(__file__).resolve().parent / "test_ui_failed_login.js"
    assert script_path.exists()

    result = subprocess.run(
        ["node", str(script_path)],
        capture_output=True,
        text=True,
        timeout=15,
    )
    print(result.stdout)
    if result.returncode != 0:
        print("STDERR:", result.stderr)
    assert result.returncode == 0
    assert "PASS: All DOM state, charts, tables, counters, and session storage purged" in result.stdout
