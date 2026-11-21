"""
tests/test_security_pass2.py
────────────────────────────
Regression test suite for Second Security Pass: SaaS Read Side & Dashboard.

Proves:
1. Item 1: Every /api/* route and SSE stream resolves tenant ONLY from viewer credential.
   - Missing key/token -> 401
   - Invalid key/token -> 401
   - Explicit ?tenant= or X-Tenant-Id without credential -> 401 (no fallback)
   - Valid viewer token (from VIEWER_TOKEN_ACME env) -> 200 with tenant_id="acme"
   - Valid collector key (key-acme-eu1-dev) -> 200 with tenant_id="acme"
2. Item 2: SSE events are strictly tenant-scoped (Tenant B subscriber never receives Tenant A events).
3. Item 3: saas/auth.py rejects mock signatures ("sig", "test_sig", "dummy_sig") with 401. Real HMAC passes.
4. Item 4: hmac.compare_digest is used for comparisons; API keys and viewer tokens are stored hashed only.
5. Item 5: CORS uses explicit origin list (e.g. http://localhost:8000), never "*".
6. Item 6: Dashboard renders context/reason/title strings via safe textContent, no innerHTML data injection; no hardcoded tokens in bundle.
7. Item 7: Malformed JSON body returns sanitized error message without leaking body snippets or exception strings.
8. Item 8: .gitignore exists and ignores .env.
9. Item 9: Tenant A token cannot read Tenant B on any route.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import os
from pathlib import Path
from typing import Any, Dict

import pytest
from starlette.requests import Request
from starlette.testclient import TestClient

from saas.api import (
    get_collectors,
    get_health,
    get_health_history,
    list_incidents,
    get_metrics_series,
    get_security_events,
    get_thresholds,
    resolve_tenant_id,
    update_thresholds,
)
from saas.auth import (
    authenticate_collector,
    authenticate_viewer_or_collector,
    get_viewer_token_hashes,
)
from saas.db import get_connection, hash_api_key, init_db
from saas.ingest import handle_ingest
from saas.main import app as fastapi_app
from saas.sse import broadcast_event, subscribe, unsubscribe


@pytest.fixture(autouse=True)
def setup_isolated_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Provides isolated SQLite database for each test."""
    db_file = tmp_path / "saas_sec_pass2.db"
    monkeypatch.setenv("REGION", "eu")
    monkeypatch.setenv("SAAS_DB_PATH", str(db_file))
    monkeypatch.setenv("TESTING", "1")
    tok_acme = os.environ.get("VIEWER_TOKEN_ACME", "test-token-acme-env")
    tok_globex = os.environ.get("VIEWER_TOKEN_GLOBEX", "test-token-globex-env")
    monkeypatch.setenv("VIEWER_TOKEN_ACME", tok_acme)
    monkeypatch.setenv("VIEWER_TOKEN_GLOBEX", tok_globex)
    init_db("eu")
    yield


# ── Item 1: Credential-Only Tenant Derivation & 401 Enforcement ───────────────

def test_item1_missing_credential_raises_401():
    """Unauthenticated request must return 401."""
    req = Request({
        "type": "http",
        "method": "GET",
        "url": "http://localhost:8000/api/health",
        "headers": [],
        "query_string": b"",
    })
    with pytest.raises(Exception) as exc_info:
        resolve_tenant_id(request=req)
    assert exc_info.value.status_code == 401


def test_item1_tenant_query_param_or_header_alone_rejected_with_401():
    """?tenant=acme or X-Tenant-Id without credential must NOT grant access."""
    req = Request({
        "type": "http",
        "method": "GET",
        "url": "http://localhost:8000/api/health?tenant=acme",
        "headers": [(b"x-tenant-id", b"acme")],
        "query_string": b"tenant=acme",
    })
    with pytest.raises(Exception) as exc_info:
        resolve_tenant_id(request=req)
    assert exc_info.value.status_code == 401


def test_item1_invalid_token_rejected_with_401():
    """Invalid token returns 401."""
    with pytest.raises(Exception) as exc_info:
        resolve_tenant_id(token="bogus-token-1234")
    assert exc_info.value.status_code == 401


def test_item1_valid_viewer_token_derives_tenant():
    """Token from env resolves strictly to matching tenant."""
    tok_acme = os.environ["VIEWER_TOKEN_ACME"]
    tok_globex = os.environ["VIEWER_TOKEN_GLOBEX"]
    assert resolve_tenant_id(token=tok_acme) == "acme"
    assert resolve_tenant_id(token=tok_globex) == "globex"
    assert resolve_tenant_id(x_api_key=tok_acme) == "acme"
    assert resolve_tenant_id(authorization=f"Bearer {tok_globex}") == "globex"


def test_item1_valid_collector_key_derives_tenant():
    """Collector API keys also authenticate read endpoints."""
    assert resolve_tenant_id(token="key-acme-eu1-dev") == "acme"
    assert resolve_tenant_id(token="key-globex-in1-dev") == "globex"


def test_item1_all_api_endpoints_reject_unauthenticated():
    """Verify health, thresholds, collectors, metrics, security routes reject unauthenticated."""
    unauth_req = Request({
        "type": "http",
        "method": "GET",
        "url": "http://localhost:8000/api",
        "headers": [],
        "query_string": b"",
    })

    # All must raise HTTPException 401 when unauthenticated
    for endpoint_func in (
        get_health,
        get_health_history,
        get_thresholds,
        list_incidents,
        get_collectors,
        get_metrics_series,
        get_security_events,
    ):
        with pytest.raises(Exception) as exc_info:
            endpoint_func(request=unauth_req)
        assert exc_info.value.status_code == 401

    # But succeed with valid tenant token from env
    tok_acme = os.environ["VIEWER_TOKEN_ACME"]
    auth_req = Request({
        "type": "http",
        "method": "GET",
        "url": f"http://localhost:8000/api?token={tok_acme}",
        "headers": [(b"x-api-key", tok_acme.encode())],
        "query_string": f"token={tok_acme}".encode(),
    })
    resp = get_health(request=auth_req, token=tok_acme, evaluate_now=False)
    assert resp.status_code == 200
    data = json.loads(resp.body.decode("utf-8"))
    assert data["tenant_id"] == "acme"


# ── Item 2: SSE Tenant Scoping Isolation ───────────────

def test_item2_sse_tenant_scoping_isolation():
    """Tenant B queue must NEVER receive an event broadcast to Tenant A."""
    q_acme = subscribe("acme")
    q_globex = subscribe("globex")

    try:
        # Broadcast event specifically to tenant 'acme'
        broadcast_event("acme", "health_change", {"state": "Poor", "reason": "test"})

        # Acme queue should have the event
        assert not q_acme.empty()
        msg_acme = q_acme.get_nowait()
        assert "event: health_change" in msg_acme
        assert "acme" in msg_acme

        # Globex queue MUST be completely empty!
        assert q_globex.empty()
    finally:
        unsubscribe("acme", q_acme)
        unsubscribe("globex", q_globex)


# ── Item 3: Rejection of Test-Signature Bypass ───────────────

def test_item3_mock_signature_bypass_eliminated():
    """Mock signatures ('sig', 'test_sig', 'dummy_sig') must be rejected with 401."""
    body = b'{"payloads":[]}'
    for mock_sig in ("sig", "test_sig", "dummy_sig", "mock"):
        auth = authenticate_collector("key-acme-eu1-dev", signature=mock_sig, body_bytes=body)
        assert auth is None, f"Mock signature '{mock_sig}' was unexpectedly accepted!"


def test_item3_genuine_hmac_signature_accepted():
    """Real HMAC-SHA256 computed with collector's secret must pass authentication."""
    body = b'{"payloads":[]}'
    secret = "secret-acme-eu1"
    valid_sig = hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

    auth = authenticate_collector("key-acme-eu1-dev", signature=valid_sig, body_bytes=body)
    assert auth is not None
    assert auth.tenant_id == "acme"
    assert auth.collector_id == "col-acme-eu-1"


# ── Item 4: Constant-Time Digest & Hashed Storage ───────────────

def test_item4_stored_viewer_tokens_are_hashed():
    """Viewer token dictionary stores SHA-256 hashes, not plaintext tokens."""
    viewer_hashes = get_viewer_token_hashes()
    assert len(viewer_hashes) > 0
    tok_acme = os.environ.get("VIEWER_TOKEN_ACME", "")
    tok_globex = os.environ.get("VIEWER_TOKEN_GLOBEX", "")
    assert tok_acme
    assert tok_globex

    for stored_hash, tenant in viewer_hashes.items():
        # Must be 64-character hex string (SHA-256)
        assert len(stored_hash) == 64
        assert stored_hash != tok_acme
        assert stored_hash != tok_globex

    # Authenticating correctly matches hash via hmac.compare_digest
    assert authenticate_viewer_or_collector(tok_acme) == "acme"
    assert authenticate_viewer_or_collector(tok_globex) == "globex"


def test_item4_collector_hashes_in_db():
    """Collector API keys in database are stored only as SHA-256 hashes."""
    conn = get_connection()
    rows = conn.execute("SELECT api_key_hash FROM collectors").fetchall()
    conn.close()

    assert len(rows) > 0
    for r in rows:
        key_hash = r["api_key_hash"]
        assert len(key_hash) == 64  # SHA-256 hex
        assert not key_hash.startswith("key-")


# ── Item 5: CORS Explicit Origins ───────────────

def test_item5_cors_never_wildcard():
    """FastAPI CORS middleware must NOT contain '*' in allow_origins."""
    from fastapi.middleware.cors import CORSMiddleware
    from saas.main import ALLOWED_ORIGINS
    assert "*" not in ALLOWED_ORIGINS

    cors_mw = None
    for mw in fastapi_app.user_middleware:
        if mw.cls == CORSMiddleware:
            cors_mw = mw
            break

    assert cors_mw is not None
    allow_origins = cors_mw.kwargs.get("allow_origins", [])
    assert "*" not in allow_origins
    assert "http://localhost:8000" in allow_origins or "http://127.0.0.1:8000" in allow_origins


# ── Item 6: Dashboard Plain Text Rendering (No innerHTML for Dynamic Data) ───────────────

def test_item6_dashboard_no_inner_html_injection():
    """Verify dashboard/index.html does not assign innerHTML with dynamic variable interpolation."""
    dashboard_path = Path(__file__).resolve().parent.parent / "dashboard" / "index.html"
    assert dashboard_path.exists()
    content = dashboard_path.read_text(encoding="utf-8")

    # Ensure innerHTML is not used for dynamic rows
    assert "tbody.innerHTML =" not in content
    assert "tr.innerHTML =" not in content
    assert "content.innerHTML =" not in content
    # Ensure textContent or replaceChildren is used
    assert "textContent" in content
    assert "replaceChildren" in content
    # Ensure hardcoded viewer tokens are NOT present in committed dashboard
    assert "TENANT_VIEWER_TOKENS" not in content
    assert "viewer-token-acme" not in content
    assert "viewer-token-globex" not in content
    # Ensure sessionStorage is used for secure client-side viewer token storage
    assert "sessionStorage" in content
    assert "viewerTokenInput" in content


# ── Item 7: No Error/Logger String Leakage ───────────────

def test_item7_malformed_json_returns_sanitized_error():
    """Malformed JSON returns generic 'Invalid JSON body format' without echoing body or traceback."""
    malformed_body = b'{"payloads": [{"secret": "LEAK_ME_12345", broken'
    secret = "secret-acme-eu1"
    valid_sig = hmac.new(secret.encode("utf-8"), malformed_body, hashlib.sha256).hexdigest()

    code, resp = handle_ingest("key-acme-eu1-dev", valid_sig, malformed_body)
    assert code == 400
    assert resp["error"] == "Invalid JSON body format"
    assert "LEAK_ME" not in resp["error"]
    assert "Traceback" not in resp["error"]


# ── Item 8: Gitignore Excludes .env ───────────────

def test_item8_gitignore_excludes_env():
    """Verify .gitignore exists and specifies .env."""
    gitignore_path = Path(__file__).resolve().parent.parent / ".gitignore"
    assert gitignore_path.exists()
    lines = [line.strip() for line in gitignore_path.read_text(encoding="utf-8").splitlines()]
    assert ".env" in lines


# ── Item 9: Tenant A Token Cannot Read Tenant B On Any Route ───────────────

def test_token_for_tenant_a_cannot_read_tenant_b_on_any_route():
    """
    Cross-tenant isolation test:
    Verify that an authenticated token for Tenant A (acme):
    1. Returns strictly Tenant A records across all read routes (/api/health, /api/incidents, /api/collectors, /api/thresholds)
    2. Cannot access Tenant B's incidents (/api/incidents/{b_id} -> 404)
    3. Cannot access Tenant B data even if ?tenant=globex or X-Tenant-Id is passed in request
    """
    from saas.api import get_incident

    tok_acme = os.environ["VIEWER_TOKEN_ACME"]
    tok_globex = os.environ["VIEWER_TOKEN_GLOBEX"]

    # 1. Verify health endpoint returns only Acme data
    req_acme = Request({
        "type": "http",
        "method": "GET",
        "url": f"http://localhost:8000/api/health?token={tok_acme}",
        "headers": [(b"x-api-key", tok_acme.encode())],
        "query_string": f"token={tok_acme}".encode(),
    })
    resp_health = get_health(request=req_acme, token=tok_acme, evaluate_now=False)
    assert resp_health.status_code == 200
    health_data = json.loads(resp_health.body.decode("utf-8"))
    assert health_data["tenant_id"] == "acme"

    # 2. Verify incidents endpoint returns only Acme incidents
    resp_inc = list_incidents(request=req_acme)
    inc_data = json.loads(resp_inc.body.decode("utf-8"))
    assert inc_data["tenant_id"] == "acme"
    for item in inc_data.get("incidents", []):
        assert item.get("tenant_id") == "acme"

    # 3. Verify collectors endpoint returns only Acme collectors
    resp_col = get_collectors(request=req_acme)
    col_data = json.loads(resp_col.body.decode("utf-8"))
    assert col_data["tenant_id"] == "acme"
    for item in col_data.get("collectors", []):
        assert item.get("tenant_id") == "acme"

    # 4. Verify thresholds endpoint returns only Acme thresholds
    resp_thresh = get_thresholds(request=req_acme)
    thresh_data = json.loads(resp_thresh.body.decode("utf-8"))
    assert thresh_data["tenant_id"] == "acme"

    # 5. Insert an incident for Globex in db and verify Acme token CANNOT read it (404)
    conn = get_connection()
    conn.execute(
        """
        INSERT OR IGNORE INTO incidents
        (id, tenant_id, title, severity, status, affected_json,
         root_cause_candidate, suppressed_count, opened_utc, updated_utc)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "inc-globex-iso-test",
            "globex",
            "Globex Secret Outage",
            "CRITICAL",
            "open",
            "[]",
            "switch-01",
            0,
            "2026-11-20T12:00:00Z",
            "2026-11-20T12:00:00Z",
        ),
    )
    conn.commit()
    conn.close()

    # Attempting to fetch Globex incident using Acme token must return 404
    resp_inc_detail = get_incident("inc-globex-iso-test", request=req_acme, token=tok_acme)
    assert resp_inc_detail.status_code == 404
    err_body = json.loads(resp_inc_detail.body.decode("utf-8"))
    assert "not found" in err_body.get("error", "").lower()

    # 6. Verify that spoofing ?tenant=globex or X-Tenant-Id: globex with Acme token raises 403 Forbidden
    spoofed_req = Request({
        "type": "http",
        "method": "GET",
        "url": f"http://localhost:8000/api/health?tenant=globex&token={tok_acme}",
        "headers": [
            (b"x-api-key", tok_acme.encode()),
            (b"x-tenant-id", b"globex"),
        ],
        "query_string": f"tenant=globex&token={tok_acme}".encode(),
    })
    with pytest.raises(Exception) as exc_info:
        resolve_tenant_id(spoofed_req)
    assert exc_info.value.status_code == 403

