"""
tests/test_health.py
────────────────────
Phase 5 Health Transition State Machine & API Tests:
- Heartbeat staleness progression: Excellent -> Fair at 30 s -> Poor at 60 s
- Reason string verification (e.g. "Poor: no heartbeat for 65 s")
- History logging and ordering by at_utc DESC
- Metric threshold and critical alert evaluation
- REST endpoints: GET /api/health, GET /api/health/history, PUT /api/thresholds
- Server-Sent Events (SSE) transition broadcasting
"""

import json
from datetime import datetime, timedelta, timezone
import pytest
from fastapi.testclient import TestClient

from collector.uuidv7 import uuidv7
from saas.db import get_connection, init_db
from saas.health import (
    evaluate_collector_health,
    evaluate_source_health,
    evaluate_tenant_health,
    get_tenant_thresholds,
    record_state_transition,
)
from saas.main import app
from saas.sse import subscribe, unsubscribe
from saas.tenancy import get_scoped_query


@pytest.fixture(autouse=True)
def setup_saas_db(tmp_path, monkeypatch):
    """Isolate SaaS DB for test execution."""
    test_db = tmp_path / "saas_health_test.db"
    monkeypatch.setenv("SAAS_DB_PATH", str(test_db))
    monkeypatch.setenv("REGION", "eu")
    monkeypatch.setenv("TESTING", "1")
    init_db("eu")
    yield


def test_collector_reporting_on_time_is_excellent():
    now = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
    collector = {
        "id": "col-acme-eu-1",
        "last_seen": (now - timedelta(seconds=5)).isoformat(),
        "cpu": 25.0,
        "mem": 45.0,
    }
    state, reason = evaluate_collector_health(collector, now)
    assert state == "Excellent"
    assert "reporting on time" in reason


def test_collector_missing_heartbeat_at_35s_is_fair():
    now = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
    collector = {
        "id": "col-acme-eu-1",
        "last_seen": (now - timedelta(seconds=35)).isoformat(),
        "cpu": 25.0,
        "mem": 45.0,
    }
    state, reason = evaluate_collector_health(collector, now)
    assert state == "Fair"
    assert "Fair: data stale for 35 s" == reason


def test_collector_missing_heartbeat_at_65s_is_poor():
    now = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
    collector = {
        "id": "col-acme-eu-1",
        "last_seen": (now - timedelta(seconds=65)).isoformat(),
        "cpu": 25.0,
        "mem": 45.0,
    }
    state, reason = evaluate_collector_health(collector, now)
    assert state == "Poor"
    assert "Poor: no heartbeat for 65 s" == reason


def test_acceptance_gate_stop_collector_progression_and_history():
    """
    ACCEPTANCE GATE:
    Stop a collector: it shows Fair around 30 s and Poor by 60 s with the
    stated reason, and the transition appears in the history with a UTC timestamp.
    """
    t0 = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)
    conn = get_connection()
    with conn:
        conn.execute(
            "UPDATE collectors SET last_seen = ? WHERE id = 'col-acme-eu-1'",
            (t0.isoformat(),),
        )
    conn.close()

    # T = 0: Collector is reporting on time -> Initial state Excellent
    evaluate_tenant_health("acme", now=t0)
    cur_state = get_scoped_query("acme", table="health_state", where_clause="entity_id = 'col-acme-eu-1'")[0]
    assert cur_state["state"] == "Excellent"

    # T + 35s: Collector has stopped! Last seen is 35s ago -> Transitions to Fair
    t_fair = t0 + timedelta(seconds=35)
    evaluate_tenant_health("acme", now=t_fair)
    cur_state = get_scoped_query("acme", table="health_state", where_clause="entity_id = 'col-acme-eu-1'")[0]
    assert cur_state["state"] == "Fair"
    assert "Fair: data stale for 35 s" in cur_state["reason"]

    # T + 65s: Collector is still stopped! 65s elapsed -> Transitions to Poor
    t_poor = t0 + timedelta(seconds=65)
    evaluate_tenant_health("acme", now=t_poor)
    cur_state = get_scoped_query("acme", table="health_state", where_clause="entity_id = 'col-acme-eu-1'")[0]
    assert cur_state["state"] == "Poor"
    assert "Poor: no heartbeat for 65 s" in cur_state["reason"]

    # Verify history audit trail: ordered by at_utc DESC
    history = get_scoped_query(
        "acme",
        table="health_history",
        where_clause="entity_id = 'col-acme-eu-1'",
        order_by="at_utc DESC",
    )
    assert len(history) == 3

    # Most recent transition: Fair -> Poor
    assert history[0]["from_state"] == "Fair"
    assert history[0]["to_state"] == "Poor"
    assert "Poor: no heartbeat for 65 s" in history[0]["reason"]
    assert history[0]["at_utc"] == t_poor.isoformat()

    # Second transition: Excellent -> Fair
    assert history[1]["from_state"] == "Excellent"
    assert history[1]["to_state"] == "Fair"
    assert "Fair: data stale for 35 s" in history[1]["reason"]
    assert history[1]["at_utc"] == t_fair.isoformat()

    # Initial transition: Unknown -> Excellent
    assert history[2]["from_state"] == "Unknown"
    assert history[2]["to_state"] == "Excellent"
    assert history[2]["at_utc"] == t0.isoformat()


def test_metric_exceeding_threshold_evaluates_poor():
    now = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
    src = "h_11223344"
    conn = get_connection()
    with conn:
        conn.execute(
            """
            INSERT INTO metrics (
                tenant_id, payload_id, collector_id, source_ref,
                category, value, unit, event_time_utc, received_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("acme", uuidv7(), "col-acme-eu-1", src, "cpu", 96.5, "percent", now.isoformat(), now.isoformat()),
        )
    conn.close()

    thresholds = get_tenant_thresholds("acme")
    state, reason = evaluate_source_health("acme", src, thresholds, now)
    assert state == "Poor"
    assert "cpu (96.5) exceeds poor threshold" in reason


def test_critical_alert_evaluates_poor():
    now = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
    src = "h_99887766"
    conn = get_connection()
    with conn:
        conn.execute(
            """
            INSERT INTO metrics (
                tenant_id, payload_id, collector_id, source_ref,
                category, value, unit, event_time_utc, received_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("acme", uuidv7(), "col-acme-eu-1", src, "cpu", 30.0, "percent", now.isoformat(), now.isoformat()),
        )
        conn.execute(
            """
            INSERT INTO events (
                tenant_id, payload_id, kind, category, severity,
                context, event_time_utc, received_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            ("acme", uuidv7(), "alert", "service", "critical", "database crash", now.isoformat(), now.isoformat()),
        )
    conn.close()

    thresholds = get_tenant_thresholds("acme")
    state, reason = evaluate_source_health("acme", src, thresholds, now)
    assert state == "Poor"
    assert "critical alert" in reason.lower()


def test_health_api_endpoints(monkeypatch: pytest.MonkeyPatch):
    import os
    from starlette.requests import Request
    from saas.api import get_health, get_health_history, get_thresholds, update_thresholds

    token_acme = os.environ.get("VIEWER_TOKEN_ACME", "test-token-acme-env")
    monkeypatch.setenv("VIEWER_TOKEN_ACME", token_acme)

    req = Request({
        "type": "http",
        "method": "GET",
        "path": "/",
        "headers": [(b"x-api-key", token_acme.encode())],
        "query_string": f"token={token_acme}".encode(),
    })

    # 1. GET /api/health
    resp_health = get_health(req, token=token_acme)
    assert resp_health.status_code == 200
    data = json.loads(resp_health.body)
    assert data["status"] == "ok"
    assert data["tenant_id"] == "acme"
    assert isinstance(data["entities"], list)

    # 2. GET /api/thresholds
    resp_thresh = get_thresholds(req, token=token_acme)
    assert resp_thresh.status_code == 200
    thresh_data = json.loads(resp_thresh.body)
    assert thresh_data["status"] == "ok"
    assert len(thresh_data["thresholds"]) > 0

    # 3. PUT /api/thresholds
    new_cpu_threshold = {
        "category": "cpu",
        "fair_at": 65.0,
        "poor_at": 85.0,
        "stale_fair_s": 25,
        "stale_poor_s": 50,
    }
    resp_put = update_thresholds(
        request=req,
        body=new_cpu_threshold,
        token=token_acme,
    )
    assert resp_put.status_code == 200
    assert json.loads(resp_put.body)["updated_count"] == 1

    # Verify updated values
    thresholds = get_tenant_thresholds("acme")
    assert thresholds["cpu"]["fair_at"] == 65.0
    assert thresholds["cpu"]["poor_at"] == 85.0
    assert thresholds["cpu"]["stale_fair_s"] == 25
    assert thresholds["cpu"]["stale_poor_s"] == 50

    # 4. GET /api/health/history
    resp_history = get_health_history(req, token=token_acme)
    assert resp_history.status_code == 200
    hist_data = json.loads(resp_history.body)
    assert hist_data["status"] == "ok"
    assert isinstance(hist_data["history"], list)


def test_sse_broadcasts_health_changes():
    now = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
    queue = subscribe("acme")

    try:
        # Trigger transition
        record_state_transition("acme", "col-acme-eu-1", "Fair", "Fair: test transition", now)
        assert not queue.empty()
        msg = queue.get_nowait()
        assert "event: health_change" in msg
        assert "Fair: test transition" in msg
    finally:
        unsubscribe("acme", queue)
