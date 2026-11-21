"""
tests/test_scenario_injector.py
─────────────────────────────────
Unit and integration tests for Phase 12 Chaos Scenario Injector.

Validates:
1. All 8 judging scenarios execute cleanly and return valid UTC timestamps and metadata.
2. Baseline reset restores normal diurnal state and Online collector connection state.
3. Rehearsal mode executes all scenarios in sequence.
4. Typer CLI commands ('inject', 'reset', 'rehearsal').
5. SaaS REST API endpoints (/api/scenario/list, /api/scenario/inject, /api/scenario/reset).
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Generator

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from saas.api import router
from saas.db import init_db
from saas.main import app as fastapi_app
from tools.scenario_injector import (
    SCENARIO_CATALOG,
    app as typer_app,
    reset_baseline,
    run_all_scenarios,
    run_scenario,
)

runner = CliRunner()


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path: Path) -> Generator[None, None, None]:
    db_file = tmp_path / "saas_scenario_test.db"
    orig_db = os.environ.get("SAAS_DB_PATH")
    orig_region = os.environ.get("REGION")
    orig_testing = os.environ.get("TESTING")

    os.environ["TESTING"] = "1"
    os.environ["SAAS_DB_PATH"] = str(db_file)
    os.environ["REGION"] = "eu"
    init_db("eu")

    from saas.remediation import ensure_remediation_schema
    ensure_remediation_schema()

    yield

    if orig_testing:
        os.environ["TESTING"] = orig_testing
    else:
        os.environ.pop("TESTING", None)

    if orig_db:
        os.environ["SAAS_DB_PATH"] = orig_db
    else:
        os.environ.pop("SAAS_DB_PATH", None)

    if orig_region:
        os.environ["REGION"] = orig_region
    else:
        os.environ.pop("REGION", None)


# ── Scenario Execution Tests ──────────────────────────────────────────────────

@pytest.mark.parametrize("scen_num", [1, 2, 3, 4, 5, 6, 7, 8])
def test_each_scenario_executes_with_timestamp_and_details(scen_num: int):
    """Verify each judging scenario runs, generates UTC timestamp, and returns complete details."""
    res = run_scenario(
        str(scen_num),
        collector_id="col-acme-eu-1",
        tenant_id="acme",
        as_json=False,
        auto_restore_outage=False,
    )
    assert res["status"] == "injected"
    assert res["scenario_number"] == scen_num
    assert "injected_at_utc" in res
    assert res["injected_at_utc"].endswith("Z")
    assert "narration" in res and len(res["narration"]) > 0
    assert "where_to_observe" in res and len(res["where_to_observe"]) > 0
    assert "injected_detail" in res


def test_scenario_reset():
    """Verify reset returns platform to normal baseline."""
    res = reset_baseline(collector_id="all", as_json=False)
    assert res["status"] == "reset"
    assert "reset_at_utc" in res
    assert res["details"]["collector_state"] == "Online"
    assert res["details"]["cpu_spike"] == 0.0


def test_rehearsal_mode():
    """Verify rehearsal mode executes all 8 scenarios and concludes with reset."""
    summary = run_all_scenarios(
        collector_id="col-acme-eu-1",
        tenant_id="acme",
        delay_s=0.01,
        as_json=False,
    )
    assert summary["status"] == "rehearsal_completed"
    assert summary["scenarios_executed"] == 8
    assert summary["reset_status"] == "reset"
    assert "started_utc" in summary
    assert "completed_utc" in summary


# ── Typer CLI Integration Tests ───────────────────────────────────────────────

def test_cli_inject_by_number():
    result = runner.invoke(typer_app, ["inject", "1"])
    assert result.exit_code == 0
    assert "Injected: Scenario 1" in result.stdout
    assert "Raw log contains a secret" in result.stdout


def test_cli_inject_by_alias():
    result = runner.invoke(typer_app, ["inject", "latency-rise"])
    assert result.exit_code == 0
    assert "Injected: Scenario 4" in result.stdout
    assert "Network latency rises" in result.stdout


def test_cli_reset():
    result = runner.invoke(typer_app, ["reset"])
    assert result.exit_code == 0
    assert "Platform Restored to Baseline" in result.stdout


def test_cli_rehearsal():
    result = runner.invoke(typer_app, ["rehearsal", "--delay", "0.01"])
    assert result.exit_code == 0
    assert "REHEARSAL COMPLETE" in result.stdout


# ── SaaS API Integration Tests ────────────────────────────────────────────────

def test_api_scenario_list():
    from saas.api import list_scenarios
    resp = list_scenarios()
    assert resp.status_code == 200
    data = json.loads(resp.body)
    assert data["status"] == "ok"
    assert len(data["scenarios"]) == 8
    nums = [s["number"] for s in data["scenarios"]]
    assert nums == [1, 2, 3, 4, 5, 6, 7, 8]


import respx
import httpx


# ── Regression Tests: Error Handling & Visible Scenario Effects ───────────────

def test_unreachable_simulator_returns_json_error_not_500():
    """Verify that when simulator is offline, inject endpoint returns clean JSON error (503), not 500."""
    from saas.api import ScenarioInjectRequest, api_inject_scenario
    req_body = ScenarioInjectRequest(scenario=1, collector="col-acme-eu-1")
    resp = api_inject_scenario(req_body)
    assert resp.status_code == 503, f"Expected 503 when simulator is offline, got {resp.status_code}"
    data = json.loads(resp.body)
    assert "error" in data
    assert "unreachable" in data["error"].lower() or "port 9000" in data["error"].lower()
    assert data.get("status") == "error"
    assert data.get("simulator_reachable") is False


@pytest.mark.parametrize("scen_num", [1, 2, 3, 4, 5, 6, 7, 8])
@respx.mock
def test_each_scenario_returns_200_and_produces_visible_effect(scen_num: int):
    """
    Regression Test:
    When simulator is running/reachable, scenarios 1-8 each return 200
    and produce a visible effect (new telemetry, alert, incident, or audit row).
    """
    from saas.api import ScenarioInjectRequest, api_inject_scenario

    # Mock simulator endpoints on port 9000
    respx.post("http://localhost:9000/inject/col-acme-eu-1").mock(
        return_value=httpx.Response(200, json={"status": "injected"})
    )
    respx.post("http://localhost:9000/clear/col-acme-eu-1").mock(
        return_value=httpx.Response(200, json={"status": "cleared"})
    )
    respx.post("http://localhost:9000/clear/all").mock(
        return_value=httpx.Response(200, json={"status": "cleared"})
    )

    req_body = ScenarioInjectRequest(scenario=scen_num, collector="col-acme-eu-1", tenant="acme")
    resp = api_inject_scenario(req_body)
    assert resp.status_code == 200, f"Scenario {scen_num} failed with status {resp.status_code}: {resp.body}"
    data = json.loads(resp.body)
    assert data["status"] == "injected"
    assert data["scenario_number"] == scen_num
    assert "injected_at_utc" in data

    # Verify visible effect per scenario
    detail = data.get("injected_detail", {})
    if scen_num == 1:
        # Scenario 1: secret written to local raw DB and simulator updated
        assert detail.get("simulator_updated") is True
        assert "sample" in detail
        assert detail.get("local_db_written") is True
    elif scen_num == 2:
        # Scenario 2: collector outbox enqueued buffering payload
        assert detail.get("simulator_updated") is True
        assert detail.get("buffer_state") == "Buffering"
    elif scen_num == 3:
        # Scenario 3: 5 failed login attempts injected
        assert detail.get("simulator_updated") is True
        assert detail.get("failed_attempts") == 5
    elif scen_num == 4:
        # Scenario 4: latency rise offset injected
        assert detail.get("simulator_updated") is True
        assert detail.get("latency_offset_ms") == 250.0
    elif scen_num == 5:
        # Scenario 5: CPU spike and memory leak active
        assert detail.get("simulator_updated") is True
        assert detail.get("cpu_spike_percent") == 55.0
        assert detail.get("memory_leak_active") is True
    elif scen_num == 6:
        # Scenario 6: correlated incident created with alert grouping
        assert detail.get("simulator_updated") is True
        assert len(detail.get("alerts_injected", [])) >= 3
        assert "correlated_incident" in detail
    elif scen_num == 7:
        # Scenario 7: duplicate & out-of-order delivery
        assert detail.get("simulator_updated") is True
        assert detail.get("duplicate_delivery") is True
    elif scen_num == 8:
        # Scenario 8: remediation proposal created in DB
        assert detail.get("action_name") == "restart_service"
        assert detail.get("state") == "awaiting_approval"
        assert "remediation_record" in detail


def test_remediation_propose_candidate_without_recommendation_id_returns_200():
    """Verify that proposing a remediation candidate directly without recommendation_id succeeds with 200."""
    from fastapi import Request
    from saas.api import propose_remediation

    fake_request = Request(
        scope={
            "type": "http",
            "method": "POST",
            "path": "/api/remediation/propose",
            "headers": [(b"x-api-key", b"test-key")],
            "query_string": b"",
        }
    )
    # Monkeypatch resolve_tenant_id for test
    from unittest.mock import patch
    with patch("saas.api.resolve_tenant_id", return_value="acme"):
        resp = propose_remediation(
            request=fake_request,
            payload={
                "action_name": "restart_service",
                "target_entity": "srv-edge-01",
                "actor": "dashboard.operator",
            },
        )
        assert resp.status_code == 200
        data = json.loads(resp.body)
        assert data["status"] == "ok"
        act = data["action"]
        assert act["action_name"] == "restart_service"
        assert act["state"] in ("awaiting_approval", "blocked")
        assert act["id"] > 0


def test_all_api_errors_return_json_error():
    """Verify that Starlette / FastAPI errors return JSON format with {'error': ...}."""
    from fastapi import Request
    from starlette.exceptions import HTTPException as StarletteHTTPException
    from saas.main import http_exception_handler, global_exception_handler

    fake_request = Request(
        scope={
            "type": "http",
            "method": "GET",
            "path": "/api/test",
            "headers": [],
            "query_string": b"",
        }
    )

    # 404 Not Found returns JSON {"error": ...}
    res404 = http_exception_handler(fake_request, StarletteHTTPException(status_code=404, detail="Not Found"))
    assert res404.status_code == 404
    data404 = json.loads(res404.body)
    assert "error" in data404
    assert data404["error"] == "Not Found"

    # 401 Unauthorized returns JSON {"error": ...}
    res401 = http_exception_handler(fake_request, StarletteHTTPException(status_code=401, detail="Unauthorized: invalid viewer token"))
    assert res401.status_code == 401
    data401 = json.loads(res401.body)
    assert "error" in data401
    assert "unauthorized" in data401["error"].lower()

    # 500 Unhandled Exception returns JSON {"error": ...}
    res500 = global_exception_handler(fake_request, RuntimeError("Simulated failure"))
    assert res500.status_code == 500
    data500 = json.loads(res500.body)
    assert "error" in data500
    assert "Simulated failure" in data500["error"]


def test_api_scenario_reset():
    from saas.api import api_reset_scenario
    resp = api_reset_scenario()
    assert resp.status_code == 200
    data = json.loads(resp.body)
    assert data["status"] == "reset"
    assert "reset_at_utc" in data
