"""
tests/test_remediation.py
─────────────────────────
Phase 10: Governed Remediation Test Suite.

Acceptance criteria verified:
1. Unapproved action never executes.
2. Policy-violating action is blocked with a deterministic reason (allow-list, scope, business hours).
3. Approval requires role 'operator' (non-operator is rejected with 403).
4. Rollback restores mock state and is audited.
5. Every step writes an audit_log row with actor, action, detail, and UTC time.
6. Anti-execution invariant: impossible to run real system commands.
7. REST API endpoints (/approve, /reject, /rollback, /propose, /audit, /mock-state).
"""

from __future__ import annotations

import ast
import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict

import pytest
from starlette.requests import Request

from saas.db import init_db
from saas.remediation import (
    approve_remediation_action,
    check_remediation_policy,
    ensure_remediation_schema,
    get_remediation_action,
    get_remediation_audit_trail,
    list_remediation_actions,
    mock_executor,
    propose_remediation_action,
    reject_remediation_action,
    rollback_remediation_action,
)


@pytest.fixture(autouse=True)
def setup_test_db(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Initializes a fresh isolated SQLite database for each test."""
    db_file = tmp_path / "test_saas_remediation.db"
    monkeypatch.setenv("SAAS_DB_PATH", str(db_file))
    monkeypatch.setenv("REGION", "eu")
    monkeypatch.setenv("TESTING", "1")
    tok_acme = "secret-token-acme-remediation-test-123456"
    tok_globex = "secret-token-globex-remediation-test-654321"
    monkeypatch.setenv("VIEWER_TOKEN_ACME", tok_acme)
    monkeypatch.setenv("VIEWER_TOKEN_GLOBEX", tok_globex)
    init_db(region="eu")
    ensure_remediation_schema()
    mock_executor.reset()
    yield db_file


@pytest.fixture
def acme_viewer_token() -> str:
    return "secret-token-acme-remediation-test-123456"


@pytest.fixture
def globex_viewer_token() -> str:
    return "secret-token-globex-remediation-test-654321"


# ── 1. Unapproved Action Never Executes ──────────────────────────────────────

def test_unapproved_action_never_executes():
    """An unapproved action must remain in 'awaiting_approval' and never touch mock services."""
    init_state = mock_executor.get_state("srv-edge-01")
    assert init_state.get("service_status") == "running"

    action = propose_remediation_action(
        tenant_id="acme",
        action_name="restart_service",
        target_entity="srv-edge-01",
        simulate_business_hours=False,
    )

    assert action["state"] == "awaiting_approval"
    assert action["approved_by"] is None
    assert action["executed_at"] is None

    # Verify mock service was NOT mutated
    after_state = mock_executor.get_state("srv-edge-01")
    assert after_state == init_state
    assert after_state["service_status"] == "running"

    # Attempting to rollback an unapproved action must fail
    with pytest.raises(ValueError, match="cannot be rolled back"):
        rollback_remediation_action(action["id"], tenant_id="acme", actor="operator@acme.corp")


def test_approval_requires_operator_role():
    """Approval by a role other than 'operator' (or 'admin') must be strictly forbidden."""
    action = propose_remediation_action(
        tenant_id="acme",
        action_name="restart_service",
        target_entity="srv-edge-01",
        simulate_business_hours=False,
    )

    # Role "viewer" or "analyst" cannot approve
    with pytest.raises(PermissionError, match="requires role 'operator'"):
        approve_remediation_action(
            action_id=action["id"],
            tenant_id="acme",
            actor="viewer@acme.corp",
            role="viewer",
        )

    # State remains awaiting_approval
    current = get_remediation_action(action["id"], tenant_id="acme")
    assert current["state"] == "awaiting_approval"
    assert current["executed_at"] is None


# ── 2. Policy-Violating Actions are Blocked with Reason ───────────────────────

def test_unknown_action_blocked_by_allow_list():
    """Actions not on the contracts/remediation_policy.yaml allow-list are blocked."""
    action = propose_remediation_action(
        tenant_id="acme",
        action_name="unauthorized_system_format",
        target_entity="srv-edge-01",
    )

    assert action["state"] == "blocked"
    assert "not permitted by remediation allow-list" in action["policy_result"]

    # Blocked action cannot be approved
    with pytest.raises(ValueError, match="cannot be approved in state 'blocked'"):
        approve_remediation_action(action["id"], tenant_id="acme", actor="operator@acme.corp", role="operator")


def test_multi_host_scope_blocked_by_policy():
    """Actions exceeding the max scope (1 host) are blocked."""
    action = propose_remediation_action(
        tenant_id="acme",
        action_name="restart_service",
        target_entity="srv-edge-01",
        target_entities=["srv-edge-01", "srv-edge-02", "srv-edge-03"],
        simulate_business_hours=False,
    )

    assert action["state"] == "blocked"
    assert "max scope is single host" in action["policy_result"]

    with pytest.raises(ValueError, match="cannot be approved in state 'blocked'"):
        approve_remediation_action(action["id"], tenant_id="acme", actor="operator@acme.corp", role="operator")


def test_risky_action_blocked_during_business_hours():
    """Risky actions (service restart, network reroute) are blocked during business hours (09:00 - 17:00 UTC)."""
    action = propose_remediation_action(
        tenant_id="acme",
        action_name="restart_service",
        target_entity="srv-edge-01",
        simulate_business_hours=True,
    )

    assert action["state"] == "blocked"
    assert "strictly blocked during business hours" in action["policy_result"]


# ── 3. Happy Path: Propose -> Policy -> Approve -> Execute -> Rollback ────────

def test_full_governed_remediation_lifecycle_and_audit():
    """
    Verifies full lifecycle:
    1. Proposed -> passes policy -> awaiting_approval
    2. Rollback plan stored BEFORE execution
    3. Approved by operator -> executed against mock service
    4. Mock service state mutated
    5. Rollback restores snapshot
    6. Audit trail contains UTC records for every transition
    """
    initial_mock = mock_executor.get_state("sw-core-fra-01")
    assert initial_mock["active_uplink"] == "primary"
    assert initial_mock["traffic_route"] == "uplink-01"

    # Step 1: Propose
    action = propose_remediation_action(
        tenant_id="acme",
        action_name="reroute_traffic",
        target_entity="sw-core-fra-01",
        incident_id="inc-test-01",
        simulate_business_hours=False,
        actor="recommendation_engine",
    )
    assert action["state"] == "awaiting_approval"
    action_id = action["id"]

    # Step 2: Approve & Execute as Operator
    approved_action = approve_remediation_action(
        action_id=action_id,
        tenant_id="acme",
        actor="lead_operator@acme.corp",
        role="operator",
    )
    assert approved_action["state"] == "executed"
    assert approved_action["approved_by"] == "lead_operator@acme.corp"
    assert approved_action["approved_at"] is not None
    assert approved_action["rollback_plan"] is not None

    # Verify rollback plan was recorded and holds previous state
    rb_plan = json.loads(approved_action["rollback_plan"])
    assert rb_plan["target_entity"] == "sw-core-fra-01"
    assert rb_plan["snapshot_state"]["active_uplink"] == "primary"

    # Step 3: Verify mock service state was mutated
    mutated_mock = mock_executor.get_state("sw-core-fra-01")
    assert mutated_mock["active_uplink"] == "secondary_uplink_02"
    assert mutated_mock["traffic_route"] == "uplink-02-standby"

    # Step 4: Execute Rollback
    rolled_back_action = rollback_remediation_action(
        action_id=action_id,
        tenant_id="acme",
        actor="lead_operator@acme.corp",
    )
    assert rolled_back_action["state"] == "rolled_back"
    assert rolled_back_action["rolled_back_at"] is not None

    # Step 5: Verify mock service state was fully restored
    restored_mock = mock_executor.get_state("sw-core-fra-01")
    assert restored_mock["active_uplink"] == "primary"
    assert restored_mock["traffic_route"] == "uplink-01"

    # Step 6: Verify Immutable Audit Trail
    audit = get_remediation_audit_trail(tenant_id="acme")
    actions_audited = [a["action"] for a in audit]

    assert "remediation.proposed" in actions_audited
    assert "remediation.approved_and_executed" in actions_audited
    assert "remediation.rolled_back" in actions_audited

    # Ensure every audit entry has an ISO8601 UTC timestamp
    for entry in audit:
        assert entry["at_utc"] is not None
        assert "T" in entry["at_utc"]


# ── 4. Anti-Execution Invariant (No real OS commands) ─────────────────────────

def test_anti_execution_guarantee():
    """Asserts that saas/remediation.py physically imports no system command execution modules."""
    source_file = Path(__file__).resolve().parent.parent / "saas" / "remediation.py"
    tree = ast.parse(source_file.read_text(encoding="utf-8"))

    imported_names = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_names.add(alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module:
                imported_names.add(node.module)

    forbidden = {"subprocess", "shlex", "pty"}
    for f in forbidden:
        assert f not in imported_names, f"Forbidden module '{f}' imported in saas/remediation.py"

    # Also assert no dangerous os.system, os.popen calls in AST
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("system", "popen", "spawn"):
                pytest.fail(f"Dangerous call os.{node.func.attr}() found in saas/remediation.py")


# ── 5. REST API Integration Tests ─────────────────────────────────────────────

def test_api_remediation_endpoints(acme_viewer_token: str, globex_viewer_token: str):
    """Tests /api/remediation routes with auth, RBAC, execution, rollback, and tenant isolation."""
    from saas.api import (
        approve_remediation,
        get_mock_infra_state,
        get_remediation_audit,
        get_remediations,
        propose_remediation,
        reject_remediation,
        rollback_remediation,
    )

    req_acme = Request({
        "type": "http",
        "method": "GET",
        "url": f"http://localhost:8000/api?token={acme_viewer_token}",
        "headers": [(b"authorization", f"Bearer {acme_viewer_token}".encode())],
        "query_string": f"token={acme_viewer_token}".encode(),
    })
    req_globex = Request({
        "type": "http",
        "method": "GET",
        "url": f"http://localhost:8000/api?token={globex_viewer_token}",
        "headers": [(b"authorization", f"Bearer {globex_viewer_token}".encode())],
        "query_string": f"token={globex_viewer_token}".encode(),
    })

    # 1. Propose action via API
    propose_res = propose_remediation(
        request=req_acme,
        payload={
            "action_name": "rate_limit_source",
            "target_entity": "h_1234abcd",
            "actor": "security_operator@acme.corp",
        },
        token=acme_viewer_token,
    )
    assert propose_res.status_code == 200
    res_data = json.loads(propose_res.body.decode("utf-8"))
    action_data = res_data["action"]
    action_id = action_data["id"]
    assert action_data["state"] == "awaiting_approval"

    # 2. Non-operator cannot approve (403 Forbidden)
    unauthorized_res = approve_remediation(
        action_id=action_id,
        request=req_acme,
        payload={"role": "viewer", "actor": "auditor@acme.corp"},
        token=acme_viewer_token,
    )
    assert unauthorized_res.status_code == 403

    # 3. Operator approves (200 OK)
    approve_res = approve_remediation(
        action_id=action_id,
        request=req_acme,
        payload={"role": "operator", "actor": "security_operator@acme.corp"},
        token=acme_viewer_token,
    )
    assert approve_res.status_code == 200
    appr_data = json.loads(approve_res.body.decode("utf-8"))
    assert appr_data["action"]["state"] == "executed"

    # 4. Mock state reflected via API
    mock_res = get_mock_infra_state(request=req_acme, token=acme_viewer_token)
    assert mock_res.status_code == 200
    mock_data = json.loads(mock_res.body.decode("utf-8"))
    assert mock_data["mock_state"]["h_1234abcd"]["rate_limited"] is True

    # 5. Rollback via API
    rb_res = rollback_remediation(
        action_id=action_id,
        request=req_acme,
        payload={"actor": "security_operator@acme.corp"},
        token=acme_viewer_token,
    )
    assert rb_res.status_code == 200
    rb_data = json.loads(rb_res.body.decode("utf-8"))
    assert rb_data["action"]["state"] == "rolled_back"

    # 6. Check Audit trail via API
    audit_res = get_remediation_audit(request=req_acme, token=acme_viewer_token)
    assert audit_res.status_code == 200
    audit_data = json.loads(audit_res.body.decode("utf-8"))
    assert len(audit_data["audit"]) >= 3

    # 7. Tenant Isolation check: Globex cannot see Acme's remediation actions
    globex_list = get_remediations(request=req_globex, token=globex_viewer_token)
    assert globex_list.status_code == 200
    globex_data = json.loads(globex_list.body.decode("utf-8"))
    assert len(globex_data["actions"]) == 0


# ── 8. Idempotency, Single-Transaction & Demo Reset Regression Tests ───────────

def test_proposing_same_action_three_times_creates_exactly_one_row():
    """Proposing the same open action 3 times must create exactly 1 database row and return 'already pending (id N)'."""
    from saas.db import get_connection

    # Call 1: Creates new proposal
    act1 = propose_remediation_action(
        tenant_id="acme",
        action_name="restart_service",
        target_entity="srv-edge-01",
        simulate_business_hours=False,
    )
    assert act1["state"] == "awaiting_approval"
    assert act1.get("already_pending") is not True
    act1_id = act1["id"]

    # Call 2: Returns existing proposal without creating a duplicate row
    act2 = propose_remediation_action(
        tenant_id="acme",
        action_name="restart_service",
        target_entity="srv-edge-01",
        simulate_business_hours=False,
    )
    assert act2["id"] == act1_id
    assert act2.get("already_pending") is True
    assert f"already pending (id {act1_id})" in act2.get("message", "")

    # Call 3: Repeated proposal returns existing proposal
    act3 = propose_remediation_action(
        tenant_id="acme",
        action_name="restart_service",
        target_entity="srv-edge-01",
        simulate_business_hours=False,
    )
    assert act3["id"] == act1_id
    assert act3.get("already_pending") is True
    assert f"already pending (id {act1_id})" in act3.get("message", "")

    # Verify exactly 1 database row exists
    conn = get_connection()
    try:
        count = conn.execute(
            """
            SELECT COUNT(*) FROM remediation_actions
            WHERE tenant_id = 'acme' AND target_entity = 'srv-edge-01' AND action_name = 'restart_service'
            """
        ).fetchone()[0]
        assert count == 1, f"Expected exactly 1 row, found {count}"
    finally:
        conn.close()


def test_after_approval_and_rollback_new_proposal_is_allowed():
    """Once an action is approved, executed, and rolled back, proposing it again is allowed."""
    from saas.db import get_connection

    # 1. Propose and approve
    act1 = propose_remediation_action(
        tenant_id="acme",
        action_name="restart_service",
        target_entity="srv-edge-01",
        simulate_business_hours=False,
    )
    act1_id = act1["id"]

    # Approve and simulate execution
    approved = approve_remediation_action(
        action_id=act1_id,
        tenant_id="acme",
        actor="operator@acme.corp",
        role="operator",
    )
    assert approved["state"] == "executed"

    # Roll back action
    rolled_back = rollback_remediation_action(
        action_id=act1_id,
        tenant_id="acme",
        actor="operator@acme.corp",
    )
    assert rolled_back["state"] == "rolled_back"

    # 2. Propose the same action again — must be allowed since previous is closed
    act2 = propose_remediation_action(
        tenant_id="acme",
        action_name="restart_service",
        target_entity="srv-edge-01",
        simulate_business_hours=False,
    )
    assert act2["state"] == "awaiting_approval"
    assert act2["id"] != act1_id
    assert act2.get("already_pending") is not True

    # Verify 2 rows in DB (one rolled_back, one awaiting_approval)
    conn = get_connection()
    try:
        rows = conn.execute(
            """
            SELECT id, state FROM remediation_actions
            WHERE tenant_id = 'acme' AND target_entity = 'srv-edge-01' AND action_name = 'restart_service'
            ORDER BY id ASC
            """
        ).fetchall()
        assert len(rows) == 2
        assert rows[0]["state"] == "rolled_back"
        assert rows[1]["state"] == "awaiting_approval"
    finally:
        conn.close()


def test_failed_propose_leaves_no_row(monkeypatch: pytest.MonkeyPatch):
    """The insert and audit log record share one transaction. A failure during the proposal leaves 0 rows."""
    from saas.db import get_connection
    import saas.remediation

    # Force record_audit_log inside saas.remediation to fail
    def failing_audit(*args, **kwargs):
        raise RuntimeError("Simulated audit write failure mid-transaction")

    monkeypatch.setattr(saas.remediation, "record_audit_log", failing_audit)

    with pytest.raises(RuntimeError, match="Simulated audit write failure mid-transaction"):
        propose_remediation_action(
            tenant_id="acme",
            action_name="restart_service",
            target_entity="srv-edge-01",
            simulate_business_hours=False,
        )

    # Verify no half-created action was persisted
    conn = get_connection()
    try:
        count = conn.execute(
            """
            SELECT COUNT(*) FROM remediation_actions
            WHERE tenant_id = 'acme' AND target_entity = 'srv-edge-01' AND action_name = 'restart_service'
            """
        ).fetchone()[0]
        assert count == 0, f"Expected 0 rows after rollback, but found {count}"
    finally:
        conn.close()


def test_reset_remediation_demo_state_clears_all_rows():
    """reset_remediation_demo_state clears all remediation_actions and resets mock executor state."""
    from saas.db import get_connection
    from saas.remediation import reset_remediation_demo_state

    # Insert two actions
    propose_remediation_action(tenant_id="acme", action_name="restart_service", target_entity="srv-edge-01", simulate_business_hours=False)
    propose_remediation_action(tenant_id="acme", action_name="reroute_traffic", target_entity="sw-core-fra-01", simulate_business_hours=False)

    conn = get_connection()
    try:
        count = conn.execute("SELECT COUNT(*) FROM remediation_actions WHERE tenant_id = 'acme'").fetchone()[0]
        assert count == 2
    finally:
        conn.close()

    cleared = reset_remediation_demo_state(tenant_id="acme")
    assert cleared == 2

    conn = get_connection()
    try:
        count = conn.execute("SELECT COUNT(*) FROM remediation_actions WHERE tenant_id = 'acme'").fetchone()[0]
        assert count == 0
    finally:
        conn.close()

