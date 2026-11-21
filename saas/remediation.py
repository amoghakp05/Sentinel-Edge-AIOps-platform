"""
saas/remediation.py
───────────────────
Governed, privacy-preserving remediation workflow:
  proposed -> policy check -> awaiting approval -> approved -> simulated execution -> audit record -> (optional) rolled back

Key Invariants:
1. Policy rules enforced from contracts/remediation_policy.yaml:
   - Action allow-list (only pre-approved actions allowed)
   - Must be reversible (rollback action defined)
   - Max scope: single host (<= 1 target entity)
   - Risky actions blocked during business hours (09:00 - 17:00 UTC, Mon-Fri)
   - Requires role "operator" to approve
2. Mock Executor ONLY: Impossible for code to run real system commands.
   All actions mutate an in-memory simulated service registry only.
3. Every step writes an audit_log record with actor, action, detail, and UTC time.
4. Each action stores a verified rollback plan BEFORE execution.
5. Full rollback support restores the exact previous state of the mock service.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from saas.audit import record_audit_log
from saas.db import get_connection

logger = logging.getLogger(__name__)

# ── Load Remediation Policy ───────────────────────────────────────────────────

_POLICY_FILE = Path(__file__).resolve().parent.parent / "contracts" / "remediation_policy.yaml"


def load_remediation_policy() -> dict:
    if not _POLICY_FILE.exists():
        raise FileNotFoundError(f"Remediation policy file not found: {_POLICY_FILE}")
    with open(_POLICY_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


_POLICY_SPEC = load_remediation_policy()
_ALLOWED_ACTIONS: Dict[str, Any] = _POLICY_SPEC.get("allowed_actions", {})
_GENERAL_RULES: Dict[str, Any] = _POLICY_SPEC.get("general_rules", {})


# ── Database Schema Migration Helper ──────────────────────────────────────────

def ensure_remediation_schema() -> None:
    """Ensures remediation_actions table exists with all required columns."""
    conn = get_connection()
    try:
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS remediation_actions (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    tenant_id        TEXT NOT NULL DEFAULT 'acme',
                    incident_id      TEXT,
                    recommendation_id INTEGER,
                    action_name      TEXT NOT NULL DEFAULT '',
                    target_entity    TEXT NOT NULL DEFAULT '',
                    scope            TEXT NOT NULL DEFAULT 'single_host',
                    state            TEXT NOT NULL DEFAULT 'proposed',
                    policy_result    TEXT,
                    approved_by      TEXT,
                    approved_at      TEXT,
                    rollback_plan    TEXT,
                    executed_at      TEXT,
                    execution_result TEXT,
                    rolled_back_at   TEXT,
                    created_at       TEXT,
                    updated_at       TEXT
                );
                """
            )
            # Add any missing columns for existing databases
            cols_cur = conn.execute("PRAGMA table_info(remediation_actions)")
            existing_cols = {row["name"] for row in cols_cur.fetchall()}
            needed_cols = [
                ("tenant_id", "TEXT NOT NULL DEFAULT 'acme'"),
                ("incident_id", "TEXT"),
                ("recommendation_id", "INTEGER"),
                ("action_name", "TEXT NOT NULL DEFAULT ''"),
                ("target_entity", "TEXT NOT NULL DEFAULT ''"),
                ("scope", "TEXT NOT NULL DEFAULT 'single_host'"),
                ("execution_result", "TEXT"),
                ("created_at", "TEXT"),
                ("updated_at", "TEXT"),
            ]
            for col_name, col_def in needed_cols:
                if col_name not in existing_cols:
                    try:
                        conn.execute(f"ALTER TABLE remediation_actions ADD COLUMN {col_name} {col_def}")
                    except Exception:
                        pass
    finally:
        conn.close()


ensure_remediation_schema()


# ── Mock Service Registry & Executor ──────────────────────────────────────────
# Hard Invariant: No subprocess, no os.system, no shell, no real execution.
# Pure in-memory simulated environment.

class MockServiceRegistry:
    """
    Simulated infrastructure environment.
    All remediation executions modify internal state dictionaries only.
    """

    def __init__(self) -> None:
        self.reset()

    def reset(self) -> None:
        self._state: Dict[str, Dict[str, Any]] = {
            "srv-edge-01": {
                "service_status": "running",
                "memory_leak_flag": True,
                "restarts_count": 0,
                "last_restart_utc": None,
            },
            "sw-core-fra-01": {
                "active_uplink": "primary",
                "traffic_route": "uplink-01",
                "status": "degraded_latency",
                "reroutes_count": 0,
            },
            "h_1234abcd": {
                "rate_limited": False,
                "max_req_per_s": None,
                "abuse_flag": True,
            },
            "srv-cache-01": {
                "cache_size_mb": 4096,
                "cache_flushed_utc": None,
            },
        }

    def get_state(self, entity_id: str) -> Dict[str, Any]:
        return dict(self._state.get(entity_id, {"status": "default_mock_state"}))

    def execute_mock(
        self,
        action_name: str,
        target_entity: str,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Simulates executing an action against the fake service.
        Returns a mock execution result with details.
        """
        params = params or {}
        now_iso = datetime.now(timezone.utc).isoformat()

        if target_entity not in self._state:
            self._state[target_entity] = {"status": "initialized_mock"}

        current = self._state[target_entity]

        if action_name == "restart_service":
            current["service_status"] = "restarted"
            current["memory_leak_flag"] = False
            current["restarts_count"] = current.get("restarts_count", 0) + 1
            current["last_restart_utc"] = now_iso
            return {
                "status": "success",
                "simulated": True,
                "action": action_name,
                "target": target_entity,
                "message": f"Simulated graceful restart of service on {target_entity}",
                "new_state": dict(current),
            }

        elif action_name == "reroute_traffic":
            current["active_uplink"] = params.get("target_uplink", "secondary_uplink_02")
            current["traffic_route"] = "uplink-02-standby"
            current["status"] = "normal_latency"
            current["reroutes_count"] = current.get("reroutes_count", 0) + 1
            return {
                "status": "success",
                "simulated": True,
                "action": action_name,
                "target": target_entity,
                "message": f"Simulated traffic reroute to secondary uplink on {target_entity}",
                "new_state": dict(current),
            }

        elif action_name == "rate_limit_source":
            current["rate_limited"] = True
            current["max_req_per_s"] = params.get("max_req_per_s", 10)
            current["abuse_flag"] = False
            return {
                "status": "success",
                "simulated": True,
                "action": action_name,
                "target": target_entity,
                "message": f"Simulated active rate limiting ({current['max_req_per_s']} req/s) applied on {target_entity}",
                "new_state": dict(current),
            }

        elif action_name == "flush_cache":
            current["cache_size_mb"] = 0
            current["cache_flushed_utc"] = now_iso
            return {
                "status": "success",
                "simulated": True,
                "action": action_name,
                "target": target_entity,
                "message": f"Simulated cache flush executed on {target_entity}",
                "new_state": dict(current),
            }

        else:
            return {
                "status": "unknown_action",
                "simulated": True,
                "action": action_name,
                "target": target_entity,
                "message": f"Mock simulated no-op for action '{action_name}'",
            }

    def rollback_mock(self, rollback_plan: Dict[str, Any]) -> Dict[str, Any]:
        """
        Simulates rolling back an action using the pre-stored rollback plan.
        Restores the exact previous snapshot state.
        """
        target = rollback_plan.get("target_entity")
        snapshot = rollback_plan.get("snapshot_state", {})

        if target and snapshot:
            self._state[target] = dict(snapshot)
            return {
                "status": "success",
                "simulated": True,
                "target": target,
                "message": f"Simulated rollback successful: restored previous snapshot for {target}",
                "restored_state": dict(snapshot),
            }

        return {
            "status": "noop",
            "simulated": True,
            "target": target,
            "message": "No snapshot found to restore in rollback plan",
        }


mock_executor = MockServiceRegistry()


# ── Policy Check Engine ───────────────────────────────────────────────────────

def is_business_hours(dt: Optional[datetime] = None) -> bool:
    """Checks whether the given time falls within restricted business hours (Mon-Fri 09:00-17:00 UTC)."""
    check_dt = dt or datetime.now(timezone.utc)
    bh = _GENERAL_RULES.get("business_hours", {})
    start_hour = bh.get("start_hour", 9)
    end_hour = bh.get("end_hour", 17)
    active_days = bh.get("active_days", [0, 1, 2, 3, 4])

    return check_dt.weekday() in active_days and (start_hour <= check_dt.hour < end_hour)


def check_remediation_policy(
    action_name: str,
    target_entities: List[str],
    params: Optional[Dict[str, Any]] = None,
    simulate_business_hours: Optional[bool] = None,
    dt: Optional[datetime] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Evaluates candidate remediation action against contracts/remediation_policy.yaml:
    1. Allow-list check
    2. Must be reversible check
    3. Scope check (max 1 host)
    4. Business hours restriction for risky actions
    """
    # 1. Allow-list check
    if action_name not in _ALLOWED_ACTIONS:
        return False, f"Action '{action_name}' is not permitted by remediation allow-list. Allowed: {list(_ALLOWED_ACTIONS.keys())}"

    spec = _ALLOWED_ACTIONS[action_name]

    # 2. Reversible check
    if not spec.get("reversible", False) or not spec.get("rollback_action"):
        return False, f"Action '{action_name}' violates policy: action must be reversible and specify a rollback plan."

    # 3. Max scope check (one host maximum)
    max_entities = _GENERAL_RULES.get("max_scope", {}).get("max_entities", 1)
    if len(target_entities) > max_entities:
        return False, (
            f"Action violates scope policy: max scope is single host (max {max_entities} entity), "
            f"requested {len(target_entities)} entities ({', '.join(target_entities)})."
        )

    # 4. Business hours restriction for risky actions
    is_risky = spec.get("is_risky", False)
    during_business_hours = (
        simulate_business_hours
        if simulate_business_hours is not None
        else is_business_hours(dt)
    )

    if is_risky and during_business_hours:
        return False, (
            f"Risky action '{action_name}' is strictly blocked during business hours (09:00 - 17:00 UTC, Mon-Fri). "
            f"Must be scheduled during a maintenance window or overridden with emergency approval."
        )

    return True, None


# ── Workflow State Transitions ────────────────────────────────────────────────

def propose_remediation_action(
    tenant_id: str,
    action_name: str,
    target_entity: str,
    incident_id: Optional[str] = None,
    recommendation_id: Optional[int] = None,
    target_entities: Optional[List[str]] = None,
    params: Optional[Dict[str, Any]] = None,
    simulate_business_hours: Optional[bool] = None,
    actor: str = "aiops.recommendation_engine",
) -> Dict[str, Any]:
    """
    Flow step: proposed -> policy check -> (awaiting approval OR blocked)
    Writes audit_log entry in the exact same database transaction.
    Enforces idempotency: if an open action already exists for (tenant_id, target_entity, action_name),
    returns the existing action with message "already pending (id N)" without creating a duplicate row.
    """
    targets = target_entities if target_entities is not None else [target_entity]
    scope = "single_host" if len(targets) <= 1 else f"multi_host_{len(targets)}"
    now_iso = datetime.now(timezone.utc).isoformat()

    conn = get_connection()
    safe_rec_id = int(recommendation_id) if (recommendation_id is not None and str(recommendation_id).isdigit()) else (recommendation_id if recommendation_id is not None else 0)
    try:
        with conn:
            # 1. Idempotency Check: if an open action already exists for (tenant_id, target_entity, action_name), do not create a duplicate
            cur = conn.execute(
                """
                SELECT * FROM remediation_actions
                WHERE tenant_id = ? AND target_entity = ? AND action_name = ?
                  AND state IN ('proposed', 'policy check', 'policy_check', 'awaiting_approval', 'approved')
                ORDER BY id DESC LIMIT 1
                """,
                (tenant_id, target_entity, action_name),
            )
            existing_row = cur.fetchone()
            if existing_row:
                existing_dict = dict(existing_row)
                existing_dict["already_pending"] = True
                existing_dict["message"] = f"already pending (id {existing_dict['id']})"
                return existing_dict

            # 2. Run policy evaluation for new action
            is_allowed, policy_reason = check_remediation_policy(
                action_name=action_name,
                target_entities=targets,
                params=params,
                simulate_business_hours=simulate_business_hours,
            )

            initial_state = "awaiting_approval" if is_allowed else "blocked"
            policy_result_text = "Policy Passed: Action verified against contracts/remediation_policy.yaml" if is_allowed else f"Policy Blocked: {policy_reason}"

            # 3. Insert remediation action
            cursor = conn.execute(
                """
                INSERT INTO remediation_actions (
                    tenant_id, incident_id, recommendation_id, action_name,
                    target_entity, scope, state, policy_result,
                    created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    incident_id,
                    safe_rec_id,
                    action_name,
                    target_entity,
                    scope,
                    initial_state,
                    policy_result_text,
                    now_iso,
                    now_iso,
                ),
            )
            action_id = cursor.lastrowid

            # 4. Immutable Audit Log in the SAME atomic transaction
            record_audit_log(
                tenant_id=tenant_id,
                actor=actor,
                action="remediation.proposed",
                detail={
                    "action_id": action_id,
                    "action_name": action_name,
                    "target_entity": target_entity,
                    "incident_id": incident_id,
                    "recommendation_id": safe_rec_id,
                    "scope": scope,
                    "state": initial_state,
                    "policy_result": policy_result_text,
                },
                at_utc=now_iso,
                conn=conn,
            )

            if not is_allowed:
                record_audit_log(
                    tenant_id=tenant_id,
                    actor="remediation.policy_gate",
                    action="remediation.policy_violation_blocked",
                    detail={
                        "action_id": action_id,
                        "action_name": action_name,
                        "target_entity": target_entity,
                        "reason": policy_reason,
                    },
                    at_utc=now_iso,
                    conn=conn,
                )

        return get_remediation_action(action_id, tenant_id=tenant_id)
    finally:
        conn.close()


def approve_remediation_action(
    action_id: int,
    tenant_id: str,
    actor: str,
    role: str = "operator",
) -> Dict[str, Any]:
    """
    Flow step: awaiting approval -> approved -> simulated execution -> audit record.
    Enforces:
    - Actor role must be "operator" (or "admin").
    - Action must currently be in "awaiting_approval" state.
    - Stores verified rollback plan BEFORE executing simulated action.
    - Runs mock execution only.
    """
    # 1. RBAC check
    required_role = _GENERAL_RULES.get("required_role", "operator")
    if role not in (required_role, "admin"):
        raise PermissionError(
            f"Remediation approval requires role '{required_role}', but actor role is '{role}'."
        )

    action = get_remediation_action(action_id, tenant_id=tenant_id)
    if not action:
        raise ValueError(f"Remediation action {action_id} not found.")

    if action["state"] != "awaiting_approval":
        raise ValueError(
            f"Action {action_id} cannot be approved in state '{action['state']}'. Must be in 'awaiting_approval'."
        )

    now_iso = datetime.now(timezone.utc).isoformat()
    action_name = action["action_name"]
    target_entity = action["target_entity"]
    spec = _ALLOWED_ACTIONS.get(action_name, {})

    # 2. Hard Invariant: Construct and store rollback plan BEFORE execution
    current_snapshot = mock_executor.get_state(target_entity)
    rollback_plan = {
        "rollback_action": spec.get("rollback_action", "noop_restore"),
        "target_entity": target_entity,
        "action_name": action_name,
        "snapshot_state": current_snapshot,
        "created_at_utc": now_iso,
    }
    rollback_plan_json = json.dumps(rollback_plan)

    # 3. Simulate execution against mock registry (NO real OS commands)
    exec_result = mock_executor.execute_mock(
        action_name=action_name,
        target_entity=target_entity,
        params={},
    )
    exec_result_json = json.dumps(exec_result)

    # 4. Update database record & audit log in ONE transaction
    conn = get_connection()
    try:
        with conn:
            conn.execute(
                """
                UPDATE remediation_actions
                SET state = 'executed',
                    approved_by = ?,
                    approved_at = ?,
                    rollback_plan = ?,
                    executed_at = ?,
                    execution_result = ?,
                    updated_at = ?
                WHERE id = ? AND tenant_id = ?
                """,
                (
                    actor,
                    now_iso,
                    rollback_plan_json,
                    now_iso,
                    exec_result_json,
                    now_iso,
                    action_id,
                    tenant_id,
                ),
            )
            # Immutable Audit Log
            record_audit_log(
                tenant_id=tenant_id,
                actor=actor,
                action="remediation.approved_and_executed",
                detail={
                    "action_id": action_id,
                    "action_name": action_name,
                    "target_entity": target_entity,
                    "role": role,
                    "approved_at_utc": now_iso,
                    "rollback_plan_stored": True,
                    "execution_result": exec_result,
                },
                at_utc=now_iso,
                conn=conn,
            )
        return get_remediation_action(action_id, tenant_id=tenant_id)
    finally:
        conn.close()


def reject_remediation_action(
    action_id: int,
    tenant_id: str,
    actor: str,
    reason: str = "Rejected by operator",
) -> Dict[str, Any]:
    """Rejects a proposed action."""
    action = get_remediation_action(action_id, tenant_id=tenant_id)
    if not action:
        raise ValueError(f"Remediation action {action_id} not found.")

    if action["state"] != "awaiting_approval":
        raise ValueError(f"Action {action_id} in state '{action['state']}' cannot be rejected.")

    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_connection()
    try:
        with conn:
            conn.execute(
                """
                UPDATE remediation_actions
                SET state = 'rejected',
                    policy_result = ?,
                    updated_at = ?
                WHERE id = ? AND tenant_id = ?
                """,
                (f"Rejected: {reason}", now_iso, action_id, tenant_id),
            )
            record_audit_log(
                tenant_id=tenant_id,
                actor=actor,
                action="remediation.rejected",
                detail={"action_id": action_id, "reason": reason},
                at_utc=now_iso,
                conn=conn,
            )
        return get_remediation_action(action_id, tenant_id=tenant_id)
    finally:
        conn.close()


def rollback_remediation_action(
    action_id: int,
    tenant_id: str,
    actor: str,
) -> Dict[str, Any]:
    """
    Flow step: executed -> (optional) rolled back.
    Executes the stored rollback plan to restore the exact previous mock state.
    """
    action = get_remediation_action(action_id, tenant_id=tenant_id)
    if not action:
        raise ValueError(f"Remediation action {action_id} not found.")

    if action["state"] != "executed":
        raise ValueError(
            f"Action {action_id} in state '{action['state']}' cannot be rolled back (must be 'executed')."
        )

    if not action["rollback_plan"]:
        raise ValueError(f"Action {action_id} has no stored rollback plan.")

    rollback_plan = json.loads(action["rollback_plan"])
    rollback_result = mock_executor.rollback_mock(rollback_plan)

    now_iso = datetime.now(timezone.utc).isoformat()
    conn = get_connection()
    try:
        with conn:
            conn.execute(
                """
                UPDATE remediation_actions
                SET state = 'rolled_back',
                    rolled_back_at = ?,
                    updated_at = ?
                WHERE id = ? AND tenant_id = ?
                """,
                (now_iso, now_iso, action_id, tenant_id),
            )
            record_audit_log(
                tenant_id=tenant_id,
                actor=actor,
                action="remediation.rolled_back",
                detail={
                    "action_id": action_id,
                    "action_name": action["action_name"],
                    "target_entity": action["target_entity"],
                    "rollback_result": rollback_result,
                },
                at_utc=now_iso,
                conn=conn,
            )
        return get_remediation_action(action_id, tenant_id=tenant_id)
    finally:
        conn.close()


def reset_remediation_demo_state(tenant_id: Optional[str] = None) -> int:
    """
    Clears all remediation_actions rows and resets the simulated mock executor.
    Writes an audit entry tracking the demo reset within the same transaction.
    """
    conn = get_connection()
    try:
        with conn:
            if tenant_id:
                cur = conn.execute("DELETE FROM remediation_actions WHERE tenant_id = ?", (tenant_id,))
            else:
                cur = conn.execute("DELETE FROM remediation_actions")
            deleted = cur.rowcount
            record_audit_log(
                tenant_id=tenant_id or "acme",
                actor="dashboard.operator",
                action="remediation.demo_reset",
                detail={"cleared_count": deleted},
                conn=conn,
            )
    finally:
        conn.close()

    mock_executor.reset()
    return deleted


# ── Query Helpers ─────────────────────────────────────────────────────────────

def get_remediation_action(action_id: int, tenant_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    conn = get_connection()
    try:
        if tenant_id:
            cur = conn.execute(
                "SELECT * FROM remediation_actions WHERE id = ? AND tenant_id = ?",
                (action_id, tenant_id),
            )
        else:
            cur = conn.execute("SELECT * FROM remediation_actions WHERE id = ?", (action_id,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_remediation_actions(tenant_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_connection()
    try:
        cur = conn.execute(
            """
            SELECT * FROM remediation_actions
            WHERE tenant_id = ?
            ORDER BY id DESC
            LIMIT ?
            """,
            (tenant_id, limit),
        )
        return [dict(row) for row in cur.fetchall()]
    finally:
        conn.close()


def get_remediation_audit_trail(tenant_id: str, limit: int = 50) -> List[Dict[str, Any]]:
    conn = get_connection()
    try:
        cur = conn.execute(
            """
            SELECT id, tenant_id, actor, action, detail_json, at_utc
            FROM audit_log
            WHERE tenant_id = ? AND action LIKE 'remediation.%'
            ORDER BY id DESC
            LIMIT ?
            """,
            (tenant_id, limit),
        )
        rows = []
        for r in cur.fetchall():
            d = dict(r)
            try:
                d["detail"] = json.loads(d["detail_json"]) if d["detail_json"] else {}
            except Exception:
                d["detail"] = d["detail_json"]
            rows.append(d)
        return rows
    finally:
        conn.close()
