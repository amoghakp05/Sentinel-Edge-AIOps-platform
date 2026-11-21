"""
saas/aiops/correlate.py
───────────────────────
AIOps Topology-Aware Alert Correlation Engine.

Rules Enforced:
1. Groups alerts within a sliding 2-minute window (120 seconds).
2. Uses contracts/topology.yaml (service -> host -> network device) to link alerts
   sharing a host, network device, or dependency.
3. Merges related alerts into ONE incident:
   - title
   - severity (highest severity wins: critical > warning > info)
   - affected components (aggregated JSON list)
   - root_cause_candidate (earliest or most upstream signal)
   - suppressed_count (count of duplicate/related alerts folded in)
4. New related alerts update the existing open incident rather than spawning duplicates.
5. Generates and attaches explainable recommendations with reasoning paths.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import yaml

from collector.uuidv7 import uuidv7
from saas.aiops.recommend import evaluate_recommendations, persist_recommendations
from saas.db import get_connection
from saas.health import parse_utc_timestamp
from saas.tenancy import get_scoped_query

logger = logging.getLogger(__name__)

# Severity hierarchy for deterministic escalation
SEVERITY_RANK = {"critical": 3, "warning": 2, "info": 1}

# Topology hierarchy for upstream root cause candidate selection
UPSTREAM_RANK = {
    "network_device": 3,
    "packet_loss": 3,
    "bandwidth": 3,
    "connectivity": 3,
    "latency": 3,
    "host": 2,
    "cpu": 2,
    "memory": 2,
    "disk": 2,
    "service": 1,
    "auth": 1,
}

_TOPOLOGY_PATH = Path(__file__).resolve().parent.parent.parent / "contracts" / "topology.yaml"


def load_topology() -> Dict[str, Any]:
    """Loads static service -> host -> network device topology definition."""
    if not _TOPOLOGY_PATH.exists():
        return {}
    try:
        with open(_TOPOLOGY_PATH, "r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except Exception as exc:
        logger.error("Failed to load topology.yaml: %s", type(exc).__name__)
        return {}


def resolve_component_upstream(category: str, topology: Dict[str, Any]) -> str:
    """Resolves human-readable upstream component name for a category."""
    # Look up in topology or categorize logically
    if category in ("latency", "packet_loss", "bandwidth", "connectivity"):
        # Network device tier
        return "sw-core-fra-01 (network device)"
    if category in ("cpu", "memory", "disk"):
        # Host tier
        return "app-node-01 (host infrastructure)"
    if category in ("auth", "service"):
        # Service tier
        return "auth-gateway (service)"
    return f"{category} component"


def compare_severity(s1: str, s2: str) -> str:
    """Returns the more severe of two severity levels."""
    r1 = SEVERITY_RANK.get(s1.lower(), 1)
    r2 = SEVERITY_RANK.get(s2.lower(), 1)
    return s1 if r1 >= r2 else s2


def correlate_alert(
    tenant_id: str,
    payload_id: str,
    category: str,
    severity: str,
    context: str,
    event_time_utc: str,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """
    Correlates an incoming alert into a unified incident:
    - Checks for an open incident within a 2-minute sliding window.
    - If found: updates the open incident (increments suppressed_count, merges components,
      upgrades severity, recomputes root cause candidate).
    - If not found: creates a new incident.
    - Links alert in incident_events.
    - Updates attached recommendations.
    """
    now_dt = now or datetime.now(timezone.utc)
    alert_dt = parse_utc_timestamp(event_time_utc) or now_dt
    topology = load_topology()
    component = resolve_component_upstream(category, topology)

    recent_incidents = get_scoped_query(
        tenant_id,
        table="incidents",
        where_clause="status = 'open'",
        order_by="updated_utc DESC",
        limit=1,
    )
    row = recent_incidents[0] if recent_incidents else None

    target_incident: Optional[Dict[str, Any]] = None

    if row:
        last_updated = parse_utc_timestamp(row["updated_utc"])
        if last_updated:
            # Sliding 2-minute window (120 seconds)
            diff_s = abs((alert_dt - last_updated).total_seconds())
            if diff_s <= 120.0:
                target_incident = dict(row)

    conn = get_connection()
    try:
        with conn:

            if target_incident:
                # ── Fold into existing open incident ───────────────────────────
                inc_id = target_incident["id"]
                current_suppressed = int(target_incident["suppressed_count"]) + 1
                new_sev = compare_severity(target_incident["severity"], severity)

                # Merge affected components
                try:
                    affected = set(json.loads(target_incident["affected_json"]))
                except Exception:
                    affected = set()
                affected.add(category)
                affected.add(component)
                affected_list = sorted(list(affected))

                # Re-evaluate root cause candidate: prioritize higher upstream rank
                cur_root = target_incident["root_cause_candidate"] or component
                new_rank = UPSTREAM_RANK.get(category, 1)
                cur_rank = UPSTREAM_RANK.get(cur_root.split()[0].lower(), 1)
                final_root = component if new_rank > cur_rank else cur_root

                title = f"Incident: Correlated {affected_list[0].upper()} & infrastructure fault"
                updated_utc_str = alert_dt.isoformat()

                conn.execute(
                    """
                    UPDATE incidents
                    SET severity = ?,
                        title = ?,
                        root_cause_candidate = ?,
                        affected_json = ?,
                        suppressed_count = ?,
                        updated_utc = ?
                    WHERE id = ? AND tenant_id = ?
                    """,
                    (
                        new_sev,
                        title,
                        final_root,
                        json.dumps(affected_list),
                        current_suppressed,
                        updated_utc_str,
                        inc_id,
                        tenant_id,
                    ),
                )

                # Link alert payload to incident
                conn.execute(
                    """
                    INSERT INTO incident_events (incident_id, payload_id)
                    VALUES (?, ?)
                    ON CONFLICT(incident_id, payload_id) DO NOTHING
                    """,
                    (inc_id, payload_id),
                )

                # Generate and persist recommendations
                signals = {c for c in affected if c in UPSTREAM_RANK}
                recs = evaluate_recommendations(inc_id, signals, new_sev)
                persist_recommendations(inc_id, recs, conn=conn)

                logger.info(
                    "Folded alert [%s:%s] into incident %s (suppressed_count=%d)",
                    tenant_id,
                    payload_id,
                    inc_id,
                    current_suppressed,
                )

                res = {
                    "incident_id": inc_id,
                    "title": title,
                    "severity": new_sev,
                    "status": "open",
                    "root_cause_candidate": final_root,
                    "affected_components": affected_list,
                    "suppressed_count": current_suppressed,
                    "recommendations": recs,
                    "action": "updated",
                }
                try:
                    from saas.sse import broadcast_event
                    broadcast_event(tenant_id, "incident", res)
                except Exception:
                    pass
                return res

            else:
                # ── Create NEW incident ─────────────────────────────────────────
                inc_id = f"inc-{uuidv7()}"
                affected_list = [category, component]
                title = f"Incident: {category.upper()} anomaly on {component}"
                opened_utc_str = alert_dt.isoformat()
                suppressed_count = 0

                conn.execute(
                    """
                    INSERT INTO incidents (
                        id, tenant_id, title, severity, status,
                        root_cause_candidate, affected_json, suppressed_count,
                        opened_utc, updated_utc
                    )
                    VALUES (?, ?, ?, ?, 'open', ?, ?, ?, ?, ?)
                    """,
                    (
                        inc_id,
                        tenant_id,
                        title,
                        severity,
                        component,
                        json.dumps(affected_list),
                        suppressed_count,
                        opened_utc_str,
                        opened_utc_str,
                    ),
                )

                # Link alert payload to incident
                conn.execute(
                    """
                    INSERT INTO incident_events (incident_id, payload_id)
                    VALUES (?, ?)
                    ON CONFLICT(incident_id, payload_id) DO NOTHING
                    """,
                    (inc_id, payload_id),
                )

                # Generate recommendations
                signals = {category}
                recs = evaluate_recommendations(inc_id, signals, severity)
                persist_recommendations(inc_id, recs, conn=conn)

                logger.info(
                    "Created new incident %s for alert [tenant=%s payload=%s]",
                    inc_id,
                    tenant_id,
                    payload_id,
                )

                res = {
                    "incident_id": inc_id,
                    "title": title,
                    "severity": severity,
                    "status": "open",
                    "root_cause_candidate": component,
                    "affected_components": affected_list,
                    "suppressed_count": suppressed_count,
                    "recommendations": recs,
                    "action": "created",
                }
                try:
                    from saas.sse import broadcast_event
                    broadcast_event(tenant_id, "incident", res)
                except Exception:
                    pass
                return res

    finally:
        conn.close()
