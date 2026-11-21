"""
saas/health.py
──────────────
AIOps Health Engine & State Machine.

Evaluates health state per collector and per monitored source:
- POOR:      No heartbeat for >= 60 s, critical alert, metric beyond poor threshold,
             or critical security event.
- FAIR:      Elevated latency/resource/packet loss, recurring warnings, or data
             stale for 30-59 s.
- GOOD:      Minor deviations with no service impact.
- EXCELLENT: Collector reporting on time and all metrics within baseline.

Rules Enforced:
- Hard Rule 7: Missing/stale data degrades health state. Never show last good value as healthy.
- Thresholds come from the thresholds table (per tenant, editable via API).
- Every state transition writes an immutable health_history row.
- State changes broadcast over Server-Sent Events (SSE).
- Background evaluation runs every 3 seconds.
"""

from __future__ import annotations

import asyncio
import logging
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Tuple

from saas.db import get_connection
from saas.sse import broadcast_health_change
from saas.tenancy import get_scoped_query

logger = logging.getLogger(__name__)

HealthState = Literal["Excellent", "Good", "Fair", "Poor"]

# Severity ranking for deterministic worst-state-wins resolution
_STATE_SEVERITY: Dict[str, int] = {
    "Poor": 4,
    "Fair": 3,
    "Good": 2,
    "Excellent": 1,
    "Unknown": 0,
}


def parse_utc_timestamp(ts: Optional[str]) -> Optional[datetime]:
    """Parses ISO-8601 UTC timestamp to aware datetime."""
    if not ts:
        return None
    try:
        clean = ts.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean)
        if dt.tzinfo is None:
            return dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def get_tenant_thresholds(tenant_id: str) -> Dict[str, Dict[str, Any]]:
    """Retrieves configured thresholds for the tenant from the thresholds table."""
    threshold_rows = get_scoped_query(tenant_id, table="thresholds")
    result: Dict[str, Dict[str, Any]] = {}
    for r in threshold_rows:
        result[r["category"]] = {
            "fair_at": float(r["fair_at"]),
            "poor_at": float(r["poor_at"]),
            "stale_fair_s": int(r["stale_fair_s"]),
            "stale_poor_s": int(r["stale_poor_s"]),
        }
    return result


def evaluate_collector_health(
    collector: Dict[str, Any],
    now: datetime,
) -> Tuple[HealthState, str]:
    """
    Evaluates health of a collector based on heartbeat recency and process metrics.
    """
    collector_id = collector["id"]
    last_seen_str = collector.get("last_seen")

    if not last_seen_str:
        return "Poor", f"Poor: collector '{collector_id}' has never reported"

    last_seen_dt = parse_utc_timestamp(last_seen_str)
    if not last_seen_dt:
        return "Poor", f"Poor: invalid last_seen timestamp '{last_seen_str}'"

    elapsed_s = max(0.0, (now - last_seen_dt).total_seconds())

    # Staleness evaluation
    if elapsed_s >= 60.0:
        return "Poor", f"Poor: no heartbeat for {int(elapsed_s)} s"
    if elapsed_s >= 30.0:
        return "Fair", f"Fair: data stale for {int(elapsed_s)} s"

    # Process metrics evaluation when reporting on time
    cpu = collector.get("cpu")
    mem = collector.get("mem")

    if cpu is not None and cpu >= 92.0:
        return "Poor", f"Poor: collector process CPU saturated ({cpu}%)"
    if cpu is not None and cpu >= 75.0:
        return "Fair", f"Fair: elevated collector CPU ({cpu}%)"
    if cpu is not None and cpu > 60.0:
        return "Good", f"Good: minor collector CPU deviation ({cpu}%)"

    return "Excellent", f"Excellent: collector reporting on time ({int(elapsed_s)}s ago)"


def evaluate_source_health(
    tenant_id: str,
    source_ref: str,
    thresholds: Dict[str, Dict[str, Any]],
    now: datetime,
) -> Tuple[HealthState, str]:
    """
    Evaluates health of a monitored source entity.
    Checks latest metrics, event severity, and staleness.
    """
    # Query latest metrics for this source
    recent_metrics = get_scoped_query(
        tenant_id,
        table="metrics",
        where_clause="source_ref = ?",
        params=[source_ref],
        order_by="event_time_utc DESC",
        limit=50,
    )

    # Query recent events for this source
    recent_events = get_scoped_query(
        tenant_id,
        table="events",
        order_by="event_time_utc DESC",
        limit=20,
    )

    # Determine latest activity timestamp
    latest_dt: Optional[datetime] = None
    if recent_metrics:
        latest_dt = parse_utc_timestamp(recent_metrics[0].get("event_time_utc"))

    if not latest_dt:
        return "Poor", f"Poor: no telemetry data received for source {source_ref}"

    elapsed_s = max(0.0, (now - latest_dt).total_seconds())

    # 1. Staleness evaluation: stale data must downgrade the state
    if elapsed_s >= 60.0:
        return "Poor", f"Poor: data stale for {int(elapsed_s)} s"
    if elapsed_s >= 30.0:
        return "Fair", f"Fair: data stale for {int(elapsed_s)} s"

    candidates: List[Tuple[HealthState, str]] = []

    # 2. Critical events check
    for ev in recent_events:
        ev_dt = parse_utc_timestamp(ev.get("event_time_utc"))
        if ev_dt and (now - ev_dt).total_seconds() <= 120.0:
            sev = str(ev.get("severity", "info")).lower()
            kind = str(ev.get("kind", ""))
            ctx = ev.get("context", "")

            if sev == "critical":
                candidates.append(("Poor", f"Poor: critical alert in {ev.get('category')} ({ctx})"))
            elif kind == "security_summary" and ("risk" in ctx.lower() or sev in ("critical", "warning")):
                if sev == "critical":
                    candidates.append(("Poor", f"Poor: critical security event: {ctx}"))
                else:
                    candidates.append(("Fair", f"Fair: elevated security risk: {ctx}"))
            elif sev == "warning":
                candidates.append(("Fair", f"Fair: warning alert in {ev.get('category')}"))

    # 3. Metric thresholds check (deduplicated by category, most recent per category)
    seen_cats = set()
    for m in recent_metrics:
        cat = m.get("category")
        val = m.get("value")
        if not cat or cat in seen_cats or val is None:
            continue
        seen_cats.add(cat)

        th = thresholds.get(cat, {})
        fair_at = th.get("fair_at")
        poor_at = th.get("poor_at")

        if cat == "bandwidth":
            # Inverted threshold: LOW bandwidth is bad
            if poor_at is not None and val <= poor_at:
                candidates.append(("Poor", f"Poor: bandwidth ({val} Mbps) below poor threshold ({poor_at})"))
            elif fair_at is not None and val <= fair_at:
                candidates.append(("Fair", f"Fair: bandwidth ({val} Mbps) below fair threshold ({fair_at})"))
        elif cat == "connectivity":
            if val == 0.0:
                candidates.append(("Poor", "Poor: service connectivity is down"))
        else:
            # Standard threshold: HIGH values are bad
            if poor_at is not None and val >= poor_at:
                candidates.append(("Poor", f"Poor: {cat} ({val}) exceeds poor threshold ({poor_at})"))
            elif fair_at is not None and val >= fair_at:
                candidates.append(("Fair", f"Fair: {cat} ({val}) elevated above fair threshold ({fair_at})"))
            elif fair_at is not None and val >= (fair_at * 0.8):
                candidates.append(("Good", f"Good: {cat} ({val}) has minor deviation"))

    # Default if no alerts or threshold violations
    if not candidates:
        return "Excellent", "Excellent: reporting on time and all metrics within baseline"

    # Select worst state (most severe candidate)
    candidates.sort(key=lambda c: _STATE_SEVERITY.get(c[0], 0), reverse=True)
    return candidates[0]


def record_state_transition(
    tenant_id: str,
    entity_id: str,
    new_state: HealthState,
    new_reason: str,
    now: datetime,
) -> bool:
    """
    Compares new evaluation against current health_state in DB.
    If state changed:
      1. Updates health_state table
      2. Appends health_history transition record
      3. Broadcasts SSE event
    Returns True if state changed, False otherwise.
    """
    now_iso = now.isoformat()
    conn = get_connection()
    state_changed = False

    try:
        with conn:
            cur = conn.execute(
                "SELECT state, reason FROM health_state WHERE tenant_id = ? AND entity_id = ?",
                (tenant_id, entity_id),
            )
            row = cur.fetchone()

            if not row:
                # Initial registration
                from_state = "Unknown"
                state_changed = True
                conn.execute(
                    """
                    INSERT INTO health_state (tenant_id, entity_id, state, reason, updated_utc)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (tenant_id, entity_id, new_state, new_reason, now_iso),
                )
                conn.execute(
                    """
                    INSERT INTO health_history (tenant_id, entity_id, from_state, to_state, reason, at_utc)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (tenant_id, entity_id, from_state, new_state, new_reason, now_iso),
                )
            else:
                prev_state = row["state"]
                if prev_state != new_state:
                    state_changed = True
                    conn.execute(
                        """
                        UPDATE health_state
                        SET state = ?, reason = ?, updated_utc = ?
                        WHERE tenant_id = ? AND entity_id = ?
                        """,
                        (new_state, new_reason, now_iso, tenant_id, entity_id),
                    )
                    conn.execute(
                        """
                        INSERT INTO health_history (tenant_id, entity_id, from_state, to_state, reason, at_utc)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        (tenant_id, entity_id, prev_state, new_state, new_reason, now_iso),
                    )
                else:
                    # Update reason and timestamp if reason evolved
                    conn.execute(
                        """
                        UPDATE health_state
                        SET reason = ?, updated_utc = ?
                        WHERE tenant_id = ? AND entity_id = ?
                        """,
                        (new_reason, now_iso, tenant_id, entity_id),
                    )

        if state_changed:
            event_payload = {
                "entity_id": entity_id,
                "from_state": from_state if not row else row["state"],
                "to_state": new_state,
                "reason": new_reason,
                "at_utc": now_iso,
            }
            broadcast_health_change(tenant_id, event_payload)

        return state_changed

    finally:
        conn.close()


def evaluate_tenant_health(tenant_id: str, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """
    Executes a complete health evaluation sweep for a tenant across
    all registered collectors and monitored sources.
    """
    now_dt = now or datetime.now(timezone.utc)
    thresholds = get_tenant_thresholds(tenant_id)
    evaluated_states: List[Dict[str, Any]] = []

    # 1. Evaluate registered collectors
    collectors = get_scoped_query(tenant_id, table="collectors")
    for col in collectors:
        c_id = col["id"]
        state, reason = evaluate_collector_health(col, now_dt)
        record_state_transition(tenant_id, c_id, state, reason, now_dt)
        evaluated_states.append({
            "entity_id": c_id,
            "type": "collector",
            "state": state,
            "reason": reason,
            "updated_utc": now_dt.isoformat(),
        })

    # 2. Evaluate monitored source entities
    conn = get_connection()
    try:
        cur = conn.execute(
            "SELECT DISTINCT source_ref FROM metrics WHERE tenant_id = ?",
            (tenant_id,),
        )
        sources = [r["source_ref"] for r in cur.fetchall() if r["source_ref"]]
    finally:
        conn.close()

    for src_ref in sources:
        state, reason = evaluate_source_health(tenant_id, src_ref, thresholds, now_dt)
        record_state_transition(tenant_id, src_ref, state, reason, now_dt)
        evaluated_states.append({
            "entity_id": src_ref,
            "type": "source",
            "state": state,
            "reason": reason,
            "updated_utc": now_dt.isoformat(),
        })

    return evaluated_states


class HealthEngineService:
    """
    Background worker that runs evaluate_tenant_health every 3 seconds.
    """

    def __init__(self, interval_s: float = 3.0):
        self.interval_s = interval_s
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run_loop, daemon=True, name="health-engine")
        self._thread.start()
        logger.info("Started HealthEngineService loop (interval=%.1fs)", self.interval_s)

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=2.0)
            logger.info("Stopped HealthEngineService loop")

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                conn = get_connection()
                tenants = [r["id"] for r in conn.execute("SELECT id FROM tenants").fetchall()]
                conn.close()

                for t_id in tenants:
                    evaluate_tenant_health(t_id)

            except Exception as exc:
                logger.error("Error in health engine loop: %s", type(exc).__name__)

            self._stop_event.wait(self.interval_s)


# Global singleton instance
health_engine = HealthEngineService()
