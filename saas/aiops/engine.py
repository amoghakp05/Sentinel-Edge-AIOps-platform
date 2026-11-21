"""
saas/aiops/engine.py
───────────────────
AIOps Orchestration & Alerting Service.

Coordinates:
1. Real-time metric evaluation via detect.py and baseline.py
2. Anomaly persistence to the 'anomalies' database table
3. Raising alerts within 15 seconds of the event time
4. Recording the alert-creation timestamp for latency tracking
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from collector.uuidv7 import uuidv7
from saas.aiops.detect import detector
from saas.db import get_connection
from saas.health import parse_utc_timestamp
from saas.sse import broadcast_health_change

logger = logging.getLogger(__name__)


def process_metric_telemetry(
    tenant_id: str,
    source_ref: str,
    category: str,
    value: float,
    event_time_utc_str: str,
    correlated_metrics: Optional[Dict[str, float]] = None,
    now: Optional[datetime] = None,
) -> Tuple[bool, Optional[Dict[str, Any]], Optional[Dict[str, Any]]]:
    """
    Evaluates an incoming metric reading for anomalies.
    If an anomaly is detected:
      1. Stores anomaly record in the 'anomalies' table.
      2. Raises an alert in the 'events' table within 15 s of event_time_utc.
      3. Records alert_created_at timestamp and measures alert latency.

    Returns:
        (is_anomaly, explanation, alert_record)
    """
    event_dt = parse_utc_timestamp(event_time_utc_str) or datetime.now(timezone.utc)
    now_dt = now or datetime.now(timezone.utc)

    # 1. Run detection
    is_anomaly, explanation = detector.evaluate_metric(
        tenant_id=tenant_id,
        source_ref=source_ref,
        category=category,
        value=value,
        event_time_utc=event_dt,
        correlated_metrics=correlated_metrics,
    )

    if not is_anomaly or not explanation:
        return False, None, None

    # 2. Measure alert latency: alert creation time minus event time
    alert_created_at = now_dt.isoformat()
    latency_s = max(0.0, (now_dt - event_dt).total_seconds())

    # 3. Store anomaly record
    contributing_str = json.dumps(explanation["contributing"])
    conn = get_connection()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO anomalies (
                    tenant_id, source_ref, category, observed,
                    baseline, zscore, contributing_json, confidence, at_utc
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    source_ref,
                    category,
                    explanation["observed"],
                    explanation["baseline"],
                    explanation["zscore"],
                    contributing_str,
                    explanation["confidence"],
                    alert_created_at,
                ),
            )

            # 4. Raise alert in events table
            payload_id = uuidv7()
            severity = "critical" if abs(explanation["zscore"]) >= 4.0 else "warning"
            conn.execute(
                """
                INSERT INTO events (
                    tenant_id, payload_id, kind, category, severity,
                    context, event_time_utc, received_at
                )
                VALUES (?, ?, 'alert', ?, ?, ?, ?, ?)
                """,
                (
                    tenant_id,
                    payload_id,
                    category,
                    severity,
                    explanation["why"],
                    event_time_utc_str,
                    alert_created_at,
                ),
            )
    finally:
        conn.close()

    alert_record = {
        "payload_id": payload_id,
        "tenant_id": tenant_id,
        "source_ref": source_ref,
        "category": category,
        "severity": severity,
        "event_time_utc": event_time_utc_str,
        "alert_created_at": alert_created_at,
        "latency_s": round(latency_s, 3),
        "explanation": explanation,
    }

    # Broadcast alert over SSE
    broadcast_health_change(tenant_id, {
        "type": "anomaly_alert",
        "category": category,
        "severity": severity,
        "latency_s": latency_s,
        "explanation": explanation,
    })

    # Correlate alert into unified incident within sliding 2-minute window
    try:
        from saas.aiops.correlate import correlate_alert
        correlate_alert(
            tenant_id=tenant_id,
            payload_id=payload_id,
            category=category,
            severity=severity,
            context=explanation["why"],
            event_time_utc=event_time_utc_str,
            now=now_dt,
        )
    except Exception as corr_exc:
        logger.debug("Incident correlation error: %s", type(corr_exc).__name__)

    logger.info(
        "Raised AIOps alert [tenant=%s payload=%s category=%s] latency=%.3fs",
        tenant_id,
        payload_id,
        category,
        latency_s,
    )

    return True, explanation, alert_record
