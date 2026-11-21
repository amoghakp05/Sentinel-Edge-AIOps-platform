"""
saas/ingest.py
──────────────
SaaS Telemetry Ingestion Handler.

Rules Enforced:
- Hard Rule 1: Allow-list validation on server side; rejects unknown fields,
  bad types, over-length strings, or secret scanner hits with 400.
- Hard Rule 3: The SaaS derives tenant_id and collector_id from the collector credential,
  NEVER from the request body. Any 'tenant_id' inside the body is dropped/ignored.
- Hard Rule 5: Dedupe on (tenant_id, payload_id). Retried duplicate payloads still
  receive an ACK containing payload_id and sha256 of the stored body.
- Separate storage for event_time_utc and received_at.
- Updates collectors.last_seen, version, and status from heartbeats.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from saas.auth import authenticate_collector
from saas.db import get_connection
from saas.regions import verify_tenant_region
from saas.validate import validate_payload

logger = logging.getLogger(__name__)

# Heartbeat context parsing patterns
_RE_VERSION = re.compile(r"v([0-9.]+)")
_RE_CPU = re.compile(r"cpu=([0-9.]+)%")
_RE_MEM = re.compile(r"mem=([0-9.]+)MB")
_RE_QUEUE = re.compile(r"queue=([0-9]+)")
_RE_CFG = re.compile(r"cfg=([a-f0-9]+)")


def compute_ack_hash(payload: Dict[str, Any]) -> str:
    """Computes deterministic SHA-256 of stored payload body."""
    return hashlib.sha256(json.dumps(payload, sort_keys=True).encode("utf-8")).hexdigest()


def handle_ingest(
    api_key: Optional[str],
    signature: Optional[str],
    body_bytes: bytes,
) -> Tuple[int, Dict[str, Any]]:
    """
    Validates collector credentials, derives tenant_id & collector_id,
    verifies regional pin, applies server-side validation against allow-list,
    stores records with ON CONFLICT DO NOTHING, updates collector heartbeat state,
    and returns idempotent ACKs.
    """
    # 1. Authenticate collector and derive tenant_id & collector_id
    auth = authenticate_collector(api_key, signature, body_bytes)
    if not auth:
        return 401, {"error": "Unauthorized collector credential or invalid HMAC signature"}

    tenant_id, credential_collector_id = auth

    # 2. Regional routing check
    region_ok, region_err = verify_tenant_region(tenant_id, credential_collector_id)
    if not region_ok:
        return 421, {"error": region_err or "Misdirected Request: wrong region"}

    # 3. Parse JSON body
    try:
        data = json.loads(body_bytes.decode("utf-8"))
    except Exception:
        return 400, {"error": "Invalid JSON body format"}

    payloads = data.get("payloads", [])
    if not isinstance(payloads, list):
        return 400, {"error": "'payloads' must be an array"}

    # 4. Server-side validation against allow-list
    # Reject unknown fields, bad types, over-length strings, secret scanner hits
    for item in payloads:
        if not isinstance(item, dict):
            return 400, {"error": "Each payload element must be a JSON object"}

        # Hard Rule 3: Never trust client-provided tenant_id in body; drop/ignore it immediately
        item.pop("tenant_id", None)

        valid, err_msg = validate_payload(item, tenant_id, credential_collector_id)
        if not valid:
            return 400, {"error": err_msg or "Payload failed server validation"}

    # 5. Process and store valid payloads
    acks: List[Dict[str, str]] = []
    received_at = datetime.now(timezone.utc).isoformat()
    conn = get_connection()

    try:
        with conn:
            for item in payloads:
                # Copy item so modifications do not corrupt external state
                item_copy = dict(item)

                # Hard Rule 3: Never trust client-provided tenant_id; use credential tenant_id
                item_copy.pop("tenant_id", None)

                payload_id = str(item_copy.get("payload_id", ""))
                event_time_utc = str(item_copy.get("event_time_utc", ""))
                kind = str(item_copy.get("kind", "metric"))
                collector_id = str(item_copy.get("collector_id", credential_collector_id))
                source_ref = str(item_copy.get("source_ref", ""))
                category = item_copy.get("category")
                severity = str(item_copy.get("severity", "info"))
                context = item_copy.get("context")
                value = item_copy.get("value")
                unit = item_copy.get("unit")

                ack_hash = compute_ack_hash(item_copy)

                # Store in metrics table if metric
                if kind == "metric":
                    conn.execute(
                        """
                        INSERT INTO metrics (
                            tenant_id, payload_id, collector_id, source_ref,
                            category, value, unit, event_time_utc, received_at
                        )
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                        ON CONFLICT(tenant_id, payload_id) DO NOTHING
                        """,
                        (
                            tenant_id,
                            payload_id,
                            collector_id,
                            source_ref,
                            category or "unknown",
                            value,
                            unit,
                            event_time_utc,
                            received_at,
                        ),
                    )

                # Store in events table for all kinds (alerts, heartbeats, security_summary, health)
                conn.execute(
                    """
                    INSERT INTO events (
                        tenant_id, payload_id, kind, category, severity,
                        context, event_time_utc, received_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(tenant_id, payload_id) DO NOTHING
                    """,
                    (
                        tenant_id,
                        payload_id,
                        kind,
                        category,
                        severity,
                        context,
                        event_time_utc,
                        received_at,
                    ),
                )

                # Update collector heartbeat state
                if kind == "heartbeat":
                    version = None
                    cpu = None
                    mem = None
                    queue_depth = None
                    config_hash = None

                    if context:
                        m_v = _RE_VERSION.search(context)
                        if m_v:
                            version = m_v.group(1)
                        m_c = _RE_CPU.search(context)
                        if m_c:
                            cpu = float(m_c.group(1))
                        m_m = _RE_MEM.search(context)
                        if m_m:
                            mem = float(m_m.group(1))
                        m_q = _RE_QUEUE.search(context)
                        if m_q:
                            queue_depth = int(m_q.group(1))
                        m_h = _RE_CFG.search(context)
                        if m_h:
                            config_hash = m_h.group(1)

                    conn.execute(
                        """
                        UPDATE collectors
                        SET last_seen = ?,
                            status = 'active',
                            version = COALESCE(?, version),
                            cpu = COALESCE(?, cpu),
                            mem = COALESCE(?, mem),
                            queue_depth = COALESCE(?, queue_depth),
                            config_hash = COALESCE(?, config_hash)
                        WHERE id = ? AND tenant_id = ?
                        """,
                        (
                            received_at,
                            version,
                            cpu,
                            mem,
                            queue_depth,
                            config_hash,
                            collector_id,
                            tenant_id,
                        ),
                    )

                # Retried duplicates still receive an ACK
                acks.append({
                    "payload_id": payload_id,
                    "ack_hash": ack_hash,
                })

    finally:
        conn.close()

    # Broadcast telemetry & heartbeats to SSE subscribers
    try:
        from saas.sse import broadcast_event
        for item in payloads:
            if isinstance(item, dict):
                k = item.get("kind")
                if k == "metric":
                    broadcast_event(tenant_id, "telemetry", {
                        "payload_id": item.get("payload_id"),
                        "category": item.get("category"),
                        "value": item.get("value"),
                        "unit": item.get("unit"),
                        "source_ref": item.get("source_ref"),
                        "event_time_utc": item.get("event_time_utc"),
                    })
                elif k == "heartbeat":
                    broadcast_event(tenant_id, "collector_heartbeat", {
                        "collector_id": item.get("collector_id", credential_collector_id),
                        "last_seen": received_at,
                        "context": item.get("context"),
                    })
                elif k == "security_summary":
                    broadcast_event(tenant_id, "security_event", {
                        "payload_id": item.get("payload_id"),
                        "category": item.get("category"),
                        "severity": item.get("severity"),
                        "context": item.get("context"),
                        "event_time_utc": item.get("event_time_utc"),
                    })
    except Exception as exc:
        logger.debug("Failed to broadcast SSE telemetry: %s", type(exc).__name__)

    # Trigger AIOps anomaly evaluation after DB transaction has committed cleanly
    for item in payloads:
        if isinstance(item, dict):
            k = item.get("kind")
            v = item.get("value")
            c = item.get("category")
            t_utc = str(item.get("event_time_utc", received_at))
            s_ref = str(item.get("source_ref", ""))
            pid = str(item.get("payload_id", ""))
            sev = str(item.get("severity", "info"))
            ctx = str(item.get("context", ""))

            if k == "metric" and v is not None and c and s_ref:
                try:
                    from saas.aiops.engine import process_metric_telemetry
                    process_metric_telemetry(
                        tenant_id=tenant_id,
                        source_ref=s_ref,
                        category=c,
                        value=float(v),
                        event_time_utc_str=t_utc,
                    )
                except Exception as exc:
                    logger.debug("AIOps post-ingest error: %s", type(exc).__name__)

            elif k == "alert" and c and pid:
                try:
                    from saas.aiops.correlate import correlate_alert
                    correlate_alert(
                        tenant_id=tenant_id,
                        payload_id=pid,
                        category=c,
                        severity=sev,
                        context=ctx,
                        event_time_utc=t_utc,
                    )
                except Exception as exc:
                    logger.debug("Alert correlation post-ingest error: %s", type(exc).__name__)

    return 200, {
        "status": "ok",
        "tenant_id": tenant_id,
        "received_count": len(payloads),
        "acked": acks,
    }


def reset_ingest_state_for_tests() -> None:
    """Helper for test suites to reset or re-init tables if needed."""
    pass
