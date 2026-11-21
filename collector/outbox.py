"""
collector/outbox.py
───────────────────
Local persistent outbox queue manager (Store-and-Forward Pattern).

Rules:
- Hard Rule 4: Write to the outbox table with status='pending' BEFORE any network call.
- Mark sent ONLY after an explicit SaaS ACK.
- Guaranteed FIFO draining: oldest records transmitted first.
- payload_id is an RFC 9562 UUIDv7.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from collector.db import get_db
from collector.uuidv7 import uuidv7


def enqueue(payload: Dict[str, Any], validate_policy: bool = True) -> str:
    """
    Inserts a validated payload into the outbox with status='pending'.
    Enforces egress allow-list policy before queuing.
    Assigns a UUIDv7 payload_id if one is not already present.
    Returns the payload_id.
    """
    if validate_policy:
        from collector import policy
        allowed, filtered, reason = policy.enforce_policy(payload)
        if not allowed or not filtered:
            raise ValueError(f"Payload rejected by egress policy: {reason}")
        payload = filtered

    if "payload_id" not in payload or not payload["payload_id"]:
        payload["payload_id"] = uuidv7()

    payload_id = str(payload["payload_id"])
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    body_json = json.dumps(payload, sort_keys=True)

    conn = get_db()
    conn.execute(
        """
        INSERT INTO outbox (payload_id, body_json, status, attempts, next_try_at, created_at)
        VALUES (?, ?, 'pending', 0, ?, ?)
        ON CONFLICT(payload_id) DO UPDATE SET
            body_json = excluded.body_json
        """,
        (payload_id, body_json, now_utc, now_utc),
    )
    conn.commit()

    return payload_id


def get_pending_batch(limit: int = 50) -> List[Dict[str, Any]]:
    """
    Fetches up to *limit* oldest pending outbox items ready for transmission.
    Ordered strictly by created_at ASC (FIFO).
    """
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    conn = get_db()

    rows = conn.execute(
        """
        SELECT payload_id, body_json, attempts, created_at
        FROM   outbox
        WHERE  status = 'pending'
          AND  (next_try_at IS NULL OR next_try_at <= ?)
        ORDER  BY created_at ASC
        LIMIT  ?
        """,
        (now_utc, limit),
    ).fetchall()

    results: List[Dict[str, Any]] = []
    for r in rows:
        try:
            body = json.loads(r["body_json"])
            results.append({
                "payload_id": r["payload_id"],
                "body": body,
                "raw_json": r["body_json"],
                "attempts": r["attempts"],
                "created_at": r["created_at"],
            })
        except Exception:
            continue

    return results


def mark_acked(payload_id: str) -> None:
    """
    Marks an outbox item as successfully transmitted and acknowledged.
    """
    conn = get_db()
    conn.execute(
        "UPDATE outbox SET status = 'sent' WHERE payload_id = ?",
        (payload_id,),
    )
    conn.commit()


def mark_failed(payload_id: str, next_try_at_utc: str) -> None:
    """
    Increments attempt counter and sets the backoff timestamp.
    Status remains 'pending'.
    """
    conn = get_db()
    conn.execute(
        """
        UPDATE outbox
        SET attempts = attempts + 1,
            next_try_at = ?
        WHERE payload_id = ?
        """,
        (next_try_at_utc, payload_id),
    )
    conn.commit()


def get_outbox_stats() -> Dict[str, Any]:
    """
    Returns real-time queue depth and age metrics for status/diagnostics.
    """
    conn = get_db()
    pending_row = conn.execute(
        "SELECT count(*), min(created_at) FROM outbox WHERE status = 'pending'"
    ).fetchone()

    pending_count = pending_row[0] if pending_row else 0
    oldest_created = pending_row[1] if pending_row else None
    oldest_age_s = 0.0

    if oldest_created:
        try:
            oldest_dt = datetime.fromisoformat(oldest_created.replace("Z", "+00:00"))
            now_dt = datetime.now(timezone.utc)
            oldest_age_s = max(0.0, (now_dt - oldest_dt).total_seconds())
        except Exception:
            pass

    return {
        "pending_count": pending_count,
        "oldest_age_s": round(oldest_age_s, 1),
        "oldest_created_at": oldest_created,
        "state": "Buffering" if pending_count > 0 else "Online",
    }
