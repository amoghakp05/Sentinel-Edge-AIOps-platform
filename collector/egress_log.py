"""
collector/egress_log.py
───────────────────────
Append-only cryptographic proof of transmission.

Contract:
- For every send attempt, record the exact JSON string sent (identical bytes),
  its SHA-256 digest, timestamp (UTC), destination URL, and initial status.
- Rows are append-only. They are NEVER updated or deleted, except to set
  the final delivery status and record the SaaS's returned ACK hash.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from collector.db import get_db


def log_send_attempt(payload_id: str, exact_json: str, destination: str, status: str = "pending") -> int:
    """
    Appends an egress record to the local egress_log table.
    Computes and stores SHA-256 of the exact bytes transmitted.
    Returns the auto-incrementing sequence number (seq).
    """
    sha256_digest = hashlib.sha256(exact_json.encode("utf-8")).hexdigest()
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = get_db()
    cur = conn.execute(
        """
        INSERT INTO egress_log (payload_id, ts_utc, exact_json, sha256, destination, status, saas_ack_hash)
        VALUES (?, ?, ?, ?, ?, ?, NULL)
        """,
        (payload_id, now_utc, exact_json, sha256_digest, destination, status),
    )
    conn.commit()

    return cur.lastrowid or 0


def record_saas_ack(payload_id: str, saas_ack_hash: str) -> None:
    """
    Records the SaaS response body hash upon successful acknowledgment.
    """
    conn = get_db()
    conn.execute(
        """
        UPDATE egress_log
        SET status = 'acked',
            saas_ack_hash = ?
        WHERE payload_id = ?
        """,
        (saas_ack_hash, payload_id),
    )
    conn.commit()


def get_egress_record(payload_id: str) -> Optional[Dict[str, Any]]:
    """Retrieve full egress details for a specific payload_id."""
    conn = get_db()
    row = conn.execute(
        "SELECT seq, payload_id, ts_utc, exact_json, sha256, destination, status, saas_ack_hash FROM egress_log WHERE payload_id = ? ORDER BY seq DESC LIMIT 1",
        (payload_id,),
    ).fetchone()

    return dict(row) if row else None


def tail_egress(limit: int = 20) -> List[Dict[str, Any]]:
    """Return the latest *limit* egress records."""
    conn = get_db()
    rows = conn.execute(
        "SELECT seq, payload_id, ts_utc, sha256, destination, status, saas_ack_hash FROM egress_log ORDER BY seq DESC LIMIT ?",
        (limit,),
    ).fetchall()

    return [dict(r) for r in rows]
