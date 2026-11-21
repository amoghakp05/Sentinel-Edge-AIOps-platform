"""
saas/audit.py
─────────────
Immutable audit logging for tenant actions, security violations, and region routing errors.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from saas.db import get_connection


def record_audit_log(
    tenant_id: str,
    actor: str,
    action: str,
    detail: Optional[Dict[str, Any] | str] = None,
    at_utc: Optional[str] = None,
    conn: Optional[Any] = None,
) -> int:
    """
    Appends an immutable audit log record to the saas database.
    Returns the inserted row ID.
    If conn is provided, executes within the caller's transaction.
    """
    now_iso = at_utc or datetime.now(timezone.utc).isoformat()
    detail_str = (
        json.dumps(detail) if isinstance(detail, (dict, list))
        else (str(detail) if detail is not None else "")
    )

    if conn is not None:
        cursor = conn.execute(
            """
            INSERT INTO audit_log (tenant_id, actor, action, detail_json, at_utc)
            VALUES (?, ?, ?, ?, ?)
            """,
            (tenant_id, actor, action, detail_str, now_iso),
        )
        return cursor.lastrowid or 0

    c = get_connection()
    try:
        with c:
            cursor = c.execute(
                """
                INSERT INTO audit_log (tenant_id, actor, action, detail_json, at_utc)
                VALUES (?, ?, ?, ?, ?)
                """,
                (tenant_id, actor, action, detail_str, now_iso),
            )
            return cursor.lastrowid or 0
    finally:
        c.close()
