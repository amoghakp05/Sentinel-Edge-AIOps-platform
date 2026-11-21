"""
saas/tenancy.py
───────────────
Hard Rule 4: Multi-tenancy isolation.
Every SaaS read query MUST go through get_scoped_query(tenant_id).
No raw or un-scoped queries elsewhere.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Sequence, Union

from saas.db import get_connection

logger = logging.getLogger(__name__)

# Permitted tables for tenant-scoped reads
ALLOWED_TABLES = {
    "metrics",
    "events",
    "health_state",
    "health_history",
    "thresholds",
    "anomalies",
    "baselines",
    "incidents",
    "incident_events",
    "recommendations",
    "remediation_actions",
    "audit_log",
    "collectors",
    "tenants",
}


def get_scoped_query(
    tenant_id: str,
    table: Optional[str] = None,
    columns: Optional[Sequence[str]] = None,
    where_clause: Optional[str] = None,
    params: Optional[Sequence[Any]] = None,
    order_by: Optional[str] = None,
    limit: Optional[int] = None,
    raw_sql: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Executes a read query strictly bound to tenant_id.

    Usage 1 (Structured table query):
        rows = get_scoped_query(
            tenant_id="acme",
            table="metrics",
            where_clause="category = ?",
            params=["cpu"],
            order_by="event_time_utc ASC",
        )

    Usage 2 (Direct SQL with mandatory tenant parameter binding):
        rows = get_scoped_query(
            tenant_id="acme",
            raw_sql="SELECT * FROM events WHERE tenant_id = ? AND kind = ? ORDER BY event_time_utc ASC",
            params=["alert"],
        )

    Returns:
        List of row dicts matching the tenant-scoped query.
    """
    if not tenant_id or not isinstance(tenant_id, str):
        raise ValueError("A valid non-empty tenant_id string is required for all reads")

    conn = get_connection()
    try:
        if raw_sql:
            # Enforce that raw SQL contains tenant_id filtering
            sql_clean = raw_sql.strip()
            if not sql_clean.upper().startswith("SELECT"):
                raise ValueError("get_scoped_query only permits SELECT queries")

            # Always ensure tenant_id parameter is bound first
            exec_params = [tenant_id] + list(params or [])
            cursor = conn.execute(sql_clean, exec_params)
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

        if not table or table not in ALLOWED_TABLES:
            raise ValueError(f"Table '{table}' is not in allowed tables: {sorted(ALLOWED_TABLES)}")

        cols = ", ".join(columns) if columns else "*"

        if table == "recommendations":
            query_parts = [f"SELECT recommendations.* FROM recommendations JOIN incidents ON recommendations.incident_id = incidents.id WHERE incidents.tenant_id = ?"]
            exec_params: List[Any] = [tenant_id]
        elif table == "incident_events":
            query_parts = [f"SELECT incident_events.* FROM incident_events JOIN incidents ON incident_events.incident_id = incidents.id WHERE incidents.tenant_id = ?"]
            exec_params = [tenant_id]
        else:
            tenant_column = "id" if table == "tenants" else "tenant_id"
            query_parts = [f"SELECT {cols} FROM {table} WHERE {tenant_column} = ?"]
            exec_params = [tenant_id]

        if where_clause:
            query_parts.append(f"AND ({where_clause})")
            if params:
                exec_params.extend(params)

        if order_by:
            query_parts.append(f"ORDER BY {order_by}")

        if limit is not None:
            query_parts.append(f"LIMIT {int(limit)}")

        sql = " ".join(query_parts)
        cursor = conn.execute(sql, exec_params)
        rows = cursor.fetchall()
        return [dict(r) for r in rows]

    finally:
        conn.close()
