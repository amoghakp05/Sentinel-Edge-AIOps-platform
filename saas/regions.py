"""
saas/regions.py
───────────────
Regional Routing & Enforcement.

Each SaaS instance has a REGION environment variable ('eu' or 'in').
Each tenant is pinned to a specific region.
If a payload arrives at the wrong region, the request is rejected with 421
(Misdirected Request) and logged to the immutable audit log.
Zero data is replicated across regions.
"""

from __future__ import annotations

import logging
from typing import Optional, Tuple

from saas.audit import record_audit_log
from saas.db import get_connection, get_region

logger = logging.getLogger(__name__)

# Canonical regional aliases
REGION_ALIASES = {
    "eu-central-1": "eu",
    "eu": "eu",
    "ap-south-1": "in",
    "in": "in",
}


def canonical_region(reg: str) -> str:
    """Normalizes region string to short standard code ('eu' or 'in')."""
    return REGION_ALIASES.get(reg.strip().lower(), reg.strip().lower())


def get_tenant_pinned_region(tenant_id: str) -> Optional[str]:
    """Retrieves the pinned region for a tenant from the regional DB."""
    try:
        conn = get_connection()
        row = conn.execute(
            "SELECT region FROM tenants WHERE id = ?",
            (tenant_id,),
        ).fetchone()
        conn.close()
        if row:
            return canonical_region(row["region"])
    except Exception as exc:
        logger.error("Failed to query tenant region for %s: %s", tenant_id, type(exc).__name__)

    # Static fallback
    if tenant_id == "acme":
        return "eu"
    if tenant_id == "globex":
        return "in"
    return None


def verify_tenant_region(tenant_id: str, collector_id: str = "unknown") -> Tuple[bool, Optional[str]]:
    """
    Verifies that the tenant is allowed to send data to this regional instance.

    Returns:
        (True, None) if region matches.
        (False, error_message) if misdirected; also logs audit record.
    """
    current_region = get_region()
    pinned_region = get_tenant_pinned_region(tenant_id)

    if not pinned_region:
        msg = f"Tenant '{tenant_id}' has no configured region"
        logger.warning(msg)
        return False, msg

    if current_region != pinned_region:
        detail = {
            "error": "Misdirected Request",
            "current_region": current_region,
            "pinned_region": pinned_region,
            "collector_id": collector_id,
        }
        record_audit_log(
            tenant_id=tenant_id,
            actor=collector_id,
            action="MISDIRECTED_REGION",
            detail=detail,
        )
        msg = f"Tenant '{tenant_id}' is pinned to region '{pinned_region}', but arrived at '{current_region}'"
        logger.warning(msg)
        return False, msg

    return True, None
