"""
collector/pseudonym.py
──────────────────────
Pseudonymisation service for mapping real hostnames / IP addresses
to pseudonymous references: ^h_[0-9a-f]{8}$

Contract:
  source_ref = "h_" + first 8 hex of HMAC-SHA256(TENANT_SECRET, real_host_or_ip)
  The reverse mapping is stored ONLY in the local SQLite table 'source_mapping'.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime, timezone
from typing import Optional

from collector.db import get_db

# Default secret if not set in environment (dev only)
DEFAULT_HMAC_SECRET = "sentinel-edge-default-dev-secret-cicada2026"


def compute_source_ref(real_source: str, secret: Optional[str] = None) -> str:
    """
    Computes the deterministic pseudonym: "h_" + 8 hex digits.
    """
    if secret is None:
        secret = os.environ.get("HMAC_SECRET", DEFAULT_HMAC_SECRET)

    digest = hmac.new(
        secret.encode("utf-8"),
        real_source.strip().encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()

    return f"h_{digest[:8]}"


def get_or_create_source_ref(real_source: str, secret: Optional[str] = None) -> str:
    """
    Computes source_ref, records the reverse mapping into the local
    'source_mapping' table, and returns the pseudonymous reference.
    """
    ref = compute_source_ref(real_source, secret)
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = get_db()
    conn.execute(
        """
        INSERT INTO source_mapping (real_source, source_ref, created_at)
        VALUES (?, ?, ?)
        ON CONFLICT(real_source) DO NOTHING
        """,
        (real_source.strip(), ref, now_utc),
    )
    conn.commit()

    return ref


def lookup_real_source(source_ref: str) -> Optional[str]:
    """
    Locally look up the real host or IP from a source_ref.
    Available ONLY within the local collector tier (for debugging/operator inspection).
    """
    conn = get_db()
    row = conn.execute(
        "SELECT real_source FROM source_mapping WHERE source_ref = ?",
        (source_ref,),
    ).fetchone()

    return row["real_source"] if row else None
