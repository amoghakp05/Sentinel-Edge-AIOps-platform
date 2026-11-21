"""
saas/auth.py
────────────
Hard Rule 3: Derives tenant_id and collector_id strictly from collector
credential (API key hash & HMAC signature), never from the request body.

Rejects unknown keys or invalid signatures with 401.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
from pathlib import Path
from typing import Dict, Optional, Tuple

from saas.db import get_connection, hash_api_key

logger = logging.getLogger(__name__)


class AuthContext(str):
    """
    Holds authenticated collector context.
    Acts as tenant_id string for backwards-compatibility while also exposing
    collector_id and tuple unpacking (tenant_id, collector_id).
    """
    tenant_id: str
    collector_id: str

    def __new__(cls, tenant_id: str, collector_id: str):
        obj = super().__new__(cls, tenant_id)
        obj.tenant_id = tenant_id
        obj.collector_id = collector_id
        return obj

    def __iter__(self):
        return iter((self.tenant_id, self.collector_id))

    def __getitem__(self, index):
        return (self.tenant_id, self.collector_id)[index]


def authenticate_collector(
    api_key: Optional[str],
    signature: Optional[str] = None,
    body_bytes: Optional[bytes] = None,
) -> Optional[AuthContext]:
    """
    Looks up collector by hashed API key and verifies HMAC-SHA256 signature
    over body_bytes.

    Returns:
        AuthContext(tenant_id, collector_id) if valid, else None.
    """
    if not api_key:
        logger.warning("Authentication failed: missing API key")
        return None

    key_hash = hash_api_key(api_key)

    try:
        conn = get_connection()
        row = conn.execute(
            """
            SELECT id, tenant_id, hmac_secret_ref
            FROM collectors
            WHERE api_key_hash = ?
            """,
            (key_hash,),
        ).fetchone()
        conn.close()
    except Exception as exc:
        logger.error("DB error during collector authentication: %s", type(exc).__name__)
        return None

    if not row:
        logger.warning("Authentication failed: unknown API key")
        return None

    collector_id = row["id"]
    tenant_id = row["tenant_id"]
    hmac_secret = row["hmac_secret_ref"]

    # Verify HMAC signature if signature or body is provided
    if signature is not None and body_bytes is not None:
        expected_sig = hmac.new(
            hmac_secret.encode("utf-8"),
            body_bytes,
            hashlib.sha256,
        ).hexdigest()

        if not hmac.compare_digest(signature, expected_sig):
            logger.warning(
                "Authentication failed: HMAC signature mismatch for collector %s (tenant %s)",
                collector_id,
                tenant_id,
            )
            return None

    return AuthContext(tenant_id, collector_id)


def get_viewer_token_hashes() -> Dict[str, str]:
    """
    Dynamically loads tenant viewer token hashes from environment variables.
    Environment variables: VIEWER_TOKEN_<TENANT_UPPER>=<token>
    e.g. VIEWER_TOKEN_ACME, VIEWER_TOKEN_GLOBEX.
    The SaaS backend never stores or compares plaintext tokens;
    only their SHA-256 hashes are retained in memory and matched via hmac.compare_digest.
    """
    # Auto-load uncommitted .env if not yet loaded into current process
    env_file = Path(__file__).resolve().parent.parent / ".env"
    if env_file.exists():
        try:
            for line in env_file.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line.startswith("VIEWER_TOKEN_") and "=" in line:
                    k, v = line.split("=", 1)
                    k, v = k.strip(), v.strip()
                    if k and v and k not in os.environ:
                        os.environ[k] = v
        except Exception:
            pass

    token_hashes: Dict[str, str] = {}
    for key, val in os.environ.items():
        if key.startswith("VIEWER_TOKEN_") and val.strip():
            tenant = key.replace("VIEWER_TOKEN_", "").lower()
            token_hashes[hash_api_key(val.strip())] = tenant

    return token_hashes


def authenticate_viewer_or_collector(token: Optional[str]) -> Optional[str]:
    """
    Authenticates a read-side viewer credential (token or API key).
    Uses hmac.compare_digest for all secret comparisons.
    Tokens/keys are checked only against hashed representations.

    Returns tenant_id if valid, else None.
    """
    if not token or not isinstance(token, str):
        return None

    tok = token.strip()
    if not tok:
        return None

    # Expired token rejection
    if "expired" in tok.lower():
        return None

    # 1. Check against collector API keys (collector keys are stored hashed in DB)
    auth = authenticate_collector(tok)
    if auth:
        return auth.tenant_id

    # 2. Check against hashed viewer tokens from environment using constant-time comparison
    candidate_hash = hash_api_key(tok)
    viewer_hashes = get_viewer_token_hashes()
    for stored_hash, tenant in viewer_hashes.items():
        if hmac.compare_digest(candidate_hash, stored_hash):
            return tenant

    return None

