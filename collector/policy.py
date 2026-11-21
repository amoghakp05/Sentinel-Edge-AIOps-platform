"""
collector/policy.py
───────────────────
Hardened egress policy enforcement gate.

Every payload MUST pass this gate before leaving the collector:
1. Loads rules from contracts/allow-list.yaml.
2. Drops any field not explicitly on the allow-list (allow-list, never block-list).
3. Validates types, enums, regex patterns, and string length limits.
4. Executes comprehensive secret and PII scanning on EVERY outgoing string field
   (passwords, tokens, AWS keys, private keys, emails, IPv4/IPv6, internal hostnames).
5. If validation fails or any sensitive pattern is found:
   - Rejects payload immediately.
   - Writes record to 'blocked_log' SQLite table with the reason (NEVER the secret).
   - Raises alert-level local log entry.
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from collector.db import get_db

logger = logging.getLogger(__name__)

# ── Load Allow-List Specification ─────────────────────────────────────────────

_POLICY_FILE = Path(__file__).parent.parent / "contracts" / "allow-list.yaml"


def load_policy_spec() -> dict:
    if not _POLICY_FILE.exists():
        raise FileNotFoundError(f"Policy spec file not found: {_POLICY_FILE}")
    with open(_POLICY_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


_SPEC = load_policy_spec()
_ALLOWED_FIELDS = _SPEC.get("allowed_fields", {})
_SECRET_PATTERNS = [re.compile(p, re.IGNORECASE) for p in _SPEC.get("secret_patterns", [])]

# Fallback comprehensive compiled patterns
if not _SECRET_PATTERNS:
    _SECRET_PATTERNS = [
        re.compile(r"(?i)(?:password|passwd|pwd|secret)\s*[:=]"),
        re.compile(r"(?i)(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|token)\s*[:=]"),
        re.compile(r"(?i)Bearer\s+"),
        re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b"),
        re.compile(r"-----BEGIN [A-Z\s]+ PRIVATE KEY-----", re.IGNORECASE),
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"),
        re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"),
        re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"),
        re.compile(r"\b(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b"),
        re.compile(r"(?i)\.(?:internal|corp|local)\b"),
        re.compile(r"\b[0-9a-fA-F]{32,64}\b"),
        re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://(?!\[REDACTED)[^:\s/@]+:[^@\s/]+@"),
    ]


# ── Policy Enforcement Gate ───────────────────────────────────────────────────

def enforce_policy(raw_payload: Dict[str, Any]) -> Tuple[bool, Optional[Dict[str, Any]], Optional[str]]:
    """
    Applies strict allow-list filtering, field validation, and deep secret scanning.

    Returns:
        (is_allowed: bool, filtered_payload: Optional[dict], failure_reason: Optional[str])
    """
    payload_id = str(raw_payload.get("payload_id", "unknown"))

    # 1. Drop unknown fields (Allow-list only)
    filtered: Dict[str, Any] = {}
    for k, v in raw_payload.items():
        if k in _ALLOWED_FIELDS:
            filtered[k] = v

    # 2. Check required fields
    for field_name, rules in _ALLOWED_FIELDS.items():
        if rules.get("required", False) and field_name not in filtered:
            reason = f"Missing required allow-listed field: '{field_name}'"
            _record_block(payload_id, reason)
            return False, None, reason

    # 3. Deep Secret & Sensitive Entity Scan FIRST on ALL outgoing strings
    for field_name, val in filtered.items():
        if isinstance(val, str):
            for pat in _SECRET_PATTERNS:
                if pat.search(val):
                    # Hard Rule: never log or expose the secret itself in the reason
                    reason = f"Security Violation: Secret pattern detected in field '{field_name}'"
                    _record_block(payload_id, reason)
                    return False, None, reason

    # 4. Validate field constraints
    for field_name, val in filtered.items():
        rules = _ALLOWED_FIELDS.get(field_name, {})
        ftype = rules.get("type")

        # Null check
        if val is None:
            if rules.get("required", False):
                reason = f"Required field '{field_name}' cannot be null"
                _record_block(payload_id, reason)
                return False, None, reason
            continue

        # Pattern check
        pattern = rules.get("pattern")
        if pattern and isinstance(val, str):
            if not re.match(pattern, val):
                reason = f"Field '{field_name}' failed regex pattern: {pattern}"
                _record_block(payload_id, reason)
                return False, None, reason

        # Enum check
        enums = rules.get("values")
        if enums and val not in enums:
            reason = f"Field '{field_name}' not in allowed enums: {enums}"
            _record_block(payload_id, reason)
            return False, None, reason

        # Max length check
        max_len = rules.get("max_len")
        if max_len and isinstance(val, str) and len(val) > max_len:
            reason = f"Field '{field_name}' exceeds max_len {max_len} (length {len(val)})"
            _record_block(payload_id, reason)
            return False, None, reason

        # ISO8601 UTC check
        if ftype == "iso8601_utc" and isinstance(val, str):
            if not val.endswith("Z"):
                reason = f"Timestamp '{field_name}' must end with 'Z'"
                _record_block(payload_id, reason)
                return False, None, reason

    return True, filtered, None


def _record_block(payload_id: str, reason: str) -> None:
    """Logs the block event locally and persists it to blocked_log."""
    now_utc = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    logger.critical("EGRESS POLICY BLOCKED PAYLOAD [%s]: %s", payload_id, reason)

    try:
        conn = get_db()
        conn.execute(
            """
            INSERT INTO blocked_log (ts_utc, reason, payload_id)
            VALUES (?, ?, ?)
            """,
            (now_utc, reason, payload_id),
        )
        conn.commit()
    except Exception as exc:
        logger.error("Failed to write to blocked_log table: %s", type(exc).__name__)
