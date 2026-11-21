"""
saas/validate.py
────────────────
Server-Side Payload Validation Gate.

Hard Rule 1: Allow-list only.
Re-validates incoming payload against contracts/allow-list.yaml on the SERVER side.
Rejects any unknown fields (e.g. extra "password" field), bad types,
over-length strings, or strings tripping the secret scanner with HTTP 400
and creates an audit log entry.
"""

from __future__ import annotations

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import yaml

from saas.audit import record_audit_log

logger = logging.getLogger(__name__)

_POLICY_FILE = Path(__file__).resolve().parent.parent / "contracts" / "allow-list.yaml"


def load_allow_list() -> dict:
    if not _POLICY_FILE.exists():
        raise FileNotFoundError(f"Policy file not found: {_POLICY_FILE}")
    with open(_POLICY_FILE, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


_SPEC = load_allow_list()
_ALLOWED_FIELDS: Dict[str, Any] = _SPEC.get("allowed_fields", {})
_SECRET_PATTERNS: List[re.Pattern] = [
    re.compile(p, re.IGNORECASE) for p in _SPEC.get("secret_patterns", [])
]


def validate_payload(
    payload: Dict[str, Any],
    tenant_id: str,
    collector_id: str = "unknown",
) -> Tuple[bool, Optional[str]]:
    """
    Validates a single payload against server-side allow-list criteria:
    - No unknown fields allowed (any unrecognized key immediately triggers rejection).
    - payload_id is required.
    - Present fields are verified for type, enum, pattern, and max length.
    - Secret scanner check on every string value.

    Returns:
        (True, None) if valid.
        (False, error_reason) if invalid (records audit log on failure).
    """
    payload_id = str(payload.get("payload_id", "unknown"))

    # 1. Reject unknown fields
    for key in payload.keys():
        if key not in _ALLOWED_FIELDS:
            clean_key = "[REDACTED]" if scan_string_for_secrets(key) else key
            reason = f"Rejected unknown field '{clean_key}' not permitted by allow-list"
            _log_validation_failure(tenant_id, collector_id, payload_id, reason)
            return False, reason

    # 2. Check essential required field payload_id
    if "payload_id" not in payload or not payload["payload_id"]:
        reason = "Missing required allow-listed field: 'payload_id'"
        _log_validation_failure(tenant_id, collector_id, payload_id, reason)
        return False, reason

    # 3. Validate types, enums, regexes, lengths, and scan secrets
    for field_name, val in payload.items():
        rules = _ALLOWED_FIELDS.get(field_name, {})
        ftype = rules.get("type")

        if val is None:
            continue

        # Type checking
        if ftype == "string":
            if not isinstance(val, str):
                reason = f"Field '{field_name}' must be a string, got {type(val).__name__}"
                _log_validation_failure(tenant_id, collector_id, payload_id, reason)
                return False, reason

            # Max length
            max_len = rules.get("max_len")
            if max_len and len(val) > max_len:
                reason = f"Field '{field_name}' exceeds maximum allowed length of {max_len} (got {len(val)})"
                _log_validation_failure(tenant_id, collector_id, payload_id, reason)
                return False, reason

            # Pattern
            pat = rules.get("pattern")
            if pat and not re.match(pat, val):
                reason = f"Field '{field_name}' failed pattern validation"
                _log_validation_failure(tenant_id, collector_id, payload_id, reason)
                return False, reason

            # Secret scanning
            scanner_hit = scan_string_for_secrets(val)
            if scanner_hit:
                reason = f"Field '{field_name}' tripped secret scanner pattern"
                _log_validation_failure(tenant_id, collector_id, payload_id, reason)
                return False, reason

        elif ftype == "int":
            if not isinstance(val, int) or isinstance(val, bool):
                reason = f"Field '{field_name}' must be an integer, got {type(val).__name__}"
                _log_validation_failure(tenant_id, collector_id, payload_id, reason)
                return False, reason
            allowed_vals = rules.get("allowed_values")
            if allowed_vals and val not in allowed_vals:
                reason = f"Field '{field_name}' value not in allowed set {allowed_vals}"
                _log_validation_failure(tenant_id, collector_id, payload_id, reason)
                return False, reason

        elif ftype == "number":
            if not isinstance(val, (int, float)) or isinstance(val, bool):
                reason = f"Field '{field_name}' must be a number, got {type(val).__name__}"
                _log_validation_failure(tenant_id, collector_id, payload_id, reason)
                return False, reason

        elif ftype == "enum":
            allowed = rules.get("values", [])
            if str(val) not in allowed:
                reason = f"Field '{field_name}' value not in allowed enum values: {allowed}"
                _log_validation_failure(tenant_id, collector_id, payload_id, reason)
                return False, reason

        elif ftype == "iso8601_utc":
            if not isinstance(val, str) or not (val.endswith("Z") or "+00:00" in val):
                reason = f"Field '{field_name}' must be an ISO-8601 UTC timestamp ending in Z or +00:00"
                _log_validation_failure(tenant_id, collector_id, payload_id, reason)
                return False, reason

            scanner_hit = scan_string_for_secrets(val)
            if scanner_hit:
                reason = f"Field '{field_name}' tripped secret scanner pattern"
                _log_validation_failure(tenant_id, collector_id, payload_id, reason)
                return False, reason

    return True, None


def scan_string_for_secrets(text: str) -> Optional[str]:
    """Scans text against all configured secret patterns. Returns pattern string if matched."""
    for pattern in _SECRET_PATTERNS:
        if pattern.search(text):
            return pattern.pattern
    return None


def _log_validation_failure(tenant_id: str, actor: str, payload_id: str, reason: str) -> None:
    logger.warning("Validation failure for tenant=%s collector=%s payload=%s", tenant_id, actor, payload_id)
    try:
        record_audit_log(
            tenant_id=tenant_id,
            actor=actor,
            action="VALIDATION_FAILED",
            detail={"payload_id": payload_id, "reason": reason},
        )
    except Exception as exc:
        logger.error("Failed to write audit log for validation failure: %s", type(exc).__name__)
