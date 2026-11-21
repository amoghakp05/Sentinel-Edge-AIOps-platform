"""
collector/redact.py
───────────────────
Redaction engine for scrubbing sensitive strings from raw telemetry.

Features:
- Regex scrubbers for passwords, bearer/JWT tokens, API keys (AWS AKIA..., generic 32+ char hex/b64),
  private keys, emails, IPv4/IPv6, credit-card-like numbers, usernames in auth lines, and URI credentials.
- Shannon entropy calculator to catch unknown high-entropy tokens/secrets.
- Replaces matches with typed placeholders: [REDACTED:token], [REDACTED:password], [REDACTED:api_key], etc.
- Return both cleaned text and a list of detected categories (categories only, never values).
"""

from __future__ import annotations

import math
import re
from typing import List, Set, Tuple

# ── Regex Patterns ────────────────────────────────────────────────────────────

# 1. Private keys
_RE_PRIVATE_KEY = re.compile(
    r"-----BEGIN [A-Z\s]+ PRIVATE KEY-----[\s\S]*?-----END [A-Z\s]+ PRIVATE KEY-----"
    r"|-----BEGIN RSA PRIVATE KEY-----[\s\S]*?-----END RSA PRIVATE KEY-----"
    r"|-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----",
    re.IGNORECASE,
)

# 2. URI credentials: proto://user:password@host
_RE_URI_CREDENTIALS = re.compile(
    r"""([a-zA-Z][a-zA-Z0-9+.-]*://)([^:\s/@]+):([^@\s/]+)@"""
)

# 3. Passwords (with or without quotes around key and value, spacing, brackets)
_RE_PASSWORD = re.compile(
    r"""(?:['"]?(?:password|passwd|pwd|secret)['"]?)\s*[:=]\s*(?:"([^"]+)"|'([^']+)'|([^\s'",;\]]+))""",
    re.IGNORECASE,
)

# 4. Bearer and JWT tokens: Bearer ..., eyJ...
_RE_JWT_BEARER = re.compile(
    r"""\bBearer\s+([A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_=]*)"""
    r"""|\b(eyJ[A-Za-z0-9\-_]{10,}\.eyJ[A-Za-z0-9\-_]{10,}\.[A-Za-z0-9\-_]{10,})\b""",
    re.IGNORECASE,
)

# 5. AWS Access Keys: AKIA..., ASIA...
_RE_AWS_KEY = re.compile(r"\b((?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16})\b")

# 6. Generic 32+ character hex tokens / API keys (e.g. md5/sha256 tokens)
_RE_HEX_API_KEY = re.compile(r"\b[0-9a-fA-F]{32,64}\b")

# 7. Generic API keys in key-value contexts: api_key=..., client_secret=...
_RE_KEY_VALUE = re.compile(
    r"""(?:['"]?(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|token)['"]?)\s*[:=]\s*(?:"([^"]+)"|'([^']+)'|([^\s'",;\]]+))""",
    re.IGNORECASE,
)

# 8. Emails
_RE_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b"
)

# 9. Credit-card-like numbers (13 to 19 digits, optionally separated by spaces or dashes)
_RE_CREDIT_CARD = re.compile(
    r"\b(?:\d{4}[-\s]?){3}\d{4}\b|\b\d{15,16}\b"
)

# 10. Usernames in authentication lines
_RE_AUTH_USER = re.compile(
    r"""\b(?:user|username|login)\s*[:=]\s*(['"]?)([A-Za-z0-9_.-]+)\1"""
    r"""|for\s+(?:invalid\s+user\s+)?([A-Za-z0-9_.-]+)\s+from""",
    re.IGNORECASE,
)

# 11. IPv4 Addresses
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# 12. IPv6 Addresses
_RE_IPV6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b"
    r"|\b(?:[0-9a-fA-F]{1,4}:)*::(?:[0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}\b"
)


# ── Shannon Entropy ───────────────────────────────────────────────────────────

def shannon_entropy(s: str) -> float:
    """Calculates the Shannon entropy of a string."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


# ── Main Redaction Engine ─────────────────────────────────────────────────────

def redact_text(text: str) -> Tuple[str, List[str]]:
    """
    Scrub sensitive patterns from *text* and replace them with typed placeholders.

    Returns:
        (cleaned_text, list_of_detected_categories)
    """
    if not text:
        return text, []

    categories: Set[str] = set()
    cleaned = text

    # 1. Private keys
    if _RE_PRIVATE_KEY.search(cleaned):
        cleaned = _RE_PRIVATE_KEY.sub("[REDACTED:private_key]", cleaned)
        categories.add("private_key")

    # 2. URI credentials: proto://user:password@host -> proto://[REDACTED:credentials]@host
    def _sub_uri(m: re.Match) -> str:
        categories.add("username")
        categories.add("password")
        return f"{m.group(1)}[REDACTED:credentials]@"
    cleaned = _RE_URI_CREDENTIALS.sub(_sub_uri, cleaned)

    # 3. JWT / Bearer
    def _sub_jwt(m: re.Match) -> str:
        categories.add("token")
        return "[REDACTED:token]"
    cleaned = _RE_JWT_BEARER.sub(_sub_jwt, cleaned)

    # 4. AWS keys
    def _sub_aws(m: re.Match) -> str:
        categories.add("api_key")
        return "[REDACTED:api_key]"
    cleaned = _RE_AWS_KEY.sub(_sub_aws, cleaned)

    # 5. Passwords (replaces whole match with typed placeholder)
    def _sub_password(m: re.Match) -> str:
        categories.add("password")
        return "[REDACTED:password]"
    cleaned = _RE_PASSWORD.sub(_sub_password, cleaned)

    # 6. Key-value API tokens (replaces whole match with typed placeholder)
    def _sub_kv(m: re.Match) -> str:
        key_name = m.group(0).lower()
        if "token" in key_name:
            categories.add("token")
            return "[REDACTED:token]"
        categories.add("api_key")
        return "[REDACTED:api_key]"
    cleaned = _RE_KEY_VALUE.sub(_sub_kv, cleaned)

    # 7. Credit-card-like numbers
    def _sub_cc(m: re.Match) -> str:
        categories.add("credit_card")
        return "[REDACTED:credit_card]"
    cleaned = _RE_CREDIT_CARD.sub(_sub_cc, cleaned)

    # 8. Emails
    def _sub_email(m: re.Match) -> str:
        categories.add("email")
        return "[REDACTED:email]"
    cleaned = _RE_EMAIL.sub(_sub_email, cleaned)

    # 9. Usernames in auth lines
    def _sub_user(m: re.Match) -> str:
        user = m.group(2) or m.group(3)
        if user and user.lower() not in {"unknown", "none", "system", "invalid", "[redacted:username]"}:
            categories.add("username")
            return m.group(0).replace(user, "[REDACTED:username]")
        return m.group(0)
    cleaned = _RE_AUTH_USER.sub(_sub_user, cleaned)

    # 10. IPv4 Addresses (ignoring numbers already inside brackets)
    def _sub_ipv4(m: re.Match) -> str:
        categories.add("ipv4")
        return "[REDACTED:ipv4]"
    cleaned = _RE_IPV4.sub(_sub_ipv4, cleaned)

    # 11. IPv6 Addresses
    def _sub_ipv6(m: re.Match) -> str:
        categories.add("ipv6")
        return "[REDACTED:ipv6]"
    cleaned = _RE_IPV6.sub(_sub_ipv6, cleaned)

    # 12. Generic 32+ hex tokens
    def _sub_hex(m: re.Match) -> str:
        categories.add("api_key")
        return "[REDACTED:api_key]"
    cleaned = _RE_HEX_API_KEY.sub(_sub_hex, cleaned)

    # 13. High-Entropy Tokens (Words >= 18 chars with entropy > 3.8)
    def _sub_entropy(m: re.Match) -> str:
        word = m.group(0)
        if word.startswith("[REDACTED:"):
            return word
        if len(word) >= 18 and shannon_entropy(word) > 3.8:
            categories.add("entropy")
            return "[REDACTED:token]"
        return word

    cleaned = re.sub(r"\b[A-Za-z0-9+/=_\-]{18,}\b", _sub_entropy, cleaned)

    return cleaned, sorted(list(categories))
