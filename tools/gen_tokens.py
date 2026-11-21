"""
tools/gen_tokens.py
───────────────────
Generates cryptographically random viewer tokens per tenant using secrets.token_urlsafe(32).
Writes the plaintext tokens to the local uncommitted .env file.
The SaaS backend never stores or compares these plaintext tokens directly;
it stores and compares only their SHA-256 hashes via hmac.compare_digest.
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path
from typing import Dict

TENANTS = ["acme", "globex"]


def generate_tokens() -> Dict[str, str]:
    """Generates random secure URL-safe tokens (32 bytes entropy) for configured tenants."""
    return {tenant: secrets.token_urlsafe(32) for tenant in TENANTS}


def update_env_file(tokens: Dict[str, str], env_path: Path) -> None:
    """Writes or updates token environment variables in the local .env file."""
    lines: list[str] = []
    if env_path.exists():
        lines = env_path.read_text(encoding="utf-8").splitlines()

    new_lines: list[str] = []
    existing_keys: set[str] = set()

    for line in lines:
        stripped = line.strip()
        if stripped.startswith("VIEWER_TOKEN_") and "=" in stripped:
            key = stripped.split("=")[0].strip()
            existing_keys.add(key)
            tenant = key.replace("VIEWER_TOKEN_", "").lower()
            if tenant in tokens:
                new_lines.append(f"{key}={tokens[tenant]}")
            else:
                new_lines.append(line)
        else:
            new_lines.append(line)

    for tenant, token in tokens.items():
        key = f"VIEWER_TOKEN_{tenant.upper()}"
        if key not in existing_keys:
            new_lines.append(f"{key}={token}")

    env_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")


def main() -> None:
    env_path = Path(__file__).resolve().parent.parent / ".env"
    tokens = generate_tokens()
    update_env_file(tokens, env_path)
    print("Generated random tenant viewer tokens successfully:")
    for t, tok in tokens.items():
        print(f"  {t} -> VIEWER_TOKEN_{t.upper()}={tok}")
    print(f"\nPersisted plaintext tokens to local uncommitted {env_path.name}")


if __name__ == "__main__":
    main()
