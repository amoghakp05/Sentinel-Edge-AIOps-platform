"""
saas/db.py
──────────
SaaS Regional Database Management.

Each SaaS instance operates its OWN isolated SQLite database based on the
REGION environment variable (e.g. saas_eu.db or saas_in.db).
Zero data is replicated across regions.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
import threading
from pathlib import Path
from typing import Optional

# Base directory for regional databases
SAAS_DB_DIR = Path(__file__).resolve().parent.parent

# Known collector seeds: (collector_id, tenant_id, raw_api_key, hmac_secret)
COLLECTOR_SEEDS = [
    ("col-acme-eu-1", "acme", "key-acme-eu1-dev", "secret-acme-eu1"),
    ("col-acme-eu-2", "acme", "key-acme-eu2-dev", "secret-acme-eu2"),
    ("col-globex-in-1", "globex", "key-globex-in1-dev", "secret-globex-in1"),
]

TENANT_SEEDS = [
    ("acme", "Acme Financial", "eu"),
    ("globex", "Globex Logistics", "in"),
]


def hash_api_key(api_key: str) -> str:
    """Computes SHA-256 hash of API key for secure at-rest storage."""
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()


def get_region() -> str:
    """Returns the current instance region ('eu' or 'in'). Default: 'eu'."""
    reg = os.environ.get("REGION", "eu").lower()
    if reg in ("eu-central-1", "eu"):
        return "eu"
    if reg in ("ap-south-1", "in"):
        return "in"
    return reg


def get_db_path(region: Optional[str] = None) -> Path:
    """Returns the database file path for the given or configured region."""
    if os.environ.get("SAAS_DB_PATH"):
        return Path(os.environ["SAAS_DB_PATH"])
    reg = region or get_region()
    return SAAS_DB_DIR / f"saas_{reg}.db"


_DB_INIT_LOCK = threading.Lock()
_INITIALIZED_DBS: set[str] = set()


def init_db(region: Optional[str] = None, conn: Optional[sqlite3.Connection] = None) -> None:
    """Applies contracts/db_saas.sql schema and seeds tenant/collector metadata."""
    schema_path = SAAS_DB_DIR / "contracts" / "db_saas.sql"
    if not schema_path.exists():
        raise FileNotFoundError(f"Schema not found at {schema_path}")

    with open(schema_path, "r", encoding="utf-8") as f:
        schema_sql = f.read()

    db_path = get_db_path(region)
    close_after = False
    if conn is None:
        conn = sqlite3.connect(str(db_path), timeout=30.0, check_same_thread=False)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.row_factory = sqlite3.Row
        close_after = True

    with conn:
        conn.executescript(schema_sql)

        # Seed tenants
        for t_id, t_name, t_reg in TENANT_SEEDS:
            conn.execute(
                """
                INSERT INTO tenants (id, name, region)
                VALUES (?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET name=excluded.name, region=excluded.region
                """,
                (t_id, t_name, t_reg),
            )

        # Seed collectors with hashed API keys
        for c_id, t_id, raw_key, hmac_sec in COLLECTOR_SEEDS:
            key_hash = hash_api_key(raw_key)
            conn.execute(
                """
                INSERT INTO collectors (id, tenant_id, api_key_hash, hmac_secret_ref, status)
                VALUES (?, ?, ?, ?, 'active')
                ON CONFLICT(id) DO UPDATE SET
                    tenant_id=excluded.tenant_id,
                    api_key_hash=excluded.api_key_hash,
                    hmac_secret_ref=excluded.hmac_secret_ref
                """,
                (c_id, t_id, key_hash, hmac_sec),
            )

        # Seed initial default thresholds per tenant from contracts/thresholds.yaml
        thresh_path = SAAS_DB_DIR / "contracts" / "thresholds.yaml"
        defaults = {}
        if thresh_path.exists():
            try:
                import yaml
                with open(thresh_path, "r", encoding="utf-8") as f:
                    cfg = yaml.safe_load(f)
                    defaults = cfg.get("defaults", {})
            except Exception:
                pass

        if not defaults:
            defaults = {
                "cpu": {"fair_at": 75.0, "poor_at": 92.0, "stale_fair_s": 30, "stale_poor_s": 60},
                "memory": {"fair_at": 85.0, "poor_at": 95.0, "stale_fair_s": 30, "stale_poor_s": 60},
                "disk": {"fair_at": 85.0, "poor_at": 95.0, "stale_fair_s": 120, "stale_poor_s": 300},
                "latency": {"fair_at": 150.0, "poor_at": 400.0, "stale_fair_s": 30, "stale_poor_s": 60},
                "packet_loss": {"fair_at": 2.0, "poor_at": 8.0, "stale_fair_s": 30, "stale_poor_s": 60},
                "bandwidth": {"fair_at": 10.0, "poor_at": 1.0, "stale_fair_s": 30, "stale_poor_s": 60},
                "auth": {"fair_at": 5.0, "poor_at": 20.0, "stale_fair_s": 60, "stale_poor_s": 300},
                "connectivity": {"fair_at": 1.0, "poor_at": 0.0, "stale_fair_s": 15, "stale_poor_s": 60},
                "service": {"fair_at": 1.0, "poor_at": 0.0, "stale_fair_s": 15, "stale_poor_s": 60},
            }

        for t_id, _, _ in TENANT_SEEDS:
            for cat, rules in defaults.items():
                fair = float(rules.get("fair_at", 75.0))
                poor = float(rules.get("poor_at", 90.0))
                sf = int(rules.get("stale_fair_s", 30))
                sp = int(rules.get("stale_poor_s", 60))
                conn.execute(
                    """
                    INSERT INTO thresholds (tenant_id, category, fair_at, poor_at, stale_fair_s, stale_poor_s)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(tenant_id, category) DO NOTHING
                    """,
                    (t_id, cat, fair, poor, sf, sp),
                )

    if close_after:
        conn.close()


def get_connection(region: Optional[str] = None) -> sqlite3.Connection:
    """Opens a SQLite connection with WAL mode and row factory, auto-initializing if needed."""
    db_path = get_db_path(region)
    path_str = str(db_path.resolve())

    with _DB_INIT_LOCK:
        if path_str not in _INITIALIZED_DBS:
            if not db_path.exists():
                init_db(region)
            else:
                c_test = sqlite3.connect(path_str, timeout=30.0)
                cur = c_test.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='collectors'")
                if not cur.fetchone():
                    c_test.close()
                    init_db(region)
                else:
                    c_test.close()
            _INITIALIZED_DBS.add(path_str)

    conn = sqlite3.connect(path_str, timeout=30.0, check_same_thread=False)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA foreign_keys=ON;")
    conn.row_factory = sqlite3.Row
    return conn
