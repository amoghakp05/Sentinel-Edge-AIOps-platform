"""
collector/db.py
───────────────
SQLite connection factory for the local collector database.

Design decisions
────────────────
- WAL mode is set on every new connection (D-003).
- Thread-local connections avoid sharing a single connection across threads
  (SQLite restriction in WAL mode with concurrent writers).
- Schema is applied from contracts/db_collector.sql if tables are missing.
- Module-level ``get_db()`` is the ONLY place we open connections; all other
  modules import from here.
"""

from __future__ import annotations

import os
import sqlite3
import threading
from pathlib import Path

# ── Configuration ─────────────────────────────────────────────────────────────

# Path to the SQL DDL file (resolved relative to this file's project root).
_HERE = Path(__file__).parent
_PROJECT_ROOT = _HERE.parent
_DDL_PATH = _PROJECT_ROOT / "contracts" / "db_collector.sql"

# Default DB path; overridden by the COLLECTOR_DB_PATH env var.
_DEFAULT_DB_PATH = "collector_local.db"

# Thread-local storage for per-thread connections.
_local = threading.local()


def _db_path() -> str:
    return os.environ.get("COLLECTOR_DB_PATH", _DEFAULT_DB_PATH)


def _apply_schema(conn: sqlite3.Connection) -> None:
    """
    Apply the collector schema DDL if tables are missing.
    Safe to call on every new connection (all statements use IF NOT EXISTS).
    """
    if not _DDL_PATH.exists():
        raise FileNotFoundError(
            f"Schema file not found: {_DDL_PATH}\n"
            "Run from the aiops-platform project root."
        )
    ddl = _DDL_PATH.read_text(encoding="utf-8")
    conn.executescript(ddl)


def get_db() -> sqlite3.Connection:
    """
    Return (or create) a thread-local SQLite connection in WAL mode.

    The returned connection has:
      - WAL journal mode
      - Foreign key enforcement
      - Row factory set to sqlite3.Row (column-name access)
      - Schema applied if first open in this process
    """
    path = _db_path()

    if not hasattr(_local, "conn") or _local.conn is None:
        conn = sqlite3.connect(path, check_same_thread=False)
        conn.row_factory = sqlite3.Row

        # Ensure WAL mode and FK enforcement on every new connection.
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        conn.commit()

        # Apply schema (idempotent: IF NOT EXISTS guards all DDL).
        _apply_schema(conn)
        conn.commit()

        _local.conn = conn

    return _local.conn


def close_db() -> None:
    """Close the thread-local connection if open."""
    conn: sqlite3.Connection | None = getattr(_local, "conn", None)
    if conn is not None:
        conn.close()
        _local.conn = None


def reset_for_testing(path: str) -> None:
    """
    Force a fresh connection to a specific path.
    Use ONLY in tests (sets COLLECTOR_DB_PATH and closes any open connection).
    """
    os.environ["COLLECTOR_DB_PATH"] = path
    close_db()
