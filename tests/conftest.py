"""
tests/conftest.py
──────────────────
Shared pytest fixtures for Phase 1.
"""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

import pytest

from collector.db import reset_for_testing, close_db


@pytest.fixture()
def tmp_db(tmp_path: Path):
    """
    Provide a fresh, isolated SQLite database for each test.

    Sets COLLECTOR_DB_PATH and resets the thread-local connection so every
    test gets a clean slate without touching the real collector_local.db.
    """
    db_file = str(tmp_path / "test_collector.db")
    reset_for_testing(db_file)
    yield db_file
    # Teardown: close connection so the temp file can be deleted on Windows.
    close_db()
