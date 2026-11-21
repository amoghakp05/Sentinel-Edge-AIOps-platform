"""
collector/retention.py
───────────────────────
Background retention job: deletes raw_events older than
RAW_RETENTION_HOURS (env var, default 24 h).

Design decisions (D-005)
─────────────────────────
- Runs as a daemon thread with a threading.Event stop-flag so the main
  process (CLI or daemon) can shut it down cleanly via stop().
- Uses DELETE with a LIMIT guard (500 rows per batch) to avoid holding a
  long write lock on the SQLite WAL file.
- Every deleted batch is logged at INFO so operators can verify local
  data-minimisation compliance without inspecting the DB.
- The job also returns a summary dict for testability (see run_once()).
"""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

from collector.db import get_db

logger = logging.getLogger(__name__)

# ── Configuration ─────────────────────────────────────────────────────────────

_DEFAULT_RETENTION_HOURS    = 24
_DEFAULT_INTERVAL_S         = 3600   # run once per hour
_BATCH_DELETE_LIMIT         = 500    # rows per DELETE to avoid long WAL locks


def _retention_hours() -> int:
    return int(os.environ.get("RAW_RETENTION_HOURS", _DEFAULT_RETENTION_HOURS))


def _interval_s() -> int:
    return int(os.environ.get("RETENTION_INTERVAL_S", _DEFAULT_INTERVAL_S))


# ── Public API ────────────────────────────────────────────────────────────────

class RetentionJob:
    """
    Background thread that periodically deletes old raw_events.

    Usage::

        job = RetentionJob()
        job.start()          # launches daemon thread
        ...
        job.stop()           # signals thread to exit cleanly
    """

    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the background retention thread (daemon=True)."""
        if self._thread and self._thread.is_alive():
            logger.warning("RetentionJob already running; ignoring start().")
            return

        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._run_loop,
            name="retention-job",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            "RetentionJob started: retention=%dh interval=%ds",
            _retention_hours(),
            _interval_s(),
        )

    def stop(self, timeout: float = 5.0) -> None:
        """Signal the thread to stop and wait up to *timeout* seconds."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)
        logger.info("RetentionJob stopped.")

    def _run_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                result = run_once()
                if result["deleted"] > 0:
                    logger.info(
                        "Retention run: deleted %d raw_events older than %dh (cutoff: %s)",
                        result["deleted"],
                        result["retention_hours"],
                        result["cutoff_utc"],
                    )
                else:
                    logger.debug("Retention run: nothing to delete.")
            except Exception as exc:
                logger.error("Retention job error: %s", type(exc).__name__)

            # Sleep in short increments so stop_event is checked promptly.
            interval = _interval_s()
            self._stop_event.wait(timeout=interval)


def run_once() -> dict:
    """
    Delete raw_events older than RAW_RETENTION_HOURS in batches.

    Returns a dict:
      { "deleted": int, "retention_hours": int, "cutoff_utc": str }

    This function is synchronous and safe to call from tests.
    """
    hours    = _retention_hours()
    cutoff   = datetime.now(timezone.utc) - timedelta(hours=hours)
    cutoff_s = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

    conn    = get_db()
    deleted = 0

    while True:
        cur = conn.execute(
            """
            DELETE FROM raw_events
            WHERE id IN (
                SELECT id FROM raw_events
                WHERE received_at < ?
                ORDER BY received_at ASC
                LIMIT ?
            )
            """,
            (cutoff_s, _BATCH_DELETE_LIMIT),
        )
        conn.commit()
        batch = cur.rowcount
        deleted += batch
        if batch < _BATCH_DELETE_LIMIT:
            break  # No more rows to delete.

    return {
        "deleted": deleted,
        "retention_hours": hours,
        "cutoff_utc": cutoff_s,
    }
