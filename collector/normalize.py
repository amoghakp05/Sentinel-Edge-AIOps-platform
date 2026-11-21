"""
collector/normalize.py
──────────────────────
Converts a RawRecord (from any input adapter) into a normalised Event,
then persists it to the local raw_events table.

Hard rules enforced here
─────────────────────────
- D-004: ALL datetimes are timezone-aware.  ``datetime.utcnow()`` is banned.
  We use ``datetime.now(timezone.utc)`` and dateutil.parser with tz fallback.
- D-006: ``event.source`` holds the REAL hostname/IP.  Pseudonymisation
  happens later in redact.py (Phase 2).
- The 'source' column in raw_events also stores the real value — intentional.

Nothing in this module sends or redacts data.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Optional

from dateutil import parser as dtparser
from dateutil.tz import gettz

from collector.db import get_db
from collector.models import Event, RawRecord
from collector.pseudonym import compute_source_ref

logger = logging.getLogger(__name__)


# ── Public API ────────────────────────────────────────────────────────────────

def normalize_and_store(record: RawRecord) -> Event:
    """
    Convert *record* to an Event and persist the raw data to SQLite.

    Returns the Event for the caller to pass downstream.
    Raises ValueError if the timestamp cannot be made timezone-aware.
    """
    event = _to_event(record)
    _store_raw(record, event)
    return event


# ── Normalisation logic ───────────────────────────────────────────────────────

def _to_event(record: RawRecord) -> Event:
    """Build a normalised Event from a RawRecord."""
    utc_str = _to_utc_z(record.ts)

    return Event(
        event_time_utc=utc_str,
        source_tz=record.source_tz,
        source=record.source,
        category=record.category,
        adapter=record.adapter,
        raw_text=record.raw_text,
        value=record.value,
        unit=record.unit,
    )


def _to_utc_z(dt: datetime) -> str:
    """
    Convert a timezone-aware datetime to an ISO-8601 UTC string ending in 'Z'.

    Raises ValueError if *dt* is naive (i.e. tzinfo is None).
    """
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        raise ValueError(
            f"Naive datetime passed to normalize; this is a bug in the adapter: {dt!r}"
        )
    utc = dt.astimezone(timezone.utc)
    # Format: 2026-11-20T10:00:05Z  (no microseconds to keep context short)
    return utc.strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Storage ───────────────────────────────────────────────────────────────────

def _store_raw(record: RawRecord, event: Event) -> None:
    """
    INSERT the raw record into raw_events.

    The row intentionally contains the real hostname/IP in ``source``.
    It never leaves this database (Hard Rule 1 / C5).
    """
    conn = get_db()
    conn.execute(
        """
        INSERT INTO raw_events
            (received_at, source, source_tz, category, value, unit, raw_text, adapter)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            event.event_time_utc,  # received_at = event time (closest we have)
            record.source,
            record.source_tz,
            record.category,
            record.value,
            record.unit,
            record.raw_text,
            record.adapter,
        ),
    )
    conn.commit()
    source_ref = compute_source_ref(record.source)
    logger.debug(
        "Stored raw_event: adapter=%s category=%s source_ref=%s",
        record.adapter,
        record.category,
        source_ref,
    )


# ── Utility: parse a timestamp string with tz awareness ───────────────────────

def parse_aware_datetime(
    ts_str: str,
    fallback_tz: Optional[str] = None,
) -> datetime:
    """
    Parse *ts_str* into a timezone-aware datetime.

    Parameters
    ----------
    ts_str      : Timestamp string in any common format.
    fallback_tz : IANA timezone name used if *ts_str* has no tz info.
                  If None and the string is naive, raises ValueError.

    Raises
    ------
    ValueError  : If the string cannot be parsed or is naive with no fallback.
    """
    try:
        dt = dtparser.parse(ts_str)
    except (ValueError, OverflowError) as exc:
        raise ValueError(f"Cannot parse timestamp {ts_str!r}: {exc}") from exc

    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        # Naive datetime: apply fallback tz if provided.
        if fallback_tz is None:
            raise ValueError(
                f"Timestamp {ts_str!r} has no timezone info and no fallback_tz given."
            )
        tz_obj = gettz(fallback_tz)
        if tz_obj is None:
            raise ValueError(f"Unknown IANA timezone: {fallback_tz!r}")
        dt = dt.replace(tzinfo=tz_obj)

    return dt
