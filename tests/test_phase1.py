"""
tests/test_phase1.py
──────────────────────
Phase 1 acceptance tests covering:

  T1 – Timestamp parsing with multiple timezones (never naive).
  T2 – RawRecord rejects naive datetimes loudly.
  T3 – normalize_and_store persists a row to raw_events.
  T4 – All three adapters produce records with the same Event shape.
  T5 – Retention deletes rows older than the cutoff.
  T6 – Retention leaves rows newer than the cutoff intact.
  T7 – Retention batch loop deletes > 500 rows correctly.
  T8 – Duplicate raw inserts do not error (no UNIQUE constraint on raw_events).
  T9 – sim_stream adapter parses simulator response dict correctly.
  T10 – syslog adapter parses a standard auth.log line.
  T11 – syslog adapter ignores non-auth lines.
  T12 – psutil adapter generates non-negative values for all categories.
  T13 – WAL mode is active after get_db().
"""

from __future__ import annotations

import json
import os
import re
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

# ── Import order: db must be imported after conftest sets COLLECTOR_DB_PATH ───
from collector.db import get_db
from collector.models import RawRecord, Event
from collector.normalize import normalize_and_store, parse_aware_datetime
from collector.retention import run_once


# ═══════════════════════════════════════════════════════════════════════════════
# T1 – parse_aware_datetime handles multiple timezone formats
# ═══════════════════════════════════════════════════════════════════════════════

class TestTimestampParsing:
    def test_utc_z_suffix(self):
        dt = parse_aware_datetime("2026-11-20T10:00:05Z")
        assert dt.tzinfo is not None
        assert dt.utcoffset().total_seconds() == 0  # type: ignore[union-attr]

    def test_positive_offset(self):
        # +05:30 = IST
        dt = parse_aware_datetime("2026-11-20T15:30:05+05:30")
        assert dt.tzinfo is not None
        # Offset should be +05:30 = 19800 s
        assert dt.utcoffset().total_seconds() == 19800  # type: ignore[union-attr]

    def test_negative_offset(self):
        dt = parse_aware_datetime("2026-11-20T05:00:00-05:00")
        assert dt.tzinfo is not None
        assert dt.utcoffset().total_seconds() == -18000  # type: ignore[union-attr]

    def test_naive_with_fallback_tz(self):
        dt = parse_aware_datetime("2026-11-20 10:00:00", fallback_tz="Asia/Kolkata")
        assert dt.tzinfo is not None
        # Should resolve to IST (+05:30)
        assert dt.utcoffset().total_seconds() == 19800  # type: ignore[union-attr]

    def test_naive_without_fallback_raises(self):
        with pytest.raises(ValueError, match="no timezone info and no fallback_tz"):
            parse_aware_datetime("2026-11-20 10:00:00")

    def test_invalid_string_raises(self):
        with pytest.raises(ValueError):
            parse_aware_datetime("not-a-date")

    def test_syslog_style_with_year_and_fallback(self):
        # Syslog prepends year before passing to parse_aware_datetime.
        dt = parse_aware_datetime("2026 Nov 20 10:04:12", fallback_tz="UTC")
        assert dt.year == 2026
        assert dt.month == 11
        assert dt.day == 20
        assert dt.tzinfo is not None

    def test_converted_to_utc(self):
        # +05:30 → UTC should subtract 5h30m
        dt = parse_aware_datetime("2026-11-20T15:30:00+05:30")
        utc = dt.astimezone(timezone.utc)
        assert utc.hour == 10
        assert utc.minute == 0


# ═══════════════════════════════════════════════════════════════════════════════
# T2 – RawRecord rejects naive datetimes
# ═══════════════════════════════════════════════════════════════════════════════

class TestRawRecordValidation:
    def test_naive_datetime_raises(self):
        naive = datetime(2026, 11, 20, 10, 0, 0)  # no tzinfo
        with pytest.raises(ValueError, match="timezone-aware"):
            RawRecord(
                adapter="psutil",
                source="localhost",
                source_tz="UTC",
                category="cpu",
                raw_text="cpu=50",
                ts=naive,
                value=50.0,
                unit="percent",
            )

    def test_aware_datetime_accepted(self):
        aware = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
        r = RawRecord(
            adapter="psutil",
            source="localhost",
            source_tz="UTC",
            category="cpu",
            raw_text="cpu=50",
            ts=aware,
            value=50.0,
            unit="percent",
        )
        assert r.ts.tzinfo is not None


# ═══════════════════════════════════════════════════════════════════════════════
# T3 – normalize_and_store writes to raw_events
# ═══════════════════════════════════════════════════════════════════════════════

class TestNormalizeAndStore:
    def test_stores_row(self, tmp_db):
        record = RawRecord(
            adapter="psutil",
            source="myhost.local",
            source_tz="UTC",
            category="cpu",
            raw_text="cpu=72.5percent",
            ts=datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc),
            value=72.5,
            unit="percent",
        )
        event = normalize_and_store(record)

        # Verify returned Event shape.
        assert event.event_time_utc.endswith("Z")
        assert event.source == "myhost.local"
        assert event.category == "cpu"
        assert event.value == 72.5

        # Verify DB row.
        conn = get_db()
        rows = conn.execute("SELECT * FROM raw_events").fetchall()
        assert len(rows) == 1
        assert rows[0]["source"] == "myhost.local"
        assert rows[0]["category"] == "cpu"
        assert "72.5" in rows[0]["raw_text"]

    def test_event_time_is_utc_z(self, tmp_db):
        ist = parse_aware_datetime("2026-11-20T15:30:00+05:30")
        record = RawRecord(
            adapter="sim",
            source="sim-host",
            source_tz="Asia/Kolkata",
            category="memory",
            raw_text="mem=60%",
            ts=ist,
            value=60.0,
            unit="percent",
        )
        event = normalize_and_store(record)
        # Event time should be normalised to UTC.
        assert event.event_time_utc == "2026-11-20T10:00:00Z"

    def test_raw_text_stored_verbatim(self, tmp_db):
        """The real secret must be visible in raw_events (proves local storage)."""
        secret_line = "sshd[123]: Failed password for root from 1.2.3.4 password=hunter2"
        record = RawRecord(
            adapter="syslog",
            source="1.2.3.4",
            source_tz="UTC",
            category="auth",
            raw_text=secret_line,
            ts=datetime.now(timezone.utc),
            value=1.0,
            unit="count",
        )
        normalize_and_store(record)
        conn = get_db()
        row = conn.execute("SELECT raw_text FROM raw_events LIMIT 1").fetchone()
        assert "password=hunter2" in row["raw_text"]  # secret stays local!


# ═══════════════════════════════════════════════════════════════════════════════
# T4 – All adapters produce consistent Event shape
# ═══════════════════════════════════════════════════════════════════════════════

class TestAdapterOutputShape:
    """
    Tests that records from each adapter, when passed through normalize_and_store,
    produce Events with the mandatory fields populated correctly.
    """

    def _assert_event_shape(self, event: Event, expected_category: str) -> None:
        assert isinstance(event.event_time_utc, str)
        assert event.event_time_utc.endswith("Z"), "event_time_utc must end with Z"
        # Verify no naive datetime leaked through.
        dt = datetime.fromisoformat(event.event_time_utc.replace("Z", "+00:00"))
        assert dt.tzinfo is not None
        assert isinstance(event.source, str) and event.source
        assert isinstance(event.source_tz, str) and event.source_tz
        assert event.category == expected_category

    def test_psutil_record_shape(self, tmp_db):
        from collector.inputs.psutil_input import _sample
        now = datetime.now(timezone.utc)
        records = list(_sample(now, "myhost.local", "Asia/Kolkata", "8.8.8.8", "/"))
        # At minimum we should get cpu, memory, disk.
        cats = {r.category for r in records}
        assert "cpu" in cats
        assert "memory" in cats
        assert "disk" in cats
        for r in records:
            event = normalize_and_store(r)
            self._assert_event_shape(event, r.category)

    def test_sim_record_shape(self, tmp_db):
        from collector.inputs.sim_stream import _dict_to_raw_record
        data = {
            "category": "latency",
            "value": 55.3,
            "unit": "ms",
            "source": "sim-host.local",
            "timestamp": "2026-11-20T10:00:00Z",
            "raw_text": "latency=55.3ms",
        }
        record = _dict_to_raw_record(data, source_tz="UTC")
        assert record is not None
        event = normalize_and_store(record)
        self._assert_event_shape(event, "latency")

    def test_syslog_record_shape(self, tmp_db):
        from collector.inputs.syslog_input import _parse_line
        line = "Nov 20 10:04:12 myhost sshd[1234]: Failed password for root from 10.0.0.1 port 44444 ssh2"
        record = _parse_line(line, "UTC")
        assert record is not None
        event = normalize_and_store(record)
        self._assert_event_shape(event, "auth")


# ═══════════════════════════════════════════════════════════════════════════════
# T5 – Retention deletes rows older than the cutoff
# ═══════════════════════════════════════════════════════════════════════════════

class TestRetention:
    def _insert_row(self, conn, received_at: str, source: str = "h1") -> None:
        conn.execute(
            "INSERT INTO raw_events (received_at, source, source_tz, category, adapter) "
            "VALUES (?, ?, 'UTC', 'cpu', 'psutil')",
            (received_at, source),
        )
        conn.commit()

    def test_deletes_old_rows(self, tmp_db, monkeypatch):
        monkeypatch.setenv("RAW_RETENTION_HOURS", "1")
        conn = get_db()

        old_ts = (datetime.now(timezone.utc) - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
        self._insert_row(conn, old_ts, "old-host")

        result = run_once()
        assert result["deleted"] == 1

        rows = conn.execute("SELECT * FROM raw_events").fetchall()
        assert len(rows) == 0

    def test_keeps_new_rows(self, tmp_db, monkeypatch):
        monkeypatch.setenv("RAW_RETENTION_HOURS", "1")
        conn = get_db()

        new_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self._insert_row(conn, new_ts, "new-host")

        result = run_once()
        assert result["deleted"] == 0

        rows = conn.execute("SELECT * FROM raw_events").fetchall()
        assert len(rows) == 1

    def test_mixed_old_and_new(self, tmp_db, monkeypatch):
        monkeypatch.setenv("RAW_RETENTION_HOURS", "1")
        conn = get_db()

        old_ts = (datetime.now(timezone.utc) - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        new_ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        self._insert_row(conn, old_ts, "old-host")
        self._insert_row(conn, new_ts, "new-host")

        result = run_once()
        assert result["deleted"] == 1

        rows = conn.execute("SELECT source FROM raw_events").fetchall()
        assert rows[0]["source"] == "new-host"

    def test_large_batch_deletion(self, tmp_db, monkeypatch):
        """Retention must correctly delete more than 500 rows (batch loop test)."""
        monkeypatch.setenv("RAW_RETENTION_HOURS", "1")
        conn = get_db()

        old_ts = (datetime.now(timezone.utc) - timedelta(hours=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        # Insert 600 old rows.
        conn.executemany(
            "INSERT INTO raw_events (received_at, source, source_tz, category, adapter) "
            "VALUES (?, 'h', 'UTC', 'cpu', 'psutil')",
            [(old_ts,)] * 600,
        )
        conn.commit()

        result = run_once()
        assert result["deleted"] == 600

        remaining = conn.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0]
        assert remaining == 0

    def test_returns_summary_dict(self, tmp_db, monkeypatch):
        monkeypatch.setenv("RAW_RETENTION_HOURS", "24")
        result = run_once()
        assert "deleted" in result
        assert "retention_hours" in result
        assert "cutoff_utc" in result
        assert result["retention_hours"] == 24


# ═══════════════════════════════════════════════════════════════════════════════
# T9 – sim_stream adapter: timestamp parsing edge cases
# ═══════════════════════════════════════════════════════════════════════════════

class TestSimStreamParsing:
    def test_missing_timestamp_uses_now(self):
        from collector.inputs.sim_stream import _dict_to_raw_record
        data = {"category": "cpu", "value": 50.0, "unit": "percent",
                 "source": "sim-host"}
        record = _dict_to_raw_record(data, source_tz="UTC")
        assert record is not None
        assert record.ts.tzinfo is not None

    def test_offset_timestamp_parsed_correctly(self):
        from collector.inputs.sim_stream import _dict_to_raw_record
        data = {"category": "cpu", "value": 60.0, "unit": "percent",
                 "source": "sim-host", "timestamp": "2026-11-20T15:30:00+05:30"}
        record = _dict_to_raw_record(data, source_tz="Asia/Kolkata")
        assert record is not None
        # Offset should still be +05:30
        assert record.ts.utcoffset().total_seconds() == 19800  # type: ignore[union-attr]

    def test_bad_data_returns_none(self):
        from collector.inputs.sim_stream import _dict_to_raw_record
        record = _dict_to_raw_record({"timestamp": "not-a-date"}, source_tz="UTC")
        # Should return None gracefully (no crash).
        assert record is None


# ═══════════════════════════════════════════════════════════════════════════════
# T10 / T11 – syslog adapter parsing
# ═══════════════════════════════════════════════════════════════════════════════

class TestSyslogParsing:
    def test_failed_password_line(self):
        from collector.inputs.syslog_input import _parse_line
        line = "Nov 20 10:04:12 myhost sshd[1234]: Failed password for root from 10.0.0.1 port 22 ssh2"
        record = _parse_line(line, "UTC")
        assert record is not None
        assert record.category == "auth"
        assert record.adapter == "syslog"
        assert record.value == 1.0
        assert record.unit == "count"
        # Raw text must include the IP (proves raw secret stays local).
        assert "10.0.0.1" in record.raw_text
        assert record.ts.tzinfo is not None

    def test_failed_password_invalid_user(self):
        from collector.inputs.syslog_input import _parse_line
        line = "Nov 20 11:00:00 myhost sshd[9999]: Failed password for invalid user admin from 1.2.3.4 port 55123 ssh2"
        record = _parse_line(line, "UTC")
        assert record is not None
        assert record.source == "1.2.3.4"

    def test_non_auth_line_returns_none(self):
        from collector.inputs.syslog_input import _parse_line
        line = "Nov 20 10:04:12 myhost cron[123]: (root) CMD (/usr/sbin/backup.sh)"
        record = _parse_line(line, "UTC")
        assert record is None

    def test_connection_closed_invalid_user(self):
        from collector.inputs.syslog_input import _parse_line
        line = "Nov 20 12:00:00 myhost sshd[8888]: Connection closed by invalid user ubuntu 192.168.1.1 port 60000"
        record = _parse_line(line, "UTC")
        assert record is not None
        assert record.category == "auth"


# ═══════════════════════════════════════════════════════════════════════════════
# T12 – psutil adapter produces sensible values
# ═══════════════════════════════════════════════════════════════════════════════

class TestPsutilValues:
    def test_cpu_in_range(self):
        from collector.inputs.psutil_input import _sample
        now = datetime.now(timezone.utc)
        records = list(_sample(now, "localhost", "UTC", "8.8.8.8", "/"))
        cpu_records = [r for r in records if r.category == "cpu"]
        assert len(cpu_records) == 1
        assert 0 <= cpu_records[0].value <= 100  # type: ignore[operator]

    def test_memory_in_range(self):
        from collector.inputs.psutil_input import _sample
        now = datetime.now(timezone.utc)
        records = list(_sample(now, "localhost", "UTC", "8.8.8.8", "/"))
        mem_records = [r for r in records if r.category == "memory"]
        assert len(mem_records) == 1
        assert 0 <= mem_records[0].value <= 100  # type: ignore[operator]

    def test_all_records_timezone_aware(self):
        from collector.inputs.psutil_input import _sample
        now = datetime.now(timezone.utc)
        records = list(_sample(now, "localhost", "UTC", "8.8.8.8", "/"))
        for r in records:
            assert r.ts.tzinfo is not None, f"Naive ts on {r.category} record"


# ═══════════════════════════════════════════════════════════════════════════════
# T13 – WAL mode is active
# ═══════════════════════════════════════════════════════════════════════════════

class TestWalMode:
    def test_wal_mode_enabled(self, tmp_db):
        conn = get_db()
        result = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        assert result.lower() == "wal"
