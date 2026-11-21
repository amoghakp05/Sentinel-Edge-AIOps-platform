"""
collector/inputs/syslog_input.py
──────────────────────────────────
Auth-log tail adapter.

Tails a file (default: /var/log/auth.log) and parses lines that match
failed SSH login patterns.  Each matched line becomes a RawRecord with:

  category  = 'auth'
  value     = 1.0  (one failed-login event)
  unit      = 'count'
  raw_text  = the verbatim log line (secrets MAY be present — stays local)

Design decisions
─────────────────
- D-007: Uses seek/poll (cross-platform).  ``inotify`` / ``watchdog`` is
  an optional upgrade on Linux.
- Timestamps embedded in syslog lines are parsed with parse_aware_datetime()
  from normalize.py.  If no year is embedded (syslog omits year), the current
  year is assumed.
- The real source IP from the log line is captured in raw_text and exposed as
  ``source`` on the RawRecord.  It will be pseudonymised in Phase 2.

Usage
─────
  from collector.inputs.syslog_input import stream

  for record in stream({"auth_log": "/var/log/auth.log", "source_tz": "UTC"}):
      ...
"""

from __future__ import annotations

import logging
import os
import re
import time
from datetime import datetime, timezone
from typing import Iterator, Optional

from collector.normalize import parse_aware_datetime
from collector.models import RawRecord

logger = logging.getLogger(__name__)

# ── Patterns ─────────────────────────────────────────────────────────────────

# Matches lines like:
#   Nov 20 10:04:12 hostname sshd[1234]: Failed password for root from 1.2.3.4 port 54321 ssh2
#   Nov 20 10:04:12 hostname sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 44444 ssh2
#   Nov 20 10:04:12 hostname sshd[1234]: Connection closed by invalid user ubuntu 1.2.3.4 port 44444
_FAILED_LOGIN_RE = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+\S+"         # hostname
    r"\s+sshd\[\d+\]:"
    r".*?(?:Failed password for(?: invalid user)?\s+(?P<user>\S+)\s+from\s+(?P<ip>\S+)"
    r"|Connection closed by(?: invalid user)?\s+(?P<user2>\S+)\s+(?P<ip2>\S+))"
)

# Simple extraction of "from <ip>" when the full regex doesn't match.
_FROM_IP_RE = re.compile(r"from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")

_DEFAULT_POLL_INTERVAL = 0.5  # seconds between file read attempts


def stream(config: dict | None = None) -> Iterator[RawRecord]:
    """
    Tail *config['auth_log']* and yield one RawRecord per failed login event.

    Parameters
    ----------
    config : dict with optional keys:
        auth_log       (str)   path to auth log  default: env SYSLOG_AUTH_LOG or /var/log/auth.log
        source_tz      (str)   IANA timezone of this host  default: env SOURCE_TZ or 'UTC'
        poll_interval  (float) seconds between polls  default: 0.5
    """
    if config is None:
        config = {}

    auth_log      = config.get(
        "auth_log",
        os.environ.get("SYSLOG_AUTH_LOG", "/var/log/auth.log"),
    )
    source_tz     = config.get("source_tz", os.environ.get("SOURCE_TZ", "UTC"))
    poll_interval = float(config.get("poll_interval", _DEFAULT_POLL_INTERVAL))

    logger.info("syslog_input tailing: %s  tz=%s", auth_log, source_tz)

    if not os.path.exists(auth_log):
        logger.warning(
            "Auth log not found: %s — syslog_input will wait for it to appear.", auth_log
        )

    # Open (or wait for) the log file.
    fh = _open_when_ready(auth_log, poll_interval)

    # Seek to end so we only process new lines (not replay history on startup).
    fh.seek(0, 2)

    while True:
        line = fh.readline()
        if not line:
            # No new data: check if the file was rotated.
            try:
                current_size = os.path.getsize(auth_log)
                if fh.tell() > current_size:
                    logger.info("Log rotation detected; re-opening %s", auth_log)
                    fh.close()
                    fh = _open_when_ready(auth_log, poll_interval)
            except FileNotFoundError:
                pass  # File removed temporarily during rotation; keep waiting.
            time.sleep(poll_interval)
            continue

        line = line.rstrip("\n")
        record = _parse_line(line, source_tz)
        if record is not None:
            yield record


# ── Parsing helpers ───────────────────────────────────────────────────────────

def _parse_line(line: str, source_tz: str) -> Optional[RawRecord]:
    """
    Parse a syslog auth line.

    Returns a RawRecord if the line is a failed-login event, else None.

    The ``source`` field is set to the **real** IP extracted from the log
    line.  It will be pseudonymised in Phase 2 (redact.py).
    raw_text is the verbatim line — may contain usernames, IPs, etc.
    """
    # Quick pre-filter to avoid regex cost on every line.
    if "Failed password" not in line and "Connection closed by invalid" not in line:
        return None

    m = _FAILED_LOGIN_RE.match(line)
    if m is None:
        # Try a looser IP extraction.
        ip_m = _FROM_IP_RE.search(line)
        source_ip = ip_m.group(1) if ip_m else "unknown"
    else:
        source_ip = m.group("ip") or m.group("ip2") or "unknown"

    # Parse timestamp from the line.
    ts = _parse_syslog_ts(line, source_tz)

    return RawRecord(
        adapter="syslog",
        source=source_ip,       # real IP — stays local (Hard Rule 2)
        source_tz=source_tz,
        category="auth",
        raw_text=line,          # verbatim; may contain username, IP, etc.
        value=1.0,              # one failed-login event
        unit="count",
        ts=ts,
    )


def _parse_syslog_ts(line: str, fallback_tz: str) -> datetime:
    """
    Extract and parse a timestamp from a syslog line header.

    Syslog omits the year; we assume the current year.
    Returns a timezone-aware datetime.
    """
    # Syslog header format: "Nov 20 10:04:12"
    _SYSLOG_TS_RE = re.compile(
        r"^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    )
    m = _SYSLOG_TS_RE.match(line)
    if m:
        raw_ts = m.group(1)
        current_year = datetime.now(timezone.utc).year
        ts_with_year = f"{current_year} {raw_ts}"
        try:
            return parse_aware_datetime(ts_with_year, fallback_tz=fallback_tz)
        except ValueError:
            pass

    # Fallback: use the current time.
    logger.debug("Could not parse syslog timestamp — using now()")
    return datetime.now(timezone.utc)


def _open_when_ready(path: str, poll_interval: float):
    """Block until *path* exists, then open and return the file handle."""
    while not os.path.exists(path):
        logger.debug("Waiting for log file: %s", path)
        time.sleep(poll_interval * 2)
    return open(path, "r", encoding="utf-8", errors="replace")
