"""
collector/models.py
───────────────────
Shared data-transfer objects for Phase 1.

RawRecord  – raw, un-redacted data from any input adapter.
             Secrets MAY be present.  Stays LOCAL; never egressed.

Event      – normalised representation after normalize.py runs.
             Still contains the real 'source' value; redaction is Phase 2.
"""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Optional


# ── RawRecord ────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class RawRecord:
    """
    Verbatim record from an input adapter.

    Attributes
    ----------
    adapter     : Which adapter produced this ('psutil' | 'sim' | 'syslog').
    source      : Real hostname or IP address (kept local, never egressed).
    source_tz   : IANA timezone string of the originating host.
    category    : Metric / event category (matches allow-list enum).
    raw_text    : Full verbatim line or JSON blob.  May contain secrets.
    value       : Numeric value if applicable (None for text-only records).
    unit        : Unit string (e.g. 'percent', 'ms', 'mbps').
    ts          : Timezone-aware datetime when the event occurred.
                  MUST be timezone-aware (tz is not None); adapters must
                  guarantee this or raise ValueError.
    """

    adapter:   str
    source:    str
    source_tz: str
    category:  str
    raw_text:  str
    ts:        datetime.datetime
    value:     Optional[float] = None
    unit:      Optional[str]   = None

    def __post_init__(self) -> None:
        # Hard Rule 4: reject naive datetimes loudly.
        if self.ts.tzinfo is None or self.ts.tzinfo.utcoffset(self.ts) is None:
            raise ValueError(
                f"RawRecord.ts must be timezone-aware; got naive datetime: {self.ts!r}"
            )


# ── Event ────────────────────────────────────────────────────────────────────

@dataclass
class Event:
    """
    Normalised record produced by normalize.py from a RawRecord.

    'source' still holds the real host/IP value.  It will be pseudonymised
    into 'source_ref' by redact.py in Phase 2.

    Attributes
    ----------
    event_time_utc : ISO-8601 UTC string with trailing 'Z' (e.g. 2026-11-20T10:00:05Z).
    source_tz      : IANA timezone of originating host.
    source         : Real hostname / IP — LOCAL ONLY, never egressed.
    category       : Normalised category name.
    value          : Numeric metric value (None for text events).
    unit           : Unit label (None for text events).
    raw_text       : Original verbatim text, retained for local storage.
    adapter        : Which adapter produced this.
    """

    event_time_utc: str              # always ends with 'Z'
    source_tz:      str
    source:         str              # real hostname / IP – LOCAL ONLY
    category:       str
    adapter:        str
    raw_text:       str
    value:          Optional[float] = None
    unit:           Optional[str]   = None

    # Optional structured extras set by specific adapters.
    extra:          dict            = field(default_factory=dict)
