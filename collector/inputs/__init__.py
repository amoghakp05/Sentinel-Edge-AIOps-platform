"""
collector/inputs/__init__.py
─────────────────────────────
Adapter interface for all telemetry stream consumers.
Allows swapping between the local simulator, psutil, syslog,
or an organizer-provided stream without altering collector pipeline logic.
"""

from __future__ import annotations

from typing import Iterator, Protocol, runtime_checkable
from collector.models import RawRecord


@runtime_checkable
class TelemetryStreamAdapter(Protocol):
    """
    Standard protocol that any telemetry stream input adapter must implement.
    """
    def stream(self, config: dict | None = None) -> Iterator[RawRecord]:
        """
        Continuously or batch-wise yield RawRecord items.
        """
        ...
