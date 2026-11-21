"""
collector/heartbeat.py
──────────────────────
Periodic collector heartbeat service.

Generates a heartbeat payload every 10 seconds containing:
- Collector version
- Collector process CPU and Memory usage
- Config hash
- Outbox depth (queue size)
Enqueues through the standard policy and outbox pipeline.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import socket
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import psutil

from collector import outbox, policy
from collector.pseudonym import compute_source_ref
from collector.uuidv7 import uuidv7

logger = logging.getLogger(__name__)

COLLECTOR_VERSION = "1.4.2"
HEARTBEAT_INTERVAL_S = 10.0


def compute_config_hash() -> str:
    """Computes a short hash representing current collector configuration."""
    cfg_str = f"{os.environ.get('COLLECTOR_ID')}:{os.environ.get('SAAS_INGEST_URL')}:{os.environ.get('SOURCE_TZ')}"
    return hashlib.sha256(cfg_str.encode("utf-8")).hexdigest()[:8]


def create_heartbeat_payload() -> Dict[str, Any]:
    """
    Constructs an allow-listed heartbeat payload.
    """
    now = datetime.now(timezone.utc)
    now_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    collector_id = os.environ.get("COLLECTOR_ID", "col-acme-eu-1")
    source_tz = os.environ.get("SOURCE_TZ", "UTC")
    src_ref = compute_source_ref(socket.getfqdn())

    # Measure current collector process metrics
    proc = psutil.Process(os.getpid())
    cpu_pct = round(proc.cpu_percent(interval=None), 1)
    mem_mb = round(proc.memory_info().rss / (1024 * 1024), 1)

    outbox_stats = outbox.get_outbox_stats()
    queue_depth = outbox_stats["pending_count"]
    cfg_hash = compute_config_hash()

    context = (
        f"v{COLLECTOR_VERSION} cpu={cpu_pct}% mem={mem_mb}MB "
        f"queue={queue_depth} cfg={cfg_hash}"
    )

    return {
        "payload_id": uuidv7(),
        "schema_version": 1,
        "collector_id": collector_id,
        "event_time_utc": now_str,
        "source_tz": source_tz,
        "sent_time_utc": now_str,
        "source_ref": src_ref,
        "kind": "heartbeat",
        "category": "connectivity",
        "severity": "info",
        "value": 1.0,
        "unit": "boolean",
        "window_s": 10,
        "context": context,
    }


def emit_heartbeat() -> Optional[str]:
    """
    Generates, validates, and enqueues a heartbeat payload.
    Returns payload_id if successfully enqueued, else None.
    """
    payload = create_heartbeat_payload()
    allowed, filtered, reason = policy.enforce_policy(payload)

    if allowed and filtered:
        pid = outbox.enqueue(filtered)
        logger.debug("Emitted heartbeat [%s]: queue_depth=%d", pid, outbox.get_outbox_stats()["pending_count"])
        return pid
    else:
        logger.error("Heartbeat rejected by egress policy: %s", reason)
        return None


class HeartbeatService:
    """Background service running emit_heartbeat() every 10 seconds."""

    def __init__(self, interval_s: float = HEARTBEAT_INTERVAL_S) -> None:
        self.interval_s = interval_s
        self._stop_event = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._run, name="heartbeat-thread", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 3.0) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=timeout)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                emit_heartbeat()
            except Exception as exc:
                logger.error("Heartbeat emission failed: %s", type(exc).__name__)
            self._stop_event.wait(self.interval_s)
