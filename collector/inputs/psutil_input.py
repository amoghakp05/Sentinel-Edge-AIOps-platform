"""
collector/inputs/psutil_input.py
─────────────────────────────────
Real system telemetry adapter using psutil.

Yields RawRecord objects for:
  - cpu         : system-wide CPU utilisation (%)
  - memory      : used memory (%)
  - disk        : root-partition used (%)
  - bandwidth   : bytes_sent + bytes_recv converted to Mbps since last sample
  - latency     : ICMP ping to a configurable host (ms), or None if unavailable
  - packet_loss : percentage of dropped packets on primary interface

All timestamps are timezone-aware (Hard Rule / D-004).

Usage
─────
  from collector.inputs.psutil_input import stream

  for record in stream({"source_tz": "Asia/Kolkata", "interval_s": 5}):
      ...
"""

from __future__ import annotations

import logging
import os
import platform
import socket
import time
from datetime import datetime, timezone
from typing import Iterator, Optional

import psutil

from collector.models import RawRecord

logger = logging.getLogger(__name__)

# ── Defaults ──────────────────────────────────────────────────────────────────

_DEFAULT_INTERVAL_S = 5          # seconds between samples
_DEFAULT_PING_HOST   = "8.8.8.8" # host used for latency probe (not sent to SaaS)
_DEFAULT_DISK_PATH   = "/"        # partition to measure disk usage

# Network throughput smoothing: carry previous counter values across calls.
_prev_net_counters: Optional[psutil._common.snetio] = None
_prev_net_ts: Optional[float] = None


def stream(config: dict | None = None) -> Iterator[RawRecord]:
    """
    Continuously yield RawRecord objects from real system metrics.

    Parameters
    ----------
    config : dict with optional keys:
        source_tz    (str)   IANA timezone  default: env SOURCE_TZ or 'UTC'
        interval_s   (float) seconds between full sample cycles  default: 5
        ping_host    (str)   hostname/IP to ping for latency      default: 8.8.8.8
        disk_path    (str)   path for disk usage                  default: /

    Yields one RawRecord per metric category per interval.
    """
    if config is None:
        config = {}

    source_tz  = config.get("source_tz", os.environ.get("SOURCE_TZ", "UTC"))
    interval_s = float(config.get("interval_s", _DEFAULT_INTERVAL_S))
    ping_host  = config.get("ping_host", _DEFAULT_PING_HOST)
    disk_path  = config.get("disk_path", _DEFAULT_DISK_PATH)
    source     = _local_hostname()

    logger.info(
        "psutil_input starting: tz=%s interval=%.1fs",
        source_tz, interval_s,
    )

    while True:
        now = datetime.now(timezone.utc)
        yield from _sample(now, source, source_tz, ping_host, disk_path)
        time.sleep(interval_s)


# ── Sampling helpers ───────────────────────────────────────────────────────────

def _sample(
    now: datetime,
    source: str,
    source_tz: str,
    ping_host: str,
    disk_path: str,
) -> Iterator[RawRecord]:
    """Gather all metrics for one cycle and yield RawRecords."""

    def mk(category: str, value: float, unit: str, extra: str = "") -> RawRecord:
        raw = f"{category}={value:.2f}{unit}" + (f" {extra}" if extra else "")
        return RawRecord(
            adapter="psutil",
            source=source,
            source_tz=source_tz,
            category=category,
            raw_text=raw,
            value=round(value, 4),
            unit=unit,
            ts=now,
        )

    # CPU
    try:
        cpu_pct = psutil.cpu_percent(interval=None)
        yield mk("cpu", cpu_pct, "percent")
    except Exception as exc:
        logger.warning("cpu sample failed: %s", type(exc).__name__)

    # Memory
    try:
        mem = psutil.virtual_memory()
        yield mk("memory", mem.percent, "percent",
                 extra=f"used={mem.used >> 20}MB total={mem.total >> 20}MB")
    except Exception as exc:
        logger.warning("memory sample failed: %s", type(exc).__name__)

    # Disk
    try:
        du = psutil.disk_usage(disk_path)
        yield mk("disk", du.percent, "percent",
                 extra=f"used={du.used >> 30}GB total={du.total >> 30}GB")
    except Exception as exc:
        logger.warning("disk sample failed: %s", type(exc).__name__)

    # Bandwidth (Mbps since last sample)
    try:
        bw_mbps = _bandwidth_mbps()
        if bw_mbps is not None:
            yield mk("bandwidth", bw_mbps, "mbps")
    except Exception as exc:
        logger.warning("bandwidth sample failed: %s", type(exc).__name__)

    # Packet loss (from net_io_counters: dropin + dropout / total packets)
    try:
        loss_pct = _packet_loss_pct()
        if loss_pct is not None:
            yield mk("packet_loss", loss_pct, "percent")
    except Exception as exc:
        logger.warning("packet_loss sample failed: %s", type(exc).__name__)

    # Latency (best-effort ICMP ping)
    try:
        lat_ms = _ping_ms(ping_host)
        if lat_ms is not None:
            yield mk("latency", lat_ms, "ms",
                     extra=f"target=h_{_hash_host(ping_host)}")
    except Exception as exc:
        logger.warning("latency sample failed: %s", type(exc).__name__)


def _bandwidth_mbps() -> Optional[float]:
    """
    Return aggregate network throughput in Mbps since the last call.
    Returns None on first call (no delta yet).
    """
    global _prev_net_counters, _prev_net_ts

    counters = psutil.net_io_counters()
    now_ts   = time.monotonic()

    if _prev_net_counters is None or _prev_net_ts is None:
        _prev_net_counters = counters
        _prev_net_ts       = now_ts
        return None

    elapsed  = now_ts - _prev_net_ts
    if elapsed <= 0:
        return None

    bytes_delta = (
        (counters.bytes_sent - _prev_net_counters.bytes_sent)
        + (counters.bytes_recv - _prev_net_counters.bytes_recv)
    )
    mbps = max(0.0, (bytes_delta * 8) / elapsed / 1e6)

    _prev_net_counters = counters
    _prev_net_ts       = now_ts
    return round(mbps, 4)


def _packet_loss_pct() -> Optional[float]:
    """
    Approximate packet loss from NIC drop counters.
    Returns None if counters are unavailable or zero total.
    """
    counters = psutil.net_io_counters()
    total = counters.packets_sent + counters.packets_recv
    if total == 0:
        return None
    dropped = counters.dropin + counters.dropout
    return round((dropped / total) * 100, 4)


def _ping_ms(host: str) -> Optional[float]:
    """
    Measure TCP connect latency to *host*:443 in milliseconds.
    Falls back gracefully if the network is unavailable.

    Note: This is a TCP handshake probe, not ICMP ping, so it works
    without root/administrator privileges on all platforms.
    """
    try:
        start = time.perf_counter()
        with socket.create_connection((host, 443), timeout=3):
            pass
        return round((time.perf_counter() - start) * 1000, 2)
    except OSError:
        return None


def _local_hostname() -> str:
    """Return the real local hostname.  Stored locally; never egressed."""
    return socket.getfqdn()


def _hash_host(host: str) -> str:
    """Short FNV-1a hash of a host string (for safe log references)."""
    h = 2166136261
    for c in host.encode():
        h ^= c
        h = (h * 16777619) & 0xFFFFFFFF
    return f"{h:08x}"
