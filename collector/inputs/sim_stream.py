"""
collector/inputs/sim_stream.py
───────────────────────────────
HTTP-polling adapter for the scenario simulator server
(tools/sim_stream_server.py).

The simulator server exposes GET /events which returns a JSON array of
simulated telemetry records.  This adapter polls that endpoint at a
configurable interval and yields RawRecord objects.

Design notes (D-008)
─────────────────────
- HTTP polling is the default; WebSocket is a future optional upgrade.
- The simulator injects fake secrets (passwords, tokens, IPs) into some
  records to prove they are captured in raw_events and NEVER egressed.
- Timestamps from the simulator are trusted for event_time; the adapter
  parses them with parse_aware_datetime() (tz-aware, never naive).

Usage
─────
  from collector.inputs.sim_stream import stream

  for record in stream({"base_url": "http://localhost:9000", "source_tz": "UTC"}):
      ...
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Iterator, Optional

import httpx

from collector.normalize import parse_aware_datetime
from collector.models import RawRecord

logger = logging.getLogger(__name__)

_DEFAULT_POLL_INTERVAL = 1.0   # seconds


def stream(config: dict | None = None) -> Iterator[RawRecord]:
    """
    Poll the simulator server and yield RawRecord objects.

    Parameters
    ----------
    config : dict with optional keys:
        base_url      (str)   simulator base URL  default: env SIM_STREAM_URL
        source_tz     (str)   IANA tz of simulated host  default: env SOURCE_TZ or 'UTC'
        poll_interval (float) seconds between polls  default: 1.0
        collector_id  (str)   which collector to simulate  default: 'col-blr-01'
    """
    if config is None:
        config = {}

    base_url      = config.get("base_url", os.environ.get("SIM_STREAM_URL", "http://localhost:9000"))
    source_tz     = config.get("source_tz", os.environ.get("SOURCE_TZ", "UTC"))
    poll_interval = float(config.get("poll_interval",
                                     os.environ.get("SIM_POLL_INTERVAL_S", _DEFAULT_POLL_INTERVAL)))
    collector_id  = config.get("collector_id", "col-blr-01")

    url = f"{base_url}/events"
    logger.info("sim_stream starting: collector_id=%s tz=%s", collector_id, source_tz)

    with httpx.Client(timeout=10.0) as client:
        while True:
            try:
                resp = client.get(url, params={"collector_id": collector_id})
                resp.raise_for_status()
                records_data = resp.json()

                if not isinstance(records_data, list):
                    logger.warning("Simulator returned non-list data format")
                else:
                    for raw_dict in records_data:
                        record = _dict_to_raw_record(raw_dict, source_tz)
                        if record is not None:
                            yield record

            except httpx.ConnectError:
                logger.warning("Simulator not reachable — will retry")
            except httpx.HTTPStatusError as exc:
                logger.warning("Simulator HTTP error: %s", type(exc).__name__)
            except json.JSONDecodeError as exc:
                logger.warning("Simulator returned invalid JSON: %s", type(exc).__name__)
            except Exception as exc:
                logger.error("sim_stream unexpected error: %s", type(exc).__name__)

            time.sleep(poll_interval)


# ── Parsing helpers ───────────────────────────────────────────────────────────

def _dict_to_raw_record(data: dict, source_tz: str) -> Optional[RawRecord]:
    """
    Convert a simulator event dict to a RawRecord.

    Expected simulator dict keys (all optional except category):
      category   str   metric category
      value      float numeric value
      unit       str   unit string
      source     str   simulated source host/IP (the "real" value in simulation)
      timestamp  str   ISO-8601 string (optional; uses now() if missing)
      raw_text   str   verbatim text (may contain injected secrets)
    """
    try:
        category = data.get("category", "cpu")
        source   = data.get("source", "sim-host.local")
        value    = data.get("value")
        unit     = data.get("unit")

        # Parse timestamp — simulator may include tz offset or 'Z'.
        ts_str = data.get("timestamp")
        if ts_str:
            ts = parse_aware_datetime(ts_str, fallback_tz=source_tz)
        else:
            ts = datetime.now(timezone.utc)

        # Build verbatim raw_text from the full dict (may include secrets).
        raw_text = data.get("raw_text") or json.dumps(data, separators=(",", ":"))

        return RawRecord(
            adapter="sim",
            source=source,
            source_tz=source_tz,
            category=category,
            raw_text=raw_text,
            value=float(value) if value is not None else None,
            unit=unit,
            ts=ts,
        )

    except Exception as exc:
        logger.warning("Failed to parse simulator event: %s", type(exc).__name__)
        return None
