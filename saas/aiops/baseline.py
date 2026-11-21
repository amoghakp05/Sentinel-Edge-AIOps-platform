"""
saas/aiops/baseline.py
──────────────────────
AIOps Baseline Modeling Engine.

Maintains per-tenant, per-source_ref, per-metric:
1. Rolling Exponentially Weighted Moving Average (EWMA)
2. Rolling Median and Median Absolute Deviation (MAD)
3. 168-hour time-of-day baseline (24 hours x 7 days)

Rules Enforced:
- Uses event_time_utc to place observations into hourly buckets, NOT arrival time.
- State is persisted to the 'baselines' table in SQLite so it survives restarts.
- Provides blended baseline incorporating diurnal patterns.
"""

from __future__ import annotations

import json
import logging
import math
import statistics
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from saas.db import get_connection

logger = logging.getLogger(__name__)

# In-memory baseline cache: (tenant_id, source_ref, category) -> MetricBaseline
_BASELINE_CACHE: Dict[Tuple[str, str, str], MetricBaseline] = {}


def get_bucket_index(dt: datetime) -> int:
    """Calculates bucket index [0..167] from weekday (0..6) and hour (0..23)."""
    weekday = dt.weekday()  # Monday = 0, Sunday = 6
    hour = dt.hour          # 0..23
    return weekday * 24 + hour


class MetricBaseline:
    """
    Tracks statistical properties and diurnal patterns for a single metric stream.
    """

    def __init__(
        self,
        ewma: Optional[float] = None,
        alpha: float = 0.15,
        window: Optional[List[float]] = None,
        window_size: int = 60,
        buckets: Optional[List[Dict[str, float]]] = None,
    ):
        self.alpha = alpha
        self.ewma = ewma
        self.window = list(window or [])
        self.window_size = window_size

        # 168 hourly buckets: each has {"count": float, "sum": float}
        if buckets and len(buckets) == 168:
            self.buckets = buckets
        else:
            self.buckets = [{"count": 0.0, "sum": 0.0} for _ in range(168)]

    def update(self, value: float, dt_utc: datetime) -> None:
        """Updates rolling EWMA, median/MAD window, and time-of-day bucket."""
        # 1. Update EWMA
        if self.ewma is None:
            self.ewma = float(value)
        else:
            self.ewma = self.alpha * float(value) + (1.0 - self.alpha) * self.ewma

        # 2. Update rolling window
        self.window.append(float(value))
        if len(self.window) > self.window_size:
            self.window.pop(0)

        # 3. Update time-of-day bucket using event_time_utc
        b_idx = get_bucket_index(dt_utc)
        self.buckets[b_idx]["count"] += 1.0
        self.buckets[b_idx]["sum"] += float(value)

    def get_rolling_median_and_mad(self) -> Tuple[float, float]:
        """Calculates current rolling median and Median Absolute Deviation (MAD)."""
        if not self.window:
            med = self.ewma if self.ewma is not None else 0.0
            return med, 1.0

        med = statistics.median(self.window)
        deviations = [abs(x - med) for x in self.window]
        mad = statistics.median(deviations) if deviations else 1.0

        # Floor MAD to prevent division by near-zero on static signals
        mad = max(mad, 1.0)
        return float(med), float(mad)

    def get_blended_baseline(self, dt_utc: datetime) -> Tuple[float, float, float]:
        """
        Computes blended baseline (incorporating diurnal pattern and rolling median),
        along with MAD and EWMA.

        Returns:
            (blended_baseline, mad, ewma)
        """
        rolling_med, mad = self.get_rolling_median_and_mad()
        current_ewma = self.ewma if self.ewma is not None else rolling_med

        b_idx = get_bucket_index(dt_utc)
        bucket = self.buckets[b_idx]

        if bucket["count"] >= 3:
            tod_mean = bucket["sum"] / bucket["count"]
            # Blend: 60% diurnal pattern, 40% recent rolling median
            blended = 0.60 * tod_mean + 0.40 * rolling_med
        else:
            # Fall back to rolling median or EWMA
            blended = rolling_med

        return float(blended), float(mad), float(current_ewma)

    def to_dict(self) -> Dict[str, Any]:
        """Serializes baseline state for persistence."""
        return {
            "alpha": self.alpha,
            "ewma": self.ewma,
            "window": self.window,
            "window_size": self.window_size,
            "buckets": self.buckets,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> MetricBaseline:
        """Deserializes baseline state from persistence dictionary."""
        return cls(
            alpha=data.get("alpha", 0.15),
            ewma=data.get("ewma"),
            window=data.get("window", []),
            window_size=data.get("window_size", 60),
            buckets=data.get("buckets"),
        )


def get_baseline(
    tenant_id: str,
    source_ref: str,
    category: str,
) -> MetricBaseline:
    """Retrieves baseline from in-memory cache or restores from SQLite."""
    key = (tenant_id, source_ref, category)
    if key in _BASELINE_CACHE:
        return _BASELINE_CACHE[key]

    conn = get_connection()
    try:
        cur = conn.execute(
            """
            SELECT state_json FROM baselines
            WHERE tenant_id = ? AND source_ref = ? AND category = ?
            """,
            (tenant_id, source_ref, category),
        )
        row = cur.fetchone()
        if row:
            try:
                data = json.loads(row["state_json"])
                baseline = MetricBaseline.from_dict(data)
                _BASELINE_CACHE[key] = baseline
                return baseline
            except Exception as exc:
                logger.error("Failed to parse baseline state: tenant=%s category=%s (%s)", tenant_id, category, type(exc).__name__)

        # Initialize fresh baseline
        baseline = MetricBaseline()
        _BASELINE_CACHE[key] = baseline
        return baseline
    finally:
        conn.close()


def save_baseline(
    tenant_id: str,
    source_ref: str,
    category: str,
    baseline: MetricBaseline,
    updated_utc: Optional[str] = None,
) -> None:
    """Persists baseline state to SQLite so it survives restarts."""
    key = (tenant_id, source_ref, category)
    _BASELINE_CACHE[key] = baseline

    now_iso = updated_utc or datetime.now(timezone.utc).isoformat()
    state_str = json.dumps(baseline.to_dict())

    conn = get_connection()
    try:
        with conn:
            conn.execute(
                """
                INSERT INTO baselines (tenant_id, source_ref, category, state_json, updated_utc)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(tenant_id, source_ref, category) DO UPDATE SET
                    state_json = excluded.state_json,
                    updated_utc = excluded.updated_utc
                """,
                (tenant_id, source_ref, category, state_str, now_iso),
            )
    finally:
        conn.close()


def reset_baseline_cache_for_tests() -> None:
    """Clears in-memory baseline cache for test isolation."""
    _BASELINE_CACHE.clear()
