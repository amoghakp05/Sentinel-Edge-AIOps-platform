"""
collector/aggregate.py
──────────────────────
5-second tumbling window metric and event aggregator.

Rules:
- 5-second tumbling windows -> avg/min/max per source per metric.
- Failed logins become a single COUNT per source per window.
- Absolutely NO usernames and NO raw lines are preserved in aggregates.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

from collector.pseudonym import compute_source_ref

_SOURCE_REF_REGEX = re.compile(r"^h_[0-9a-f]{8}$")


@dataclass
class MetricSummary:
    source_ref: str
    category: str
    window_s: int
    window_start_utc: str
    window_end_utc: str
    avg_value: float
    min_value: float
    max_value: float
    sample_count: int
    unit: Optional[str] = None


@dataclass
class AuthSummary:
    source_ref: str
    window_s: int
    window_start_utc: str
    window_end_utc: str
    failed_login_count: int


@dataclass
class _Bucket:
    values: List[float] = field(default_factory=list)
    unit: Optional[str] = None
    failed_logins: int = 0


class TumblingWindowAggregator:
    """
    Groups telemetry by source_ref and 5-second tumbling time boundaries.
    """

    def __init__(self, window_s: int = 5) -> None:
        self.window_s = window_s
        # Key: (window_timestamp_s, source_ref, category) -> _Bucket
        self._buckets: Dict[Tuple[int, str, str], _Bucket] = {}

    def add_sample(
        self,
        event_time_utc: datetime,
        source_ref: str,
        category: str,
        value: Optional[float] = None,
        unit: Optional[str] = None,
        is_failed_login: bool = False,
    ) -> None:
        """
        Record a single observation into its aligned tumbling window.
        """
        # Security Guard: Ensure source_ref is strictly pseudonymous, never a raw host or IP
        if not _SOURCE_REF_REGEX.match(source_ref):
            source_ref = compute_source_ref(source_ref)

        ts_epoch = int(event_time_utc.timestamp())
        window_start_ts = (ts_epoch // self.window_s) * self.window_s
        key = (window_start_ts, source_ref, category)

        if key not in self._buckets:
            self._buckets[key] = _Bucket(unit=unit)

        bucket = self._buckets[key]
        if value is not None and not is_failed_login:
            bucket.values.append(value)
            if unit:
                bucket.unit = unit

        if is_failed_login or category == "auth":
            bucket.failed_logins += 1

    def flush(self, older_than_utc: Optional[datetime] = None) -> Tuple[List[MetricSummary], List[AuthSummary]]:
        """
        Flushes and returns completed window summaries.
        If older_than_utc is None, flushes all currently buffered windows.
        """
        metric_results: List[MetricSummary] = []
        auth_results: List[AuthSummary] = []

        keys_to_delete = []

        for (w_start, src_ref, cat), bucket in self._buckets.items():
            w_end = w_start + self.window_s

            if older_than_utc is not None and w_end > int(older_than_utc.timestamp()):
                continue  # Window still active/open

            keys_to_delete.append((w_start, src_ref, cat))

            w_start_str = datetime.fromtimestamp(w_start, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
            w_end_str = datetime.fromtimestamp(w_end, tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

            if cat == "auth":
                auth_results.append(
                    AuthSummary(
                        source_ref=src_ref,
                        window_s=self.window_s,
                        window_start_utc=w_start_str,
                        window_end_utc=w_end_str,
                        failed_login_count=bucket.failed_logins,
                    )
                )
            elif bucket.values:
                avg_val = round(sum(bucket.values) / len(bucket.values), 2)
                min_val = round(min(bucket.values), 2)
                max_val = round(max(bucket.values), 2)
                metric_results.append(
                    MetricSummary(
                        source_ref=src_ref,
                        category=cat,
                        window_s=self.window_s,
                        window_start_utc=w_start_str,
                        window_end_utc=w_end_str,
                        avg_value=avg_val,
                        min_value=min_val,
                        max_value=max_val,
                        sample_count=len(bucket.values),
                        unit=bucket.unit,
                    )
                )

        for k in keys_to_delete:
            del self._buckets[k]

        return metric_results, auth_results
