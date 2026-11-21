"""
collector/local_analysis.py
───────────────────────────
Edge analysis engine: detects brute-force authentication attacks.

Rules:
- If failed logins > N within M seconds (configurable via env or arguments),
  emits a 'security_summary' with a computed risk_score (0-100).
- Short context string formatted as:
  "{count} failed logins in {window_s}s from {num_sources} source (risk {risk})"
- HARD RULE: context strings are built ONLY from already-aggregated/redacted numbers.
  Never embeds usernames, raw log lines, or un-hashed IP addresses.
"""

from __future__ import annotations

import math
import os
import re
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Deque, Dict, List, Optional, Tuple

from collector.pseudonym import compute_source_ref

_SOURCE_REF_REGEX = re.compile(r"^h_[0-9a-f]{8}$")

DEFAULT_FAILED_LOGIN_THRESHOLD = int(os.environ.get("AUTH_FAIL_THRESHOLD", "5"))
DEFAULT_ANALYSIS_WINDOW_S = int(os.environ.get("AUTH_ANALYSIS_WINDOW_S", "60"))


@dataclass
class SecuritySummary:
    source_ref: str
    kind: str           # "security_summary"
    category: str       # "auth"
    severity: str       # "warning" | "critical"
    value: float        # risk_score (0.0 to 100.0)
    unit: str           # "risk_score"
    window_s: int
    context: str
    event_time_utc: str


class BruteForceAnalyzer:
    """
    Sliding-window detector for authentication brute-force spikes.
    Tracks failure events per source_ref.
    """

    def __init__(
        self,
        threshold: int = DEFAULT_FAILED_LOGIN_THRESHOLD,
        window_s: int = DEFAULT_ANALYSIS_WINDOW_S,
    ) -> None:
        self.threshold = threshold
        self.window_s = window_s
        # Map of source_ref -> deque of timestamps (epoch seconds)
        self._history: Dict[str, Deque[float]] = {}
        # Cooldown to avoid duplicate alerts within the same attack window
        self._last_alerted: Dict[str, float] = {}

    def record_failures(self, source_ref: str, count: int, at_time: datetime) -> Optional[SecuritySummary]:
        """
        Record *count* failed logins for *source_ref* at *at_time*.
        Returns a SecuritySummary if threshold is crossed, else None.
        """
        if count <= 0:
            return None

        # Security Guard: Ensure source_ref is strictly pseudonymous
        if not _SOURCE_REF_REGEX.match(source_ref):
            source_ref = compute_source_ref(source_ref)

        ts = at_time.timestamp()
        if source_ref not in self._history:
            self._history[source_ref] = deque()

        q = self._history[source_ref]
        # Append timestamps
        for _ in range(count):
            q.append(ts)

        # Evict timestamps older than sliding window
        cutoff = ts - self.window_s
        while q and q[0] < cutoff:
            q.popleft()

        total_in_window = len(q)

        # Check breach
        if total_in_window > self.threshold:
            # Check cooldown (30s)
            last = self._last_alerted.get(source_ref, 0.0)
            if ts - last >= 30.0:
                self._last_alerted[source_ref] = ts
                risk = self._compute_risk_score(total_in_window)
                severity = "critical" if risk >= 75.0 else "warning"

                # HARD RULE: Built ONLY from aggregated numeric values, max length 200
                context = (
                    f"{total_in_window} failed logins in {self.window_s}s "
                    f"from 1 source (risk {int(risk)})"
                )[:200]

                return SecuritySummary(
                    source_ref=source_ref,
                    kind="security_summary",
                    category="auth",
                    severity=severity,
                    value=risk,
                    unit="risk_score",
                    window_s=self.window_s,
                    context=context,
                    event_time_utc=at_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
                )

        return None

    def _compute_risk_score(self, count: int) -> float:
        """
        Calculates a calibrated risk score (0-100) based on burst intensity.
        Example: 14 failures with threshold 5 yields risk ~82.
        """
        excess = count - self.threshold
        # Base 50 for exceeding threshold, scaling up to 100
        score = 50.0 + (excess * 3.5)
        return float(min(100.0, max(0.0, round(score, 1))))
