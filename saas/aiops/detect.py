"""
saas/aiops/detect.py
────────────────────
AIOps Anomaly Detection Engine.

Algorithms:
1. Robust Z-score:
     z = 0.6745 * (x - blended_median) / MAD
2. Persistence Rule:
     Flag an anomaly ONLY if |z| exceeds the limit for at least 3 of the
     last 5 evaluation windows (reduces false alarms on transient spikes).
3. Multivariate Second Opinion:
     Evaluates cross-metric correlation (CPU, memory, latency, packet loss).
"""

from __future__ import annotations

import collections
import logging
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional, Tuple

from saas.aiops.baseline import MetricBaseline, get_baseline, save_baseline
from saas.aiops.explain import generate_explanation

logger = logging.getLogger(__name__)

# Default robust z-score threshold for anomaly classification
DEFAULT_Z_THRESHOLD = 3.0

# Rolling window persistence history: (tenant_id, source_ref, category) -> deque(maxlen=5) of bool
_WINDOW_HISTORY: Dict[Tuple[str, str, str], Deque[bool]] = {}


def compute_robust_zscore(value: float, median: float, mad: float) -> float:
    """
    Computes robust z-score normalized by Median Absolute Deviation (MAD):
    z = 0.6745 * (value - median) / MAD
    """
    safe_mad = max(0.5, abs(mad))
    z = 0.6745 * (float(value) - float(median)) / safe_mad
    return float(z)


class AnomalyDetector:
    """
    Stateful detector enforcing baseline comparison and 3/5 persistence gating.
    """

    def __init__(self, z_threshold: float = DEFAULT_Z_THRESHOLD):
        self.z_threshold = z_threshold

    def evaluate_metric(
        self,
        tenant_id: str,
        source_ref: str,
        category: str,
        value: float,
        event_time_utc: datetime,
        correlated_metrics: Optional[Dict[str, float]] = None,
    ) -> Tuple[bool, Optional[Dict[str, Any]]]:
        """
        Evaluates a new metric reading against its blended baseline:
        1. Retrieves persisted baseline.
        2. Computes robust z-score against blended time-of-day baseline.
        3. Updates 5-window persistence queue.
        4. If |z| >= threshold for >= 3 of last 5 windows: returns (True, explanation).
        5. Updates baseline model with new observation.

        Returns:
            (is_anomaly: bool, explanation_dict: Optional[dict])
        """
        key = (tenant_id, source_ref, category)

        # 1. Retrieve baseline
        baseline_model = get_baseline(tenant_id, source_ref, category)
        blended_median, mad, ewma = baseline_model.get_blended_baseline(event_time_utc)

        # 2. Compute robust z-score
        z = compute_robust_zscore(value, blended_median, mad)
        sample_exceeds = abs(z) >= self.z_threshold

        # 3. Update 5-window persistence queue
        if key not in _WINDOW_HISTORY:
            _WINDOW_HISTORY[key] = collections.deque(maxlen=5)

        history = _WINDOW_HISTORY[key]
        history.append(sample_exceeds)

        exceeded_count = sum(1 for h in history if h)
        total_windows = len(history)
        persistence_str = f"{exceeded_count}/{total_windows}"

        # 4. Persistence rule: must exceed in at least 3 of last 5 windows
        is_anomaly = exceeded_count >= 3 and sample_exceeds

        explanation: Optional[Dict[str, Any]] = None

        if is_anomaly:
            # Correlated signals second opinion
            corr_zscores: Dict[str, float] = {}
            if correlated_metrics:
                for c_cat, c_val in correlated_metrics.items():
                    if c_cat != category:
                        c_base = get_baseline(tenant_id, source_ref, c_cat)
                        c_med, c_mad, _ = c_base.get_blended_baseline(event_time_utc)
                        corr_zscores[c_cat] = compute_robust_zscore(c_val, c_med, c_mad)

            explanation = generate_explanation(
                metric=category,
                observed=value,
                baseline=blended_median,
                zscore=z,
                persistence_ratio=persistence_str,
                exceeded_count=exceeded_count,
                total_windows=total_windows,
                correlated_signals=corr_zscores,
            )
            logger.info(
                "AIOps Anomaly Detected: tenant=%s metric=%s persistence=%s",
                tenant_id,
                category,
                persistence_str,
            )

        # 5. Update baseline with non-extreme reading (or downweighted reading)
        # Extreme outliers are not fully absorbed into baseline immediately to prevent corruption
        if not is_anomaly:
            baseline_model.update(value, event_time_utc)
            save_baseline(tenant_id, source_ref, category, baseline_model, event_time_utc.isoformat())

        return is_anomaly, explanation


# Global singleton detector instance
detector = AnomalyDetector()


def reset_detector_state_for_tests() -> None:
    """Clears window history for clean test execution."""
    _WINDOW_HISTORY.clear()
