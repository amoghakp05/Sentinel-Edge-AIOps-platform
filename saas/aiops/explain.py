"""
saas/aiops/explain.py
─────────────────────
AIOps Root-Cause Explainability Engine.

Generates structured, human-readable explanations for every detected anomaly:
{
  "metric": "cpu",
  "observed": 94.5,
  "baseline": 42.0,
  "zscore": 5.82,
  "persistence": "3/5",
  "contributing": [
    {"signal": "cpu", "weight": 0.75},
    {"signal": "latency", "weight": 0.25}
  ],
  "confidence": 0.92,
  "why": "Observed cpu of 94.5% is 5.82 robust standard deviations above baseline (42.0%). Persisted in 3 of last 5 windows."
}

Rules Enforced:
- Contributing weights are derived from each signal's standardized deviation, normalized to 1.0.
- Explanations are written in clear, plain English.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def compute_confidence(zscore: float, exceeded_count: int, total_windows: int) -> float:
    """Computes confidence score [0.0..1.0] from z-score magnitude and persistence ratio."""
    abs_z = abs(zscore)
    # Base confidence from z-score (sigmoid-like scaling: 3.0 -> 0.75, 5.0 -> 0.95, 8.0 -> 0.99)
    if abs_z >= 7.0:
        base_conf = 0.98
    elif abs_z >= 5.0:
        base_conf = 0.92
    elif abs_z >= 4.0:
        base_conf = 0.85
    elif abs_z >= 3.0:
        base_conf = 0.75
    else:
        base_conf = 0.60

    # Boost by persistence ratio
    persistence_factor = exceeded_count / max(1, total_windows)
    final_conf = min(0.99, base_conf * (0.8 + 0.2 * persistence_factor))
    return round(final_conf, 2)


def generate_explanation(
    metric: str,
    observed: float,
    baseline: float,
    zscore: float,
    persistence_ratio: str,
    exceeded_count: int = 3,
    total_windows: int = 5,
    correlated_signals: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """
    Constructs a complete explainability payload for a detected anomaly.

    Weights come from each signal's standardized deviation, normalized to 1.0.
    """
    # 1. Calculate contributing weights
    # Primary signal deviation
    signal_devs: Dict[str, float] = {metric: max(0.1, abs(zscore))}

    # Correlated signals deviations (if provided)
    if correlated_signals:
        for sig_name, sig_z in correlated_signals.items():
            if sig_name != metric:
                signal_devs[sig_name] = max(0.05, abs(sig_z))

    total_dev = sum(signal_devs.values())
    raw_weights = {k: v / total_dev for k, v in signal_devs.items()}

    # Normalize weights so sum is exactly 1.0
    contributing: List[Dict[str, Any]] = []
    accumulated_weight = 0.0

    sorted_signals = sorted(raw_weights.items(), key=lambda kv: kv[1], reverse=True)
    for idx, (sig, w) in enumerate(sorted_signals):
        if idx == len(sorted_signals) - 1:
            # Last item absorbs rounding difference so sum == 1.0
            final_w = round(max(0.01, 1.0 - accumulated_weight), 2)
        else:
            final_w = round(w, 2)
            accumulated_weight += final_w

        contributing.append({"signal": sig, "weight": final_w})

    confidence = compute_confidence(zscore, exceeded_count, total_windows)

    # 2. Construct plain English explanation
    direction = "above" if zscore >= 0 else "below"
    why = (
        f"Observed {metric} ({observed:.1f}) is {abs(zscore):.2f} robust standard deviations {direction} "
        f"blended baseline ({baseline:.1f}). Anomaly persisted across {persistence_ratio} evaluation windows."
    )

    return {
        "metric": metric,
        "observed": round(observed, 2),
        "baseline": round(baseline, 2),
        "zscore": round(zscore, 2),
        "persistence": persistence_ratio,
        "contributing": contributing,
        "confidence": confidence,
        "why": why,
    }
