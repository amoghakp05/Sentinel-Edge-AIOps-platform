"""
tests/test_aiops.py
───────────────────
Phase 6 AIOps Anomaly Detection & Explainability Tests:
- Acceptance Gate: CPU spike flagged with full explanation and alert latency < 15s.
- Diurnal baseline: Normal 9 AM morning rise is NOT flagged.
- Noisy normal data: 1 hour of noisy baseline produces zero false alarms.
- Persistence gating: 1-window transient spike is suppressed by 3-of-5 rule.
- Baseline persistence: State survives process/cache restart.
"""

import json
import random
from datetime import datetime, timedelta, timezone
import pytest

from collector.uuidv7 import uuidv7
from saas.aiops.baseline import (
    MetricBaseline,
    get_baseline,
    get_bucket_index,
    reset_baseline_cache_for_tests,
    save_baseline,
)
from saas.aiops.detect import (
    AnomalyDetector,
    compute_robust_zscore,
    detector,
    reset_detector_state_for_tests,
)
from saas.aiops.engine import process_metric_telemetry
from saas.aiops.explain import generate_explanation
from saas.db import init_db
from saas.tenancy import get_scoped_query


@pytest.fixture(autouse=True)
def setup_saas_db(tmp_path, monkeypatch):
    """Isolate SaaS DB for test execution."""
    test_db = tmp_path / "saas_aiops_test.db"
    monkeypatch.setenv("SAAS_DB_PATH", str(test_db))
    monkeypatch.setenv("REGION", "eu")
    init_db("eu")
    reset_baseline_cache_for_tests()
    reset_detector_state_for_tests()
    yield


def test_baseline_state_survives_restart():
    """Baselines persist to SQLite and survive cache eviction/restarts."""
    t0 = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
    base = get_baseline("acme", "h_11223344", "cpu")

    for v in [35.0, 36.0, 34.5, 35.5, 36.5]:
        base.update(v, t0)
    save_baseline("acme", "h_11223344", "cpu", base)

    # Evict in-memory cache to simulate restart
    reset_baseline_cache_for_tests()

    restored = get_baseline("acme", "h_11223344", "cpu")
    med, mad = restored.get_rolling_median_and_mad()
    assert abs(med - 35.5) <= 1.0
    assert len(restored.window) == 5


def test_normal_9am_daily_rise_not_flagged():
    """
    Requirement: Inject a normal 9 am daily rise -> NOT flagged.
    At 9 am, normal diurnal rise to ~65% matches the time-of-day bucket baseline.
    """
    # Monday 09:00 UTC
    monday_9am = datetime(2026, 11, 23, 9, 0, 0, tzinfo=timezone.utc)
    base = get_baseline("acme", "h_11223344", "cpu")

    # Warm up 9 am Monday bucket with historical 65% readings
    for _ in range(10):
        base.update(65.0, monday_9am)
    save_baseline("acme", "h_11223344", "cpu", base)

    # Now evaluate Monday 9am reading of 67.0%
    is_anomaly, explanation = detector.evaluate_metric(
        tenant_id="acme",
        source_ref="h_11223344",
        category="cpu",
        value=67.0,
        event_time_utc=monday_9am,
    )

    # Must NOT be flagged as anomaly
    assert not is_anomaly
    assert explanation is None


def test_one_hour_noisy_normal_data_zero_false_alarms():
    """
    Requirement: Run 1 hour of noisy-but-normal data -> false alarm count at or near 0.
    """
    random.seed(42)
    start_time = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)

    # Pre-warm baseline with 30 nominal samples (mean 40.0)
    for i in range(30):
        t = start_time - timedelta(minutes=30 - i)
        val = 40.0 + random.gauss(0, 1.5)
        detector.evaluate_metric("acme", "h_11223344", "cpu", val, t)

    false_alarms = 0
    # Simulate 60 minutes of normal telemetry with noise
    for minute in range(60):
        t = start_time + timedelta(minutes=minute)
        # Normal fluctuation around 40% with Gaussian noise (std=2.0)
        noisy_val = 40.0 + random.gauss(0, 2.0)
        is_anomaly, _ = detector.evaluate_metric(
            tenant_id="acme",
            source_ref="h_11223344",
            category="cpu",
            value=noisy_val,
            event_time_utc=t,
        )
        if is_anomaly:
            false_alarms += 1

    # False alarms must be 0
    assert false_alarms == 0


def test_transient_single_spike_suppressed_by_persistence_rule():
    """A transient spike lasting only 1 window is suppressed by the 3/5 rule."""
    t0 = datetime(2026, 11, 20, 14, 0, 0, tzinfo=timezone.utc)

    # Establish baseline around 30.0%
    for i in range(20):
        detector.evaluate_metric("acme", "h_11223344", "cpu", 30.0, t0 - timedelta(seconds=20 - i))

    # Single transient spike
    is_anomaly, _ = detector.evaluate_metric(
        tenant_id="acme",
        source_ref="h_11223344",
        category="cpu",
        value=98.0,
        event_time_utc=t0,
    )
    # 1 out of 5 is NOT an anomaly
    assert not is_anomaly


def test_acceptance_gate_cpu_spike_flagged_with_explanation_and_latency():
    """
    ACCEPTANCE GATE:
    A CPU spike produces an anomaly with observed, baseline, z-score and contributing signals;
    a normal daily pattern does not fire; alert latency is logged and under 15 s.
    """
    t0 = datetime(2026, 11, 20, 15, 0, 0, tzinfo=timezone.utc)

    # 1. Establish baseline at 35.0% CPU and 160.0 ms latency
    for i in range(25):
        t_hist = t0 - timedelta(seconds=25 - i)
        detector.evaluate_metric("acme", "h_11223344", "cpu", 35.0, t_hist)
        detector.evaluate_metric("acme", "h_11223344", "latency", 160.0, t_hist)

    # 2. Inject sustained CPU spike (95.0%) across 3 consecutive windows
    spike_time = t0 + timedelta(seconds=5)

    # Window 1
    flagged1, expl1, alert1 = process_metric_telemetry(
        tenant_id="acme",
        source_ref="h_11223344",
        category="cpu",
        value=95.0,
        event_time_utc_str=spike_time.isoformat(),
        now=spike_time + timedelta(seconds=1.2),
    )
    assert not flagged1  # 1/1 not flagged

    # Window 2
    flagged2, expl2, alert2 = process_metric_telemetry(
        tenant_id="acme",
        source_ref="h_11223344",
        category="cpu",
        value=95.0,
        event_time_utc_str=(spike_time + timedelta(seconds=5)).isoformat(),
        now=spike_time + timedelta(seconds=6.1),
    )
    assert not flagged2  # 2/2 not flagged

    # Window 3 (Persistence reached: 3/3)
    alert_now = spike_time + timedelta(seconds=12.5)  # 2.5s after window event time
    flagged3, expl3, alert3 = process_metric_telemetry(
        tenant_id="acme",
        source_ref="h_11223344",
        category="cpu",
        value=95.0,
        event_time_utc_str=(spike_time + timedelta(seconds=10)).isoformat(),
        correlated_metrics={"latency": 180.0, "memory": 60.0},
        now=alert_now,
    )

    # MUST be flagged!
    assert flagged3 is True
    assert expl3 is not None
    assert alert3 is not None

    # Check observed, baseline, z-score
    assert expl3["metric"] == "cpu"
    assert expl3["observed"] == 95.0
    assert abs(expl3["baseline"] - 35.0) <= 2.0
    assert expl3["zscore"] >= 5.0
    assert "3/3" in expl3["persistence"] or "3/5" in expl3["persistence"]

    # Check contributing signals and normalized weights summing to 1.0
    contributing = expl3["contributing"]
    assert len(contributing) >= 1
    assert contributing[0]["signal"] == "cpu"
    total_weights = sum(c["weight"] for c in contributing)
    assert abs(total_weights - 1.0) <= 0.02

    # Check plain English why narrative
    assert "Observed cpu" in expl3["why"]
    assert "robust standard deviations" in expl3["why"]

    # Check Alert Latency Requirement: latency under 15 s
    assert alert3["latency_s"] <= 15.0
    assert alert3["latency_s"] == 2.5  # Exactly 12.5s - 10s = 2.5s

    # Verify written to 'anomalies' and 'events' tables
    anomalies = get_scoped_query("acme", table="anomalies")
    assert len(anomalies) >= 1
    assert anomalies[-1]["category"] == "cpu"
    assert anomalies[-1]["observed"] == 95.0

    alerts = get_scoped_query("acme", table="events", where_clause="kind = 'alert'")
    assert len(alerts) >= 1
    assert alerts[-1]["category"] == "cpu"
    assert alerts[-1]["severity"] == "critical"
