"""
tests/test_correlate.py
───────────────────────
Phase 7 Correlation & Recommendation Engine Tests:
- Acceptance Gate: 5 or more alerts collapsed into 1 incident with root cause candidate and recommendation reasoning path.
- Multi-signal correlation: latency + packet_loss + failed_logins -> 1 incident, suppressed_count >= 2.
- Sliding 2-minute window: alerts within 120s fold into open incident; alerts past 120s spawn separate incident.
- Recommendation rules: verify pattern matching, signals, confidence, and reasoning steps.
"""

from datetime import datetime, timedelta, timezone
import pytest

from collector.uuidv7 import uuidv7
from saas.aiops.correlate import correlate_alert
from saas.aiops.recommend import evaluate_recommendations
from saas.db import get_connection, init_db
from saas.tenancy import get_scoped_query


@pytest.fixture(autouse=True)
def setup_saas_db(tmp_path, monkeypatch):
    """Isolate SaaS DB for test execution."""
    test_db = tmp_path / "saas_correlate_test.db"
    monkeypatch.setenv("SAAS_DB_PATH", str(test_db))
    monkeypatch.setenv("REGION", "eu")
    init_db("eu")
    yield


def test_multi_alert_correlation_into_single_incident():
    """
    Requirement 4: inject latency + packet loss + failed logins at the same time ->
    exactly one incident, suppressed_count >= 2, correct root cause candidate,
    recommendation with reasoning path.
    """
    t0 = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)

    # 1. Alert 1: latency
    r1 = correlate_alert(
        tenant_id="acme",
        payload_id=uuidv7(),
        category="latency",
        severity="warning",
        context="Latency elevated to 185ms",
        event_time_utc=t0.isoformat(),
        now=t0,
    )
    assert r1["action"] == "created"
    inc_id = r1["incident_id"]

    # 2. Alert 2: packet loss (5 seconds later)
    r2 = correlate_alert(
        tenant_id="acme",
        payload_id=uuidv7(),
        category="packet_loss",
        severity="critical",
        context="Packet loss spike 4.5%",
        event_time_utc=(t0 + timedelta(seconds=5)).isoformat(),
        now=t0 + timedelta(seconds=5),
    )
    assert r2["action"] == "updated"
    assert r2["incident_id"] == inc_id
    assert r2["suppressed_count"] == 1

    # 3. Alert 3: failed logins (auth burst 10 seconds later)
    r3 = correlate_alert(
        tenant_id="acme",
        payload_id=uuidv7(),
        category="auth",
        severity="critical",
        context="14 failed logins in 60s from 1 source",
        event_time_utc=(t0 + timedelta(seconds=10)).isoformat(),
        now=t0 + timedelta(seconds=10),
    )
    assert r3["action"] == "updated"
    assert r3["incident_id"] == inc_id
    assert r3["suppressed_count"] >= 2

    # Query DB to ensure EXACTLY ONE incident exists
    incidents = get_scoped_query("acme", table="incidents")
    assert len(incidents) == 1
    inc = incidents[0]

    assert inc["id"] == inc_id
    assert inc["severity"] == "critical"  # Escalated to critical
    assert inc["suppressed_count"] >= 2

    # Upstream root cause candidate should be network device tier
    assert "network device" in inc["root_cause_candidate"].lower() or "sw-core" in inc["root_cause_candidate"].lower()

    # Verify recommendations
    recs = get_scoped_query("acme", table="recommendations", where_clause="incident_id = ?", params=[inc_id])
    assert len(recs) >= 1
    patterns = [r["pattern"] for r in recs]
    assert "link_congestion_or_fault" in patterns


def test_acceptance_gate_five_alerts_collapse_into_one_incident():
    """
    ACCEPTANCE GATE:
    Five or more alerts become one incident with a root cause candidate
    and a recommendation whose reasoning path lists the signals that led to it.
    """
    t0 = datetime(2026, 11, 20, 11, 0, 0, tzinfo=timezone.utc)

    alert_categories = [
        ("latency", "warning", "Latency spiked to 210ms"),
        ("packet_loss", "critical", "Packet loss reached 5.2%"),
        ("bandwidth", "warning", "Bandwidth dropped to 2.1 Mbps"),
        ("cpu", "warning", "Host CPU elevated to 78%"),
        ("auth", "critical", "Security summary: 20 failed logins"),
    ]

    for idx, (cat, sev, ctx) in enumerate(alert_categories):
        t_alert = t0 + timedelta(seconds=idx * 15)  # All within 60s (< 120s window)
        res = correlate_alert(
            tenant_id="acme",
            payload_id=uuidv7(),
            category=cat,
            severity=sev,
            context=ctx,
            event_time_utc=t_alert.isoformat(),
            now=t_alert,
        )

    # Must result in EXACTLY ONE incident
    incidents = get_scoped_query("acme", table="incidents")
    assert len(incidents) == 1
    inc = incidents[0]

    # Verify root cause candidate is selected
    assert inc["root_cause_candidate"] is not None
    assert len(inc["root_cause_candidate"]) > 0

    # Verify suppressed count folded in at least 4 alerts (1 primary + 4 suppressed)
    assert inc["suppressed_count"] >= 4

    # Verify recommendations and reasoning path
    recs = get_scoped_query("acme", table="recommendations", where_clause="incident_id = ?", params=[inc["id"]])
    assert len(recs) >= 1

    rec = recs[0]
    assert rec["likely_cause"] is not None
    assert rec["action"] is not None

    import json
    reasoning_path = json.loads(rec["reasoning_json"])
    assert isinstance(reasoning_path, list)
    assert len(reasoning_path) >= 3

    # Reasoning path explicitly mentions signals that led to it
    signals = json.loads(rec["signals_json"])
    assert len(signals) >= 1
    found_signal_in_reasoning = any(
        any(sig in step.lower() for sig in signals)
        for step in reasoning_path
    )
    assert found_signal_in_reasoning is True


def test_sliding_window_expiration():
    """Alerts separated by > 120 seconds form separate incidents."""
    t0 = datetime(2026, 11, 20, 12, 0, 0, tzinfo=timezone.utc)

    # Alert 1 at T=0
    r1 = correlate_alert("acme", uuidv7(), "cpu", "critical", "CPU 95%", t0.isoformat(), now=t0)
    assert r1["action"] == "created"

    # Alert 2 at T+150s (> 120s window)
    t_later = t0 + timedelta(seconds=150)
    r2 = correlate_alert("acme", uuidv7(), "cpu", "critical", "CPU 96%", t_later.isoformat(), now=t_later)
    assert r2["action"] == "created"
    assert r2["incident_id"] != r1["incident_id"]

    incidents = get_scoped_query("acme", table="incidents")
    assert len(incidents) == 2


def test_recommendation_rules():
    """Verifies all rule triggers produce correct patterns and reasoning paths."""
    # 1. Link congestion rule
    recs1 = evaluate_recommendations("inc-1", {"latency", "packet_loss"})
    assert any(r["pattern"] == "link_congestion_or_fault" for r in recs1)
    rec1 = [r for r in recs1 if r["pattern"] == "link_congestion_or_fault"][0]
    assert "rerouting" in rec1["action"]
    assert len(rec1["reasoning_path"]) == 4

    # 2. Brute force rule
    recs2 = evaluate_recommendations("inc-2", {"cpu", "auth"})
    assert any(r["pattern"] == "brute_force_abuse" for r in recs2)
    rec2 = [r for r in recs2 if r["pattern"] == "brute_force_abuse"][0]
    assert "rate-limiting" in rec2["action"]

    # 3. Memory leak rule
    recs3 = evaluate_recommendations("inc-3", {"memory"})
    assert any(r["pattern"] == "memory_leak" for r in recs3)
    rec3 = [r for r in recs3 if r["pattern"] == "memory_leak"][0]
    assert "restart" in rec3["action"]

    # 4. Upstream outage rule
    recs4 = evaluate_recommendations("inc-4", {"connectivity", "latency"})
    assert any(r["pattern"] == "upstream_outage" for r in recs4)
    rec4 = [r for r in recs4 if r["pattern"] == "upstream_outage"][0]
    assert "router" in rec4["likely_cause"].lower()
