"""
saas/aiops/recommend.py
───────────────────────
AIOps Explainable Recommendation Engine.

Transparent rule table mapping multi-signal incident patterns to actionable,
reversible recommendations:
1. Link Congestion / Interface Fault: latency up + packet loss up
2. Brute Force / Abuse Attack: cpu up + failed logins / auth burst
3. Probable Memory Leak: memory rising steadily with no drop
4. Upstream Outage: collector offline + network latency anomaly

Each recommendation stores:
- pattern: matched pattern key
- likely_cause: human-readable explanation
- action: concrete remediation step
- signals: signals evaluated
- confidence: computed from signal strength and correlation
- reasoning_path: ordered list of steps leading to the recommendation
"""

from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from saas.db import get_connection

logger = logging.getLogger(__name__)


# Transparent recommendation rules
RULES = [
    {
        "id": "link_congestion_or_fault",
        "required_signals": {"latency", "packet_loss"},
        "likely_cause": "Link congestion or physical interface fault on upstream network path",
        "action": "Check interface errors on network device, consider dynamic traffic rerouting",
        "base_confidence": 0.92,
        "reasoning_template": [
            "Detected elevated latency exceeding fair/poor thresholds on monitored path.",
            "Observed concurrent packet loss rise on the same network path.",
            "Correlation indicates transport-layer congestion rather than application-layer failure.",
            "Recommended action: Inspect physical interface counters and initiate link rerouting.",
        ],
    },
    {
        "id": "brute_force_abuse",
        "required_signals": {"cpu", "auth"},
        "likely_cause": "Repeated authentication failure burst causing CPU exhaustion / credential stuffing attack",
        "action": "Review source IPs, apply edge rate-limiting and temporary account lockout",
        "base_confidence": 0.95,
        "reasoning_template": [
            "Detected sudden burst of failed login attempts within window.",
            "Observed concurrent CPU spike driven by cryptographic password hashing overhead.",
            "Correlation matches credential stuffing / brute-force authentication pattern.",
            "Recommended action: Implement immediate edge rate-limiting and IP filtering.",
        ],
    },
    {
        "id": "memory_leak",
        "required_signals": {"memory"},
        "likely_cause": "Unbounded heap memory accumulation / probable application memory leak",
        "action": "Investigate heap allocation profiles and schedule controlled graceful container restart",
        "base_confidence": 0.88,
        "reasoning_template": [
            "Observed continuous memory growth exceeding threshold without GC reclamation.",
            "No corresponding increase in request throughput to justify memory consumption.",
            "Pattern aligns with uncollected resource references or thread leak.",
            "Recommended action: Capture heap dump and schedule rolling service restart.",
        ],
    },
    {
        "id": "upstream_outage",
        "required_signals": {"connectivity", "latency"},
        "likely_cause": "Upstream network connectivity loss or router failure",
        "action": "Check the network path first before restarting host services",
        "base_confidence": 0.94,
        "reasoning_template": [
            "Collector heartbeat or service connectivity ceased reporting.",
            "Preceding network telemetry exhibited severe latency degradation.",
            "Correlation indicates upstream gateway or transit route interruption.",
            "Recommended action: Verify edge router status and network routing tables.",
        ],
    },
]


def evaluate_recommendations(
    incident_id: str,
    signals: Set[str],
    severity: str = "critical",
) -> List[Dict[str, Any]]:
    """
    Evaluates incident signals against the transparent rule table.
    Generates structured recommendations with confidence and reasoning paths.
    """
    recommendations: List[Dict[str, Any]] = []

    for rule in RULES:
        req = rule["required_signals"]
        if req.issubset(signals):
            # Matched rule
            conf = rule["base_confidence"]
            if severity.lower() == "critical":
                conf = min(0.99, conf + 0.03)

            reasoning_steps = list(rule["reasoning_template"])
            used_signals = sorted(list(req.intersection(signals)))

            rec = {
                "incident_id": incident_id,
                "pattern": rule["id"],
                "likely_cause": rule["likely_cause"],
                "action": rule["action"],
                "signals": used_signals,
                "confidence": round(conf, 2),
                "reasoning_path": reasoning_steps,
            }
            recommendations.append(rec)

    # Fallback generic recommendation if no specific multi-signal rule matched
    if not recommendations and signals:
        primary_signal = sorted(list(signals))[0]
        recommendations.append({
            "incident_id": incident_id,
            "pattern": f"isolated_{primary_signal}_anomaly",
            "likely_cause": f"Elevated {primary_signal} anomaly exceeding baseline",
            "action": f"Inspect logs and resource utilization for {primary_signal}",
            "signals": [primary_signal],
            "confidence": 0.75,
            "reasoning_path": [
                f"Observed persistent anomaly in {primary_signal}.",
                "No secondary correlating signals detected within window.",
                f"Recommended action: Review service telemetry and component metrics for {primary_signal}.",
            ],
        })

    return recommendations


def persist_recommendations(
    incident_id: str,
    recommendations: List[Dict[str, Any]],
    conn: Optional[Any] = None,
) -> None:
    """Stores recommendations in the SQLite recommendations table."""
    close_after = False
    if conn is None:
        conn = get_connection()
        close_after = True

    try:
        conn.execute("DELETE FROM recommendations WHERE incident_id = ?", (incident_id,))

        for rec in recommendations:
            signals_json = json.dumps(rec.get("signals", []))
            reasoning_json = json.dumps(rec.get("reasoning_path", []))
            conn.execute(
                """
                INSERT INTO recommendations (
                    incident_id, pattern, likely_cause, action,
                    signals_json, confidence, reasoning_json
                )
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    incident_id,
                    rec["pattern"],
                    rec["likely_cause"],
                    rec["action"],
                    signals_json,
                    rec["confidence"],
                    reasoning_json,
                ),
            )
    finally:
        if close_after:
            conn.close()
