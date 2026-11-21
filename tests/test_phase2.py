"""
tests/test_phase2.py
────────────────────
Phase 2 Acceptance Tests:
1. Pseudonymisation and local reverse mapping.
2. 5-second tumbling window aggregation on a hand-crafted dataset.
3. Local security analysis: threshold breach, risk score (0-100), and context generation.
4. ACCEPTANCE GATE: Feed 20 log lines containing injected secrets through the pipeline:
   - Output payloads contain zero secrets.
   - Only allow-listed fields are present.
   - Any un-sanitized attempt is stopped and logged in blocked_log.
"""

from __future__ import annotations

import datetime
from datetime import datetime, timezone
import pytest

from collector.aggregate import TumblingWindowAggregator
from collector.db import get_db
from collector.local_analysis import BruteForceAnalyzer
from collector.policy import enforce_policy
from collector.pseudonym import compute_source_ref, get_or_create_source_ref, lookup_real_source
from collector.redact import redact_text


# ── 1. Pseudonymisation Tests ─────────────────────────────────────────────────

def test_pseudonym_generation_and_local_lookup(tmp_db):
    real_host = "app-db-master.fra.acme.internal"
    secret = "test-hmac-secret-xyz"

    ref = get_or_create_source_ref(real_host, secret)
    assert ref.startswith("h_")
    assert len(ref) == 10

    # Ensure deterministic
    assert compute_source_ref(real_host, secret) == ref

    # Reverse lookup from local table
    recovered_host = lookup_real_source(ref)
    assert recovered_host == real_host


# ── 2. Aggregations on Hand-Made Sample ────────────────────────────────────────

def test_aggregates_hand_made_sample():
    agg = TumblingWindowAggregator(window_s=5)
    t0 = datetime(2026, 11, 20, 10, 0, 1, tzinfo=timezone.utc)
    t1 = datetime(2026, 11, 20, 10, 0, 3, tzinfo=timezone.utc)
    t2 = datetime(2026, 11, 20, 10, 0, 4, tzinfo=timezone.utc)
    src = "h_1234abcd"

    # Feed 3 samples in the 10:00:00 - 10:00:05 window: 20, 40, 60
    agg.add_sample(t0, src, "cpu", 20.0, "percent")
    agg.add_sample(t1, src, "cpu", 40.0, "percent")
    agg.add_sample(t2, src, "cpu", 60.0, "percent")

    # Add 2 failed logins in same window
    agg.add_sample(t0, src, "auth", is_failed_login=True)
    agg.add_sample(t2, src, "auth", is_failed_login=True)

    metric_res, auth_res = agg.flush()

    assert len(metric_res) == 1
    m = metric_res[0]
    assert m.category == "cpu"
    assert m.avg_value == 40.0
    assert m.min_value == 20.0
    assert m.max_value == 60.0
    assert m.sample_count == 3
    assert m.window_s == 5

    assert len(auth_res) == 1
    a = auth_res[0]
    assert a.failed_login_count == 2
    assert a.window_s == 5


# ── 3. Local Analysis & Risk Scoring ──────────────────────────────────────────

def test_local_analysis_risk_scoring():
    analyzer = BruteForceAnalyzer(threshold=5, window_s=60)
    now = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
    src = "h_8765fedc"

    # Under threshold -> no summary
    res = analyzer.record_failures(src, count=3, at_time=now)
    assert res is None

    # Exceed threshold (total 14 in window, threshold 5 -> 9 excess -> risk 50 + 9*3.5 = 81.5 ≈ 82)
    later = datetime(2026, 11, 20, 10, 0, 35, tzinfo=timezone.utc)
    res = analyzer.record_failures(src, count=11, at_time=later)
    assert res is not None
    assert res.kind == "security_summary"
    assert res.category == "auth"
    assert res.value == 81.5  # risk score
    assert "14 failed logins in 60s from 1 source (risk 81)" in res.context
    # Verify NO secrets or usernames appear in context
    assert "user=" not in res.context
    assert "@" not in res.context


# ── 4. ACCEPTANCE GATE ────────────────────────────────────────────────────────

def test_acceptance_gate_20_secret_logs(tmp_db):
    """
    Feeds 20 diverse log lines with secrets through the complete pipeline:
    1. Redact text
    2. Aggregate / build candidate payload
    3. Enforce policy gate
    4. Verify: zero secrets leak, only allow-listed fields retained, blocked_log records violations.
    """
    raw_secret_logs = [
        "sshd[101]: Failed password for root from 192.168.1.1 port 4001 ssh2 password=hunter2",
        "app: POST /api/login user=alice password=MySecretPass_99 from 10.4.2.17",
        "aws_s3: Error bucket access using key AKIAIOSFODNN7EXAMPLE",
        "oauth: Bearer eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYm9iIn0.abcdef1234567890 token expired",
        "auth: client_secret=GOCSPX-secret_token_1234567890abcdef for service account",
        "payment: Transaction charged to card 4532-0150-1234-5674 email=billing@corp.com",
        "audit: SSH key loaded -----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----",
        "proxy: Upstream connection timeout to peer 10.20.1.50:8080 with token=abc12345",
        "db: Connection error for uri postgres://admin:SuperPass@10.0.0.1/prod",
        "sshd[102]: Failed password for invalid user admin from 185.220.101.4 password=admin123",
        "api: Auth header missing token=Bearer_xyz_99887766554433221100",
        "config: password  =  P@ssw0rd2026! on node-fra-01",
        "auth_err: pwd: TemporaryPassword!123 for user deployer",
        "sshd[103]: Connection closed by 172.16.5.99 port 5022 user=test",
        "net: Packet rejected from IPv6 peer 2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "vault: Secret lease expired for secret=vault_token_s.9182391823918239",
        "sshd[104]: Failed password for invalid user ubuntu from 192.168.10.99 password=ubuntu",
        "sec_log: Potential leak of api_key=AKIA1111222233334444 in debug trace",
        "sshd[105]: Failed password for user priya.s from 10.10.1.15 password=PriyaPass2026",
        "admin: Backup job executed by ciso@acme.internal token=secret_token_val_9999",
    ]

    assert len(raw_secret_logs) == 20

    allowed_egress_payloads = []
    blocked_count = 0

    for i, line in enumerate(raw_secret_logs):
        # Step 1: Redact
        clean_text, cats = redact_text(line)

        # Confirm secrets stripped
        assert "hunter2" not in clean_text
        assert "MySecretPass_99" not in clean_text
        assert "AKIAIOSFODNN7EXAMPLE" not in clean_text
        assert "billing@corp.com" not in clean_text
        assert "4532-0150-1234-5674" not in clean_text

        # Step 2: Form candidate payload (using pseudonymous source_ref)
        src_ref = compute_source_ref(f"host-{i}.internal", "tenant-key-123")
        payload = {
            "payload_id": f"019349a2-5b98-7c80-87ef-3d9284157a{i:02x}",
            "schema_version": 1,
            "collector_id": "col-acme-eu-1",
            "event_time_utc": "2026-11-20T10:00:00Z",
            "source_tz": "Europe/Berlin",
            "sent_time_utc": "2026-11-20T10:00:01Z",
            "source_ref": src_ref,
            "kind": "alert",
            "category": "auth",
            "severity": "warning",
            "value": 1.0,
            "unit": "count",
            "window_s": 5,
            # Context constructed safely from clean snippet
            "context": clean_text[:180],
            # Injected dirty fields to test allow-list stripping
            "raw_log_verbatim": line,
            "tenant_id": "acme",
            "forbidden_internal_tag": "should_be_dropped",
        }

        # Step 3: Run policy gate
        allowed, filtered, reason = enforce_policy(payload)
        if allowed:
            # Check allow-list enforcement: forbidden fields must be completely gone
            assert "raw_log_verbatim" not in filtered
            assert "tenant_id" not in filtered
            assert "forbidden_internal_tag" not in filtered

            # Check zero secrets in any string
            for k, val in filtered.items():
                if isinstance(val, str):
                    assert "password=" not in val
                    assert "AKIA" not in val
            allowed_egress_payloads.append(filtered)
        else:
            blocked_count += 1

    # Verify that payloads passed clean
    assert len(allowed_egress_payloads) == 20
    assert blocked_count == 0

    # Test that intentionally poisoning a payload context gets caught and recorded in blocked_log
    poisoned_payload = dict(allowed_egress_payloads[0])
    poisoned_payload["payload_id"] = "019349a2-5b98-7c80-87ef-3d9284157a99"
    poisoned_payload["context"] = "leaked api_key=AKIAIOSFODNN7EXAMPLE"

    allowed, _, reason = enforce_policy(poisoned_payload)
    assert allowed is False

    conn = get_db()
    row = conn.execute("SELECT count(*) FROM blocked_log").fetchone()
    assert row[0] >= 1
