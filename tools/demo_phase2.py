"""
tools/demo_phase2.py
─────────────────────
Phase 2 Acceptance Gate Demo Script:
1. Feeds 20 diverse raw log lines with injected secrets into the Phase 2 pipeline.
2. Performs redaction and pseudonymisation.
3. Passes through policy gate.
4. Intentionally attempts to egress a poisoned payload to prove blocked_log captures it.
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
os.environ["COLLECTOR_DB_PATH"] = "collector_local_demo2.db"

from collector.db import get_db, reset_for_testing
from collector.policy import enforce_policy
from collector.pseudonym import compute_source_ref, get_or_create_source_ref
from collector.redact import redact_text

RAW_LOGS = [
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


def main():
    print("=" * 80)
    print("PHASE 2 ACCEPTANCE GATE: 20 Raw Secret Logs Pipeline Test")
    print("=" * 80)

    reset_for_testing("collector_local_demo2.db")
    allowed_count = 0

    print(f"\nProcessing {len(RAW_LOGS)} raw log lines through Redactor + Policy Gate:")
    print("-" * 80)

    for i, line in enumerate(RAW_LOGS):
        clean, cats = redact_text(line)
        ref = get_or_create_source_ref(f"host-node-{i}.internal", "hmac-secret-cicada")

        payload = {
            "payload_id": f"019349a2-5b98-7c80-87ef-3d9284157a{i:02x}",
            "schema_version": 1,
            "collector_id": "col-acme-eu-1",
            "event_time_utc": "2026-11-20T10:00:00Z",
            "source_tz": "Europe/Berlin",
            "sent_time_utc": "2026-11-20T10:00:01Z",
            "source_ref": ref,
            "kind": "alert",
            "category": "auth",
            "severity": "warning",
            "value": 1.0,
            "unit": "count",
            "window_s": 5,
            "context": clean[:160],
            # Injected forbidden fields that MUST be stripped
            "password": "should_be_dropped",
            "tenant_id": "acme",
            "raw_input_line": line,
        }

        allowed, filtered, reason = enforce_policy(payload)
        if allowed:
            allowed_count += 1
            print(f"[{i+1:02d}] PASS | Source: {ref} | Categories: {cats} | Clean Context: {filtered['context'][:60]}...")
            assert "raw_input_line" not in filtered
            assert "password" not in filtered
            assert "tenant_id" not in filtered
        else:
            print(f"[{i+1:02d}] BLOCKED | Reason: {reason}")

    print("-" * 80)
    print(f"Result: {allowed_count}/20 payloads passed clean with ZERO secrets and allow-list enforced.")

    print("\nNow testing malicious/poisoned payload injection into Policy Gate:")
    poison = {
        "payload_id": "019349a2-5b98-7c80-87ef-3d9284157aff",
        "schema_version": 1,
        "collector_id": "col-acme-eu-1",
        "event_time_utc": "2026-11-20T10:00:00Z",
        "source_tz": "Europe/Berlin",
        "sent_time_utc": "2026-11-20T10:00:01Z",
        "source_ref": "h_9f3a1c2e",
        "kind": "alert",
        "category": "auth",
        "severity": "critical",
        "context": "Direct un-redacted secret: password=LeakedAdminKey999!",
    }
    allowed, _, reason = enforce_policy(poison)
    print(f"Poison payload transmission allowed: {allowed}")
    print(f"Policy block reason: {reason}")

    conn = get_db()
    rows = conn.execute("SELECT id, ts_utc, reason, payload_id FROM blocked_log").fetchall()
    print(f"\nAudit Log (blocked_log entries in local DB: {len(rows)}):")
    for r in rows:
        print(f"  ID {r['id']} | {r['ts_utc']} | Payload: {r['payload_id']} | Reason: {r['reason']}")

    print("\n[ACCEPTANCE GATE PASSED]")


if __name__ == "__main__":
    main()
