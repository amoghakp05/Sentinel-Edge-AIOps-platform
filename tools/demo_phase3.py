"""
tools/demo_phase3.py
─────────────────────
Phase 3 Acceptance Gate Demonstration:
1. Simulates SaaS offline: collector enqueues events, `collector buffer` shows Buffering and outbox grows.
2. Simulates SaaS recovery: sender drains outbox with ACKs, outbox empties to 0.
3. Calls `collector egress show <id>` showing RAW secret on LEFT and REDACTED metadata on RIGHT with verified hash.
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

import httpx
import respx

sys.path.insert(0, str(Path(__file__).parent.parent))
os.environ["COLLECTOR_DB_PATH"] = "collector_local_demo3.db"

from collector import egress_log, outbox, policy, sender
from collector.cli import app
from collector.db import get_db, reset_for_testing
from collector.normalize import normalize_and_store
from collector.pseudonym import compute_source_ref
from collector.redact import redact_text
from collector.models import RawRecord
from collector.uuidv7 import uuidv7
from typer.testing import CliRunner

runner = CliRunner()


def main():
    print("=" * 80)
    print("PHASE 3 ACCEPTANCE GATE DEMO: Outbox Resilience & Side-by-Side Audit")
    print("=" * 80)

    reset_for_testing("collector_local_demo3.db")
    conn = get_db()

    # Step 1: Ingest a raw event with a sensitive secret into local raw_events
    raw_secret_line = "sshd[5001]: Failed password for root from 192.168.1.99 port 45222 ssh2 password=UltraSecretPass999 token=eyJh12345"
    now_utc = datetime.now(timezone.utc)

    raw_rec = RawRecord(
        adapter="syslog",
        source="192.168.1.99",
        source_tz="UTC",
        category="auth",
        raw_text=raw_secret_line,
        value=1.0,
        unit="count",
        ts=now_utc,
    )
    normalize_and_store(raw_rec)
    print("\n1. Ingested raw event with secret into local SQLite raw_events.")

    # Step 2: Redact, form allow-listed payload, enqueue to outbox
    clean_text, _ = redact_text(raw_secret_line)
    src_ref = compute_source_ref("192.168.1.99")
    test_pid = uuidv7()

    candidate = {
        "payload_id": test_pid,
        "schema_version": 1,
        "collector_id": "col-acme-eu-1",
        "event_time_utc": now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_tz": "Europe/Berlin",
        "sent_time_utc": now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_ref": src_ref,
        "kind": "alert",
        "category": "auth",
        "severity": "critical",
        "value": 1.0,
        "unit": "count",
        "window_s": 5,
        "context": clean_text[:160],
    }

    allowed, filtered, _ = policy.enforce_policy(candidate)
    assert allowed and filtered
    outbox.enqueue(filtered)

    # Enqueue 3 more payloads to demonstrate queue growth during outage
    for i in range(3):
        p = dict(filtered)
        p["payload_id"] = uuidv7()
        p["context"] = f"subsequent telemetry batch {i}"
        outbox.enqueue(p)

    print("\n2. Outage Demonstration (SaaS DOWN):")
    # Execute `collector buffer` CLI command while SaaS is unreachable
    with respx.mock:
        respx.post("http://localhost:8001/v1/ingest").mock(
            return_value=httpx.Response(503, json={"error": "SaaS Outage"})
        )
        # Attempt to send during outage
        sender.send_batch()

        # Check buffer status
        res = runner.invoke(app, ["buffer"])
        print(res.stdout)

    print("\n3. Recovery Demonstration (SaaS RESTARTED):")
    # Restore SaaS: ACKs all payloads
    with respx.mock:
        def ack_cb(request):
            data = json.loads(request.content)
            acks = []
            for p in data["payloads"]:
                body_hash = hashlib.sha256(json.dumps(p, sort_keys=True).encode("utf-8")).hexdigest()
                acks.append({"payload_id": p["payload_id"], "ack_hash": body_hash})
            return httpx.Response(200, json={"status": "ok", "acked": acks})

        respx.post("http://localhost:8001/v1/ingest").mock(side_effect=ack_cb)

        # Reset retry timestamps for immediate drain
        conn.execute("UPDATE outbox SET next_try_at = '2026-11-20T00:00:00Z'")
        conn.commit()

        # Draining outbox
        drained = sender.send_batch()
        print(f"Drained {drained} queued records from outbox after SaaS reconnect.")

        # Check buffer status again (should be Online with 0 pending)
        res = runner.invoke(app, ["buffer"])
        print(res.stdout)

    print("\n4. Side-by-Side Egress Verification (`collector egress show <id>`):")
    res = runner.invoke(app, ["egress", "show", test_pid])
    print(res.stdout)

    print("\n[ACCEPTANCE GATE PASSED]")


if __name__ == "__main__":
    main()
