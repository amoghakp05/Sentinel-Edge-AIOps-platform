"""
tests/test_phase3.py
────────────────────
Phase 3 Tests:
1. RFC 9562 UUIDv7 compliance and time-ordering.
2. HMAC-SHA256 signature generation and validation.
3. Heartbeat generation with process CPU/mem and queue depth.
4. Egress log hash verification.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import httpx
import pytest
import respx

from collector import egress_log, heartbeat, outbox, sender
from collector.db import get_db
from collector.uuidv7 import uuidv7

UUIDV7_REGEX = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$")


def test_uuidv7_conformance():
    id1 = uuidv7()
    time.sleep(0.005)
    id2 = uuidv7()

    assert UUIDV7_REGEX.match(id1)
    assert UUIDV7_REGEX.match(id2)
    # Monotonically increasing by time
    assert id1 < id2


def test_hmac_signature_generation():
    body = b'{"payloads":[{"id":"test"}]}'
    secret = "test-hmac-key-99"

    sig = sender.compute_signature(body, secret)
    expected = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    assert sig == expected


def test_heartbeat_payload_structure(tmp_db):
    hb = heartbeat.create_heartbeat_payload()
    assert hb["kind"] == "heartbeat"
    assert hb["category"] == "connectivity"
    assert hb["severity"] == "info"
    assert UUIDV7_REGEX.match(hb["payload_id"])
    assert "cpu=" in hb["context"]
    assert "mem=" in hb["context"]
    assert "queue=" in hb["context"]
    assert "cfg=" in hb["context"]


@respx.mock
def test_send_batch_and_ack(tmp_db):
    saas_url = "http://test-saas:8001"
    ingest_url = f"{saas_url}/v1/ingest"

    p = {
        "payload_id": uuidv7(),
        "schema_version": 1,
        "collector_id": "col-acme-eu-1",
        "event_time_utc": "2026-11-20T10:00:00Z",
        "source_tz": "Europe/Berlin",
        "sent_time_utc": "2026-11-20T10:00:00Z",
        "source_ref": "h_9f3a1c2e",
        "kind": "metric",
        "category": "latency",
        "severity": "info",
        "value": 24.5,
        "unit": "ms",
        "window_s": 5,
        "context": "latency nominal",
    }
    pid = outbox.enqueue(p)

    expected_hash = hashlib.sha256(json.dumps(p, sort_keys=True).encode("utf-8")).hexdigest()

    respx.post(ingest_url).mock(
        return_value=httpx.Response(200, json={
            "status": "ok",
            "acked": [{"payload_id": pid, "ack_hash": expected_hash}]
        })
    )

    acked = sender.send_batch(saas_url=saas_url)
    assert acked == 1

    # Outbox should be marked sent
    stats = outbox.get_outbox_stats()
    assert stats["pending_count"] == 0

    # Egress log should record acked and matching hash
    rec = egress_log.get_egress_record(pid)
    assert rec is not None
    assert rec["status"] == "acked"
    assert rec["saas_ack_hash"] == expected_hash
    assert rec["sha256"] == expected_hash
