"""
tools/live_feed_daemon.py
─────────────────────────
Generates continuous live telemetry batches and sends them to SaaS on port 8000
so that the dashboard charts update in real-time.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import random
import time
from datetime import datetime, timezone
import uuid

import httpx

from collector.uuidv7 import uuidv7

SAAS_URL = "http://127.0.0.1:8000/v1/ingest"
API_KEY = "key-acme-eu1-dev"
HMAC_SECRET = "secret-acme-eu1"
COLLECTOR_ID = "col-acme-eu-1"


def compute_sig(body: bytes, secret: str) -> str:
    return hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()


def run_feed() -> None:
    step = 0
    client = httpx.Client(timeout=3.0)
    print("Live Telemetry Feeder running against", SAAS_URL)

    while True:
        now_iso = datetime.now(timezone.utc).isoformat()
        t = step * 0.2

        # Realistic sinusoidal diurnal telemetry with subtle noise
        cpu_val = round(35.0 + 10.0 * math.sin(t) + random.uniform(-2, 2), 1)
        mem_val = round(48.0 + 3.0 * math.cos(t * 0.5) + random.uniform(-1, 1), 1)
        disk_val = round(62.0 + (step % 50) * 0.02, 1)
        latency_val = round(28.0 + 5.0 * math.sin(t * 1.5) + random.uniform(-1, 3), 1)
        packet_loss_val = round(max(0.0, 0.1 * math.sin(t) + random.uniform(0, 0.05)), 2)
        bandwidth_val = round(120.0 + 25.0 * math.cos(t) + random.uniform(-5, 5), 1)
        conn_val = 100.0

        source_ref = "h_1234abcd"
        payloads = [
            # Heartbeat every cycle
            {
                "payload_id": str(uuidv7()),
                "schema_version": 1,
                "collector_id": COLLECTOR_ID,
                "event_time_utc": now_iso,
                "source_tz": "Europe/Berlin",
                "sent_time_utc": now_iso,
                "source_ref": source_ref,
                "kind": "heartbeat",
                "severity": "info",
                "context": f"ver=1.0.0 cpu={cpu_val} mem={mem_val} queue=0 cfg=cfg_8a2f",
            },
            # Infrastructure metrics
            {
                "payload_id": str(uuidv7()),
                "schema_version": 1,
                "collector_id": COLLECTOR_ID,
                "event_time_utc": now_iso,
                "source_tz": "Europe/Berlin",
                "sent_time_utc": now_iso,
                "source_ref": source_ref,
                "kind": "metric",
                "category": "cpu",
                "severity": "info",
                "value": cpu_val,
                "unit": "%",
                "window_s": 5,
            },
            {
                "payload_id": str(uuidv7()),
                "schema_version": 1,
                "collector_id": COLLECTOR_ID,
                "event_time_utc": now_iso,
                "source_tz": "Europe/Berlin",
                "sent_time_utc": now_iso,
                "source_ref": source_ref,
                "kind": "metric",
                "category": "memory",
                "severity": "info",
                "value": mem_val,
                "unit": "%",
                "window_s": 5,
            },
            {
                "payload_id": str(uuidv7()),
                "schema_version": 1,
                "collector_id": COLLECTOR_ID,
                "event_time_utc": now_iso,
                "source_tz": "Europe/Berlin",
                "sent_time_utc": now_iso,
                "source_ref": source_ref,
                "kind": "metric",
                "category": "disk",
                "severity": "info",
                "value": disk_val,
                "unit": "%",
                "window_s": 5,
            },
            # Network metrics
            {
                "payload_id": str(uuidv7()),
                "schema_version": 1,
                "collector_id": COLLECTOR_ID,
                "event_time_utc": now_iso,
                "source_tz": "Europe/Berlin",
                "sent_time_utc": now_iso,
                "source_ref": source_ref,
                "kind": "metric",
                "category": "latency",
                "severity": "info",
                "value": latency_val,
                "unit": "ms",
                "window_s": 5,
            },
            {
                "payload_id": str(uuidv7()),
                "schema_version": 1,
                "collector_id": COLLECTOR_ID,
                "event_time_utc": now_iso,
                "source_tz": "Europe/Berlin",
                "sent_time_utc": now_iso,
                "source_ref": source_ref,
                "kind": "metric",
                "category": "packet_loss",
                "severity": "info",
                "value": packet_loss_val,
                "unit": "%",
                "window_s": 5,
            },
            {
                "payload_id": str(uuidv7()),
                "schema_version": 1,
                "collector_id": COLLECTOR_ID,
                "event_time_utc": now_iso,
                "source_tz": "Europe/Berlin",
                "sent_time_utc": now_iso,
                "source_ref": source_ref,
                "kind": "metric",
                "category": "bandwidth",
                "severity": "info",
                "value": bandwidth_val,
                "unit": "Mbps",
                "window_s": 5,
            },
            {
                "payload_id": str(uuidv7()),
                "schema_version": 1,
                "collector_id": COLLECTOR_ID,
                "event_time_utc": now_iso,
                "source_tz": "Europe/Berlin",
                "sent_time_utc": now_iso,
                "source_ref": source_ref,
                "kind": "metric",
                "category": "connectivity",
                "severity": "info",
                "value": conn_val,
                "unit": "%",
                "window_s": 5,
            },
        ]

        # Occasional security summary every 15 steps
        if step % 15 == 0:
            payloads.append({
                "payload_id": str(uuidv7()),
                "schema_version": 1,
                "collector_id": COLLECTOR_ID,
                "event_time_utc": now_iso,
                "source_tz": "Europe/Berlin",
                "sent_time_utc": now_iso,
                "source_ref": source_ref,
                "kind": "security_summary",
                "category": "auth",
                "severity": "info",
                "context": f"0 failed logins in 60s from 1 source (risk 5)",
            })

        body_dict = {"payloads": payloads}
        body_bytes = json.dumps(body_dict).encode("utf-8")
        sig = compute_sig(body_bytes, HMAC_SECRET)

        try:
            resp = client.post(
                SAAS_URL,
                content=body_bytes,
                headers={
                    "Content-Type": "application/json",
                    "X-Api-Key": API_KEY,
                    "X-Signature": sig,
                },
            )
            print(f"Batch {step}: HTTP {resp.status_code}", flush=True)
        except Exception as exc:
            print("Feeder error:", exc, flush=True)

        step += 1
        time.sleep(3.0)


if __name__ == "__main__":
    run_feed()
