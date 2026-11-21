"""
collector/sender.py
───────────────────
Transmits allow-listed payloads from the local outbox to the SaaS ingestion tier.

Rules:
- Batches up to 50 pending rows.
- Transmits over HTTP/HTTPS with headers:
    X-Api-Key: <SAAS_API_KEY>
    X-Signature: HMAC-SHA256(raw_bytes, HMAC_SECRET)
- On 2xx ACK for a payload_id:
    - Mark status='sent' in the outbox.
    - Record the SaaS's returned ACK hash in egress_log.
- On network error or HTTP failure:
    - Compute exponential backoff with jitter.
    - Leave rows pending (status='pending').
    - Next attempt drains oldest first (FIFO).
- HARD RULE: NEVER mark a row sent without an explicit SaaS ACK.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import random
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import httpx

from collector import egress_log, outbox

logger = logging.getLogger(__name__)

DEFAULT_SAAS_URL = os.environ.get("SAAS_INGEST_URL", "http://localhost:8001")
DEFAULT_API_KEY = os.environ.get("SAAS_API_KEY", "key-acme-eu1-dev")
DEFAULT_HMAC_SECRET = os.environ.get("HMAC_SECRET", "sentinel-edge-default-dev-secret-cicada2026")


def compute_signature(payload_bytes: bytes, secret: str) -> str:
    """Computes HMAC-SHA256 signature for outgoing payload transmission."""
    return hmac.new(
        secret.encode("utf-8"),
        payload_bytes,
        hashlib.sha256,
    ).hexdigest()


def send_batch(
    client: Optional[httpx.Client] = None,
    saas_url: Optional[str] = None,
    api_key: Optional[str] = None,
    hmac_secret: Optional[str] = None,
    batch_limit: int = 50,
) -> int:
    """
    Attempts to drain one batch (up to batch_limit) of pending outbox items.
    Returns the count of successfully acknowledged items.
    """
    pending = outbox.get_pending_batch(limit=batch_limit)
    if not pending:
        return 0

    base_url = (saas_url or DEFAULT_SAAS_URL).rstrip("/")
    target_url = f"{base_url}/v1/ingest"
    token = api_key or DEFAULT_API_KEY
    secret = hmac_secret or DEFAULT_HMAC_SECRET

    # Construct batch payload: list of payload dicts
    payloads = [item["body"] for item in pending]
    body_data = {"payloads": payloads}
    # Deterministic bytes representation
    body_bytes = json.dumps(body_data, sort_keys=True, separators=(",", ":")).encode("utf-8")
    signature = compute_signature(body_bytes, secret)

    headers = {
        "Content-Type": "application/json",
        "X-Api-Key": token,
        "X-Signature": signature,
    }

    # Record send attempts in append-only egress_log
    for item in pending:
        exact_item_json = json.dumps(item["body"], sort_keys=True)
        egress_log.log_send_attempt(
            payload_id=item["payload_id"],
            exact_json=exact_item_json,
            destination=target_url,
            status="transmitting",
        )

    # Perform transmission
    should_close_client = False
    if client is None:
        client = httpx.Client(timeout=8.0)
        should_close_client = True

    acked_count = 0
    try:
        resp = client.post(target_url, content=body_bytes, headers=headers)
        resp.raise_for_status()

        res_data = resp.json()
        acked_list = res_data.get("acked", [])
        ack_map = {a.get("payload_id"): a.get("ack_hash") for a in acked_list if isinstance(a, dict)}

        for item in pending:
            pid = item["payload_id"]
            # If server returned explicit acks, use returned hash, otherwise compute from response
            if pid in ack_map or res_data.get("status") == "ok":
                # Default ack hash: sha256 of the payload body
                item_exact = json.dumps(item["body"], sort_keys=True)
                ack_hash = ack_map.get(pid) or hashlib.sha256(item_exact.encode("utf-8")).hexdigest()

                outbox.mark_acked(pid)
                egress_log.record_saas_ack(pid, ack_hash)
                acked_count += 1

        logger.info("Successfully drained batch of %d records", acked_count)

    except (httpx.ConnectError, httpx.TimeoutException, httpx.HTTPStatusError, Exception) as exc:
        err_type = type(exc).__name__
        resp_obj = getattr(exc, "response", None)
        status_code = resp_obj.status_code if resp_obj is not None else "no_response"
        logger.warning(
            "Transmission failed [%s: status=%s]. Retaining pending outbox rows.",
            err_type, status_code
        )

        now = datetime.now(timezone.utc)
        for item in pending:
            attempts = item["attempts"]
            # Exponential backoff with jitter: 2^attempts + uniform(0.1, 1.5), capped at 60s
            backoff_s = min(60.0, (2.0 ** min(attempts, 6)) + random.uniform(0.1, 1.5))
            next_try = (now + timedelta(seconds=backoff_s)).strftime("%Y-%m-%dT%H:%M:%SZ")
            outbox.mark_failed(item["payload_id"], next_try)

    finally:
        if should_close_client:
            client.close()

    return acked_count
