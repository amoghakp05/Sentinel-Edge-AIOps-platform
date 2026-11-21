"""
tools/demo_phase1.py
─────────────────────
Phase 1 end-to-end demonstration script.

Runs fully in-process (no HTTP server needed):
  1. Generates 20 ticks of simulated telemetry including injected fake secrets.
  2. Runs normalize_and_store() for every record.
  3. Prints a formatted raw tail showing secrets visible in the local DB.

Usage:
  python tools/demo_phase1.py
"""
from __future__ import annotations

import os
import random
import sys
from datetime import datetime, timezone
from pathlib import Path

# Ensure the project root is on PYTHONPATH when run from tools/
sys.path.insert(0, str(Path(__file__).parent.parent))

os.environ.setdefault("COLLECTOR_DB_PATH", "collector_local_demo.db")
os.environ.setdefault("SOURCE_TZ", "Asia/Kolkata")

from collector.models import RawRecord
from collector.normalize import normalize_and_store
from collector.db import get_db

CATEGORIES = [
    ("cpu",          lambda: round(random.uniform(30, 95), 2), "percent"),
    ("memory",       lambda: round(random.uniform(40, 90), 2), "percent"),
    ("disk",         lambda: round(random.uniform(55, 80), 2), "percent"),
    ("latency",      lambda: round(random.uniform(20, 350), 2), "ms"),
    ("packet_loss",  lambda: round(random.uniform(0, 10), 3),  "percent"),
    ("bandwidth",    lambda: round(random.uniform(50, 600), 2), "mbps"),
    ("auth",         lambda: 1.0,                               "count"),
    ("connectivity", lambda: 1.0,                               "boolean"),
]


def make_record(cat: str, val_fn, unit: str, tick: int, inject_secret: bool = False) -> RawRecord:
    now = datetime.now(timezone.utc)
    if inject_secret:
        raw = (
            f"sshd[{3000 + tick}]: Failed password for root "
            f"from 192.168.1.{tick % 255} "
            f"password=hunter{tick} token=eyJhbGci{tick:04x}"
        )
    else:
        val = val_fn()
        raw = f"{cat}={val}{unit} host=blr-dc1-host.internal"
    return RawRecord(
        adapter="sim",
        source="blr-dc1-host.internal",
        source_tz="Asia/Kolkata",
        category=cat,
        raw_text=raw,
        value=val_fn(),
        unit=unit,
        ts=now,
    )


def main() -> None:
    ingested = 0
    for tick in range(20):
        for cat, val_fn, unit in CATEGORIES:
            inject = cat == "auth" and tick % 5 == 0
            record = make_record(cat, val_fn, unit, tick, inject_secret=inject)
            normalize_and_store(record)
            ingested += 1

    print(f"Ingested {ingested} records into local DB.\n")

    conn = get_db()
    rows = conn.execute(
        """
        SELECT id, received_at, source, category, value, unit, adapter, raw_text
        FROM   raw_events
        ORDER  BY received_at DESC
        LIMIT  20
        """
    ).fetchall()

    hdr = (
        f"{'ID':>5}  {'Adp':5}  {'Category':12}  {'Value':14}  "
        f"{'Source (REAL — LOCAL ONLY)':30}  Raw Text (first 80 chars)"
    )
    print(hdr)
    print("-" * 140)

    for r in rows:
        val_str = f"{r['value']:.2f} {r['unit']}" if r["value"] is not None else "—"
        raw_snip = (r["raw_text"] or "")[:80]
        secret_markers = ["password=", "token="]
        secret_flag = "  [SECRET!]" if any(m in (r["raw_text"] or "").lower() for m in secret_markers) else ""
        print(
            f"{r['id']:>5}  {r['adapter']:5}  {r['category']:12}  "
            f"{val_str:14}  {r['source']:30}  {raw_snip}{secret_flag}"
        )

    print()
    print("[OK] Secrets (passwords, tokens, real IPs) are visible here -- this is the LOCAL database.")
    print("[!!] They will NOT appear in any egress payload (Phase 2 enforces the allow-list policy).")


if __name__ == "__main__":
    main()
