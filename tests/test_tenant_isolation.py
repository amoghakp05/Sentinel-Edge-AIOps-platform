"""
tests/test_tenant_isolation.py
───────────────────────────────
Phase 4 Multi-Tenant & Regional Isolation Tests:
- Hard Rule 3: Tenant derivation strictly from credential (body spoofing rejected/ignored)
- Hard Rule 4: Tenant B token returns ZERO Tenant A rows via get_scoped_query()
- Regional pinning: Wrong region payload returns HTTP 421 + logs audit record
- Database isolation: Regional instances have independent DB files
"""

import hashlib
import hmac
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Tuple

# Ensure project root is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from collector.uuidv7 import uuidv7
from saas.db import get_connection, init_db
from saas.ingest import handle_ingest
from saas.regions import verify_tenant_region
from saas.remediation import (
    ensure_remediation_schema,
    list_remediation_actions,
    propose_remediation_action,
)
from saas.tenancy import get_scoped_query


def sign_payload(body_bytes: bytes, secret: str = "secret-acme-eu1") -> str:
    """Computes genuine HMAC-SHA256 signature for test requests."""
    return hmac.new(secret.encode("utf-8"), body_bytes, hashlib.sha256).hexdigest()


@pytest.fixture(autouse=True)
def setup_regional_databases(tmp_path, monkeypatch):
    """Initializes separate EU and IN databases."""
    eu_db = tmp_path / "saas_eu.db"
    in_db = tmp_path / "saas_in.db"

    # Initialize EU database
    monkeypatch.setenv("SAAS_DB_PATH", str(eu_db))
    monkeypatch.setenv("REGION", "eu")
    init_db("eu")

    # Initialize IN database
    monkeypatch.setenv("SAAS_DB_PATH", str(in_db))
    monkeypatch.setenv("REGION", "in")
    init_db("in")

    # Reset back to EU for default tests
    monkeypatch.setenv("SAAS_DB_PATH", str(eu_db))
    monkeypatch.setenv("REGION", "eu")
    yield


def test_tenant_b_sees_zero_tenant_a_rows():
    """Requirement: Tenant B token returns zero Tenant A rows."""
    pid_acme = uuidv7()

    batch_acme = {
        "payloads": [
            {
                "payload_id": pid_acme,
                "schema_version": 1,
                "collector_id": "col-acme-eu-1",
                "event_time_utc": "2026-11-20T10:00:00Z",
                "source_tz": "Europe/Berlin",
                "sent_time_utc": "2026-11-20T10:00:01Z",
                "source_ref": "h_11223344",
                "kind": "metric",
                "category": "cpu",
                "severity": "info",
                "value": 55.0,
            }
        ]
    }

    # Ingest data under Acme
    acme_bytes = json.dumps(batch_acme).encode("utf-8")
    code, resp = handle_ingest("key-acme-eu1-dev", sign_payload(acme_bytes, "secret-acme-eu1"), acme_bytes)
    assert code == 200

    # Query as Acme (Tenant A)
    acme_rows = get_scoped_query("acme", table="metrics")
    assert len(acme_rows) == 1
    assert acme_rows[0]["payload_id"] == pid_acme

    # Query as Globex (Tenant B)
    globex_rows = get_scoped_query("globex", table="metrics")
    # Must be ZERO!
    assert len(globex_rows) == 0

    # Events table also zero for Globex
    globex_events = get_scoped_query("globex", table="events")
    assert len(globex_events) == 0


def test_wrong_region_returns_421(monkeypatch):
    """
    Requirement: Wrong region returns 421.
    Globex is pinned to 'in'. Sending to an 'eu' SaaS instance returns 421.
    """
    monkeypatch.setenv("REGION", "eu")

    pid = uuidv7()
    batch_globex = {
        "payloads": [
            {
                "payload_id": pid,
                "schema_version": 1,
                "collector_id": "col-globex-in-1",
                "event_time_utc": "2026-11-20T10:00:00Z",
                "source_tz": "Asia/Kolkata",
                "sent_time_utc": "2026-11-20T10:00:01Z",
                "source_ref": "h_99887766",
                "kind": "metric",
                "category": "latency",
                "severity": "info",
                "value": 15.0,
            }
        ]
    }
    body_bytes = json.dumps(batch_globex).encode("utf-8")

    # Collector for Globex attempts to send to EU instance
    code, resp = handle_ingest("key-globex-in1-dev", sign_payload(body_bytes, "secret-globex-in1"), body_bytes)
    assert code == 421
    assert "pinned to region 'in'" in resp["error"]
    assert "arrived at 'eu'" in resp["error"]

    # Verify audit log captures this misdirected routing attempt
    audit_rows = get_scoped_query("globex", table="audit_log", where_clause="action = 'MISDIRECTED_REGION'")
    assert len(audit_rows) >= 1
    assert "col-globex-in-1" in audit_rows[0]["actor"]


def test_body_cannot_spoof_tenancy():
    """Acme credential with body claiming tenant_id='globex' is stored strictly under 'acme'."""
    pid = uuidv7()
    spoofed = {
        "payloads": [
            {
                "payload_id": pid,
                "tenant_id": "globex",  # Attempted spoof
                "schema_version": 1,
                "collector_id": "col-acme-eu-1",
                "event_time_utc": "2026-11-20T10:00:00Z",
                "source_tz": "Europe/Berlin",
                "sent_time_utc": "2026-11-20T10:00:01Z",
                "source_ref": "h_11223344",
                "kind": "metric",
                "category": "bandwidth",
                "severity": "info",
                "value": 100.0,
            }
        ]
    }

    spoofed_bytes = json.dumps(spoofed).encode("utf-8")
    code, resp = handle_ingest("key-acme-eu1-dev", sign_payload(spoofed_bytes, "secret-acme-eu1"), spoofed_bytes)
    assert code == 200
    assert resp["tenant_id"] == "acme"

    # Verify record is in Acme's partition
    acme_records = get_scoped_query("acme", table="metrics", where_clause="payload_id = ?", params=[pid])
    assert len(acme_records) == 1
    assert acme_records[0]["tenant_id"] == "acme"

    # Verify record is NOT in Globex's partition
    globex_records = get_scoped_query("globex", table="metrics", where_clause="payload_id = ?", params=[pid])
    assert len(globex_records) == 0


# ── Phase 11: Full Matrix of Tenant A vs Tenant B Isolation ───────────────────

def run_full_tenant_isolation_matrix() -> Tuple[List[Dict[str, Any]], bool]:
    """
    Executes an exhaustive cross-tenant and cross-regional isolation matrix:
    [1] Tenant Acme reads Acme metrics (PASS, len > 0)
    [2] Tenant Globex reads Acme metrics (PASS, 0 rows)
    [3] Tenant Globex reads Globex metrics (PASS, len > 0)
    [4] Tenant Acme reads Globex metrics (PASS, 0 rows)
    [5] Payload body attempting tenant_id spoofing (PASS, derived from cred strictly)
    [6] Acme credential sent to IN region (PASS, 421 Misdirected)
    [7] Globex credential sent to EU region (PASS, 421 Misdirected)
    [8] Cross-tenant remediation governance actions (PASS, 0 visible)
    Returns: (matrix_results, all_passed)
    """
    temp_dir = Path(tempfile.mkdtemp())
    eu_db = temp_dir / "saas_matrix_eu.db"
    in_db = temp_dir / "saas_matrix_in.db"

    # Setup EU instance
    os.environ["SAAS_DB_PATH"] = str(eu_db)
    os.environ["REGION"] = "eu"
    init_db("eu")
    ensure_remediation_schema()

    # Setup IN instance
    os.environ["SAAS_DB_PATH"] = str(in_db)
    os.environ["REGION"] = "in"
    init_db("in")
    ensure_remediation_schema()

    matrix: List[Dict[str, Any]] = []

    # Ingest Acme data into EU
    os.environ["SAAS_DB_PATH"] = str(eu_db)
    os.environ["REGION"] = "eu"
    pid_acme = uuidv7()
    body_acme = json.dumps({"payloads": [{
        "payload_id": pid_acme,
        "schema_version": 1,
        "collector_id": "col-acme-eu-1",
        "event_time_utc": "2026-11-20T10:00:00Z",
        "source_tz": "Europe/Berlin",
        "sent_time_utc": "2026-11-20T10:00:01Z",
        "source_ref": "h_ac0e0001",
        "kind": "metric",
        "category": "cpu",
        "severity": "info",
        "value": 45.0,
    }]}).encode("utf-8")
    c_acme, _ = handle_ingest("key-acme-eu1-dev", sign_payload(body_acme, "secret-acme-eu1"), body_acme)

    # Ingest Globex data into IN
    os.environ["SAAS_DB_PATH"] = str(in_db)
    os.environ["REGION"] = "in"
    pid_globex = uuidv7()
    body_globex = json.dumps({"payloads": [{
        "payload_id": pid_globex,
        "schema_version": 1,
        "collector_id": "col-globex-in-1",
        "event_time_utc": "2026-11-20T10:00:00Z",
        "source_tz": "Asia/Kolkata",
        "sent_time_utc": "2026-11-20T10:00:01Z",
        "source_ref": "h_910b0001",
        "kind": "metric",
        "category": "cpu",
        "severity": "info",
        "value": 65.0,
    }]}).encode("utf-8")
    c_globex, _ = handle_ingest("key-globex-in1-dev", sign_payload(body_globex, "secret-globex-in1"), body_globex)

    # 1. Acme reads Acme data on EU
    os.environ["SAAS_DB_PATH"] = str(eu_db)
    os.environ["REGION"] = "eu"
    rows_a = get_scoped_query("acme", table="metrics", where_clause="payload_id = ?", params=[pid_acme])
    p1 = len(rows_a) == 1
    matrix.append({"test": "Acme reads Acme metrics", "passed": p1, "details": f"{len(rows_a)} rows found"})

    # 2. Globex reads Acme data on EU
    rows_b_on_a = get_scoped_query("globex", table="metrics", where_clause="payload_id = ?", params=[pid_acme])
    p2 = len(rows_b_on_a) == 0
    matrix.append({"test": "Globex reads Acme metrics", "passed": p2, "details": f"{len(rows_b_on_a)} rows leaked"})

    # 3. Globex reads Globex data on IN
    os.environ["SAAS_DB_PATH"] = str(in_db)
    os.environ["REGION"] = "in"
    rows_b = get_scoped_query("globex", table="metrics", where_clause="payload_id = ?", params=[pid_globex])
    p3 = len(rows_b) == 1
    matrix.append({"test": "Globex reads Globex metrics", "passed": p3, "details": f"{len(rows_b)} rows found"})

    # 4. Acme reads Globex data on IN
    rows_a_on_b = get_scoped_query("acme", table="metrics", where_clause="payload_id = ?", params=[pid_globex])
    p4 = len(rows_a_on_b) == 0
    matrix.append({"test": "Acme reads Globex metrics", "passed": p4, "details": f"{len(rows_a_on_b)} rows leaked"})

    # 5. Payload body spoofing: Acme credential claiming tenant_id='globex'
    os.environ["SAAS_DB_PATH"] = str(eu_db)
    os.environ["REGION"] = "eu"
    pid_spoof = uuidv7()
    body_spoof = json.dumps({"payloads": [{
        "payload_id": pid_spoof,
        "tenant_id": "globex",
        "schema_version": 1,
        "collector_id": "col-acme-eu-1",
        "event_time_utc": "2026-11-20T10:00:00Z",
        "source_tz": "Europe/Berlin",
        "sent_time_utc": "2026-11-20T10:00:01Z",
        "source_ref": "h_5a00f001",
        "kind": "metric",
        "category": "cpu",
        "severity": "info",
        "value": 50.0,
    }]}).encode("utf-8")
    code_sp, resp_sp = handle_ingest("key-acme-eu1-dev", sign_payload(body_spoof, "secret-acme-eu1"), body_spoof)
    sp_acme = len(get_scoped_query("acme", table="metrics", where_clause="payload_id = ?", params=[pid_spoof]))
    sp_globex = len(get_scoped_query("globex", table="metrics", where_clause="payload_id = ?", params=[pid_spoof]))
    p5 = (code_sp == 200 and resp_sp.get("tenant_id") == "acme" and sp_acme == 1 and sp_globex == 0)
    matrix.append({"test": "Body tenant spoofing prevention", "passed": p5, "details": f"stored under acme={sp_acme}, globex={sp_globex}"})

    # 6. Globex credential (pinned to 'in') sent to EU region endpoint -> 421 Misdirected
    os.environ["SAAS_DB_PATH"] = str(eu_db)
    os.environ["REGION"] = "eu"
    code_mis_eu, _ = handle_ingest("key-globex-in1-dev", sign_payload(body_globex, "secret-globex-in1"), body_globex)
    p6 = (code_mis_eu == 421)
    matrix.append({"test": "Globex (IN) to EU regional endpoint", "passed": p6, "details": f"HTTP {code_mis_eu} (Expected: 421)"})

    # 7. Acme credential (pinned to 'eu') sent to IN region endpoint -> 421 Misdirected
    os.environ["SAAS_DB_PATH"] = str(in_db)
    os.environ["REGION"] = "in"
    code_mis_in, _ = handle_ingest("key-acme-eu1-dev", sign_payload(body_acme, "secret-acme-eu1"), body_acme)
    p7 = (code_mis_in == 421)
    matrix.append({"test": "Acme (EU) to IN regional endpoint", "passed": p7, "details": f"HTTP {code_mis_in} (Expected: 421)"})

    # 8. Cross-tenant remediation isolation
    os.environ["SAAS_DB_PATH"] = str(eu_db)
    os.environ["REGION"] = "eu"
    act_acme = propose_remediation_action("acme", "restart_service", "srv-edge-01", simulate_business_hours=False)
    globex_actions = list_remediation_actions("globex")
    p8 = len(globex_actions) == 0
    matrix.append({"test": "Cross-tenant remediation isolation", "passed": p8, "details": f"Globex saw {len(globex_actions)} Acme actions"})

    all_passed = all(item["passed"] for item in matrix)

    # Cleanup
    try:
        if eu_db.exists():
            eu_db.unlink()
        if in_db.exists():
            in_db.unlink()
        temp_dir.rmdir()
    except Exception:
        pass

    return matrix, all_passed


def test_full_tenant_isolation_matrix():
    """Verify exhaustive matrix of tenant A vs tenant B access and residency."""
    matrix, all_passed = run_full_tenant_isolation_matrix()
    for row in matrix:
        print(f"\n[ISOLATION] {row['test']}: {'PASS' if row['passed'] else 'FAIL'} ({row['details']})")
        assert row["passed"], f"Isolation failed for: {row['test']} -> {row['details']}"
    assert all_passed


def main() -> None:
    matrix, all_passed = run_full_tenant_isolation_matrix()

    print("=" * 70)
    print("  PHASE 11: FULL TENANT A VS TENANT B ISOLATION MATRIX")
    print("=" * 70)
    for i, row in enumerate(matrix, start=1):
        status_str = "[PASS]" if row["passed"] else "[FAIL]"
        print(f"  {i}. {row['test']:<40} {status_str} ({row['details']})")
    print("=" * 70)
    passed_count = sum(1 for r in matrix if r["passed"])
    print(f"  TOTAL: {passed_count}/{len(matrix)} PASSED")
    print(f"  ISOLATION MATRIX STATUS: {'PASS' if all_passed else 'FAIL'}")
    print("=" * 70)

    sys.exit(0 if all_passed else 1)


if __name__ == "__main__":
    main()
