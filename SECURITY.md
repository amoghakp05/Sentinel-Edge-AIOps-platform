# Sentinel Edge — Security Architecture & Privacy Policy

> **CICADA 2026 Hackathon** | Two-tier, local-first, privacy-preserving AIOps observability platform.  
> **Core Guarantee:** _Raw stays local. Metadata goes global._

---

## 1. Data Classification: What Stays Local vs. What Is Sent

Sentinel Edge enforces a strict physical boundary between **sensitive edge source data** and **allow-listed cloud metadata**.

### What Stays Local (Never Egresses the Host)
The following information is persisted **only** in the edge node's local SQLite database (`collector_local.db`) under restricted host OS permissions, and is **never transmitted across the network**:
- **Raw Log Text & Stacktraces**: Full syslog lines, authentication messages, exception traces, and error payloads.
- **Secrets & Credentials**: Passwords (`password=...`), bearer tokens (`Bearer eyJ...`), API keys (`AKIA...`), private keys (`-----BEGIN PRIVATE KEY-----`), and database connection URIs.
- **Internal Identifiers & Network Topology**: Real hostnames (`app-node-01.fra.acme.internal`), local private IP addresses (`192.168.1.50`, `10.10.1.15`), and MAC addresses.
- **Un-aggregated Telemetry**: High-frequency sub-second metric fluctuations and raw thread queues.

### What Is Sent to Central SaaS (Egress Payloads)
Central SaaS receives **only allow-listed metadata** conforming to the strict RFC 9562 UUIDv7 JSON Schema:
- **RFC 9562 UUIDv7 Identifiers**: Time-ordered, cryptographically unique payload IDs (`payload_id`).
- **Pseudonymized Host References**: One-way HMAC-SHA256 salted hashes formatted as `h_xxxxxxxx` (e.g. `h_ac0e0001`). Host identities cannot be reversed without the edge salt.
- **Allow-Listed Categories & Metrics**: Aggregated numerical metrics (`cpu: 45.0`, `latency: 28.0`, `bandwidth: 450.0`) with standard units (`percent`, `ms`, `mbps`).
- **Security Metric Summaries**: Aggregated counts of security events (e.g., `failed_login_count: 5`), completely stripped of usernames, passwords, and source IPs.
- **UTC Timestamps & Timezones**: ISO-8601 UTC timestamps ending in `Z` and IANA timezone strings (`Europe/Berlin`).

---

## 2. Egress Allow-List & Redaction Engine

All outbound data is processed by the dual-tier allow-list gate defined in `contracts/allow-list.yaml`.

### 1. Zero-Trust Field Allow-Listing
Any JSON key not explicitly declared in `contracts/allow-list.yaml` is **silently dropped before egress** by the edge collector, and **rejected with HTTP 400 Bad Request** if received by the SaaS:
```yaml
allowed_fields:
  payload_id:     { type: string, pattern: "^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" }
  schema_version: { type: int, allowed_values: [1] }
  collector_id:   { type: string, max_len: 64 }
  event_time_utc: { type: iso8601_utc }
  source_tz:      { type: string, max_len: 64 }
  sent_time_utc:  { type: iso8601_utc }
  source_ref:     { type: string, pattern: "^h_[0-9a-f]{8}$" }
  kind:           { type: enum, values: [metric, health, security_summary, alert, heartbeat] }
  category:       { type: enum, values: [cpu, memory, disk, bandwidth, latency, packet_loss, connectivity, auth, service] }
  severity:       { type: enum, values: [info, warning, critical] }
  value:          { type: number }
  unit:           { type: string, max_len: 16 }
  window_s:       { type: int }
  context:        { type: string, max_len: 200 }
```

### 2. Multi-Pattern Secret Scanner
Every string-type value is scanned by a pre-egress regex engine featuring 13 signatures:
- **Passwords & Secrets**: `(?i)(?:password|passwd|pwd|secret)\s*[:=]`
- **Bearer Tokens & JWTs**: `(?i)Bearer\s+` and `eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`
- **Cloud Credentials**: `\b(?:AKIA|ASIA|ABIA|ACCA)[A-Z0-9]{16}\b` (AWS Access Keys)
- **Private Key Headers**: `-----BEGIN [A-Z\s]+ PRIVATE KEY-----`
- **PII & Addresses**: Email addresses, IPv4 addresses (`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`), IPv6 addresses, and internal domains (`.internal`, `.corp`, `.local`).
- **Connection Strings**: `[a-zA-Z][a-zA-Z0-9+.-]*://(?!\\[REDACTED)[^:\\s/@]+:[^@\\s/]+@`

*If any string trips a pattern, the field is either sanitized locally or dropped entirely.*

---

## 3. Security Controls & Operational Hygiene

### Authentication & Authorization
- **Collector-to-SaaS Ingestion**:
  - Collectors authenticate using an API key (`X-API-Key`) and a cryptographic HMAC-SHA256 signature (`X-Signature`) computed over the exact byte sequence of the request body:
    $$\text{Signature} = \text{HMAC-SHA256}(\text{Secret}, \text{BodyBytes})$$
  - SaaS verifies the signature using constant-time comparison (`hmac.compare_digest`) to prevent timing attacks.
- **Operator Dashboard Access**:
  - Web dashboard uses read-only Bearer Viewer Tokens (`VIEWER_TOKEN_ACME`) scoped per tenant.
  - Tokens are stored exclusively in the browser's `sessionStorage` (cleared when the tab closes) and never persisted in local storage or committed files.
  - Sensitive tokens are stripped from query strings in access logs via `StripQueryStringFilter` before uvicorn writes to stdout or disk.

### Transport Layer Security (TLS)
- In production, all WAN edge-to-SaaS communication requires TLS 1.3.
- Insecure HTTP is restricted to local loopback test harnesses.
- Wildcard CORS (`*`) is strictly disallowed; CORS headers explicitly whitelist authorized tenant origins (`http://localhost:8000`, `http://localhost:3000`).

### Local Storage & Retention
- **Edge Node SQLite WAL**: `collector_local.db` runs with Write-Ahead Logging (`PRAGMA journal_mode=WAL`) and `PRAGMA synchronous=NORMAL` for transactional integrity.
- **Local Retention Purging (`collector/retention.py`)**:
  - Raw unredacted logs are automatically purged after 7 days (configurable via `RETENTION_RAW_DAYS`).
  - Egress audit records are maintained for 30 days for cryptographic non-repudiation, then vacuumed.
- **SaaS Telemetry Retention**: Central metric timeseries data is partitioned and retained for 30 days.

### Cryptographic Egress Audit & Verification
- Every transmitted payload is logged to the edge collector's `egress_log` table with its exact SHA-256 digest, payload ID, timestamp, and SaaS response code.
- Operators can cryptographically verify that an egress payload was not tampered with using:
  ```bash
  collector verify-hash <payload_id>
  ```
- Operators can compare raw vs. egress representations side-by-side:
  ```bash
  collector egress show <payload_id>
  ```

---

## 4. Multi-Tenant Isolation Architecture

Sentinel Edge enforces tenant boundaries at every layer of the SaaS stack:

### 1. Ingestion Identity Derivation (Hard Rule)
Client payloads may **never** specify or override their own `tenant_id`. Upon receiving a request:
1. SaaS validates the `X-API-Key` and `X-Signature`.
2. SaaS derives `tenant_id` and `collector_id` **strictly from the authenticated server-side credential mapping**.
3. Any `tenant_id` field in the client JSON body is immediately popped and discarded (`item.pop("tenant_id", None)`).

### 2. Database Partitioning & Scoped Queries
- All database tables enforce `tenant_id` as part of the primary key:
  ```sql
  CREATE TABLE metrics (
      tenant_id TEXT NOT NULL,
      payload_id TEXT NOT NULL,
      ...
      PRIMARY KEY (tenant_id, payload_id)
  );
  ```
- Application code accesses the database exclusively via `get_scoped_query(tenant_id, table, ...)`. Queries automatically inject `WHERE tenant_id = ?` parameters, preventing SQL injection and cross-tenant data leaks.
- Cross-tenant access is validated by an automated 8-point isolation test matrix (`tests/test_tenant_isolation.py`), proving zero row leakage across Acme and Globex partitions.

---

## 5. Regional Data Residency & Sovereignty

To comply with data residency regulations (e.g. GDPR in the EU, DPDP in India), SaaS instances are deployed as independent, sovereign regional gateways:

```
                    ┌────────────────────────────┐
                    │ Collector col-acme-eu-1    │
                    │ Pinned to Region: 'eu'     │
                    └─────────────┬──────────────┘
                                  │
         ┌────────────────────────┴────────────────────────┐
         │ Ingest to EU (:8000)            │ Ingest to IN (:8002)
         ▼                                 ▼
   [200 OK — Ingested]             [421 Misdirected Request]
   Stored in saas_eu.db            Dropped & Audited
```

### Sovereign Ingestion Verification (`saas/regions.py`)
1. Every collector credential is permanently bound to a designated geographic region:
   - `col-acme-eu-1` $\to$ `eu` (`eu-central-1`)
   - `col-globex-in-1` $\to$ `in` (`ap-south-1`)
2. When a collector posts telemetry to a regional gateway, the gateway checks its own configured region against the collector's pinned region:
   ```python
   region_ok, err = verify_tenant_region(tenant_id, collector_id)
   if not region_ok:
       return 421, {"error": "Misdirected Request: collector pinned to another region"}
   ```
3. If an EU collector mistakenly connects to an Indian regional endpoint (or vice versa), the request is **rejected immediately with HTTP 421 Misdirected Request**, no database write occurs, and a `MISDIRECTED_REGION` audit event is logged.
4. Databases are completely decoupled: `saas_eu.db` and `saas_in.db` run on separate storage volumes with zero shared state.
