# Sentinel Edge — Architectural Limitations & Production Roadmap

> **CICADA 2026 Hackathon** | Transparent evaluation of current demonstration architecture vs. enterprise production requirements.

---

## 1. Honest Gaps in the Current Implementation

While Sentinel Edge demonstrates full end-to-end functionality, privacy-preserving data isolation, and governed remediation, several components are simplified for the hackathon demonstration:

### 1. Simulated Telemetry Sources
- **Current State:** Metric generation relies on an in-memory HTTP/WebSocket telemetry simulator (`tools/sim_stream_server.py`) with mathematical diurnal sinusoidal curves, Gaussian noise, and synthetic auth lines. While realistic psutil and syslog input adapters exist (`collector/inputs/`), they are not connected to live bare-metal server fleets in this demo environment.
- **Risk:** Edge cases in real operating system kernels (e.g. eBPF buffer overflows, kernel panic log bursts, non-standard syslog formats) are not represented.

### 2. Static Pre-Shared Keys without Real mTLS Rotation
- **Current State:** Edge collectors authenticate using static HMAC-SHA256 API secrets loaded from environment variables (`.env`). Browser dashboard sessions use pre-shared viewer tokens stored in `sessionStorage`.
- **Risk:** If an edge node is physically compromised and its disk unencrypted, the static API secret could be extracted. The system lacks automated short-lived certificate issuance or revocation lists (CRLs).

### 3. Single-Node SQLite Storage
- **Current State:** Both the edge collector (`collector_local.db`) and central SaaS instances (`saas_eu.db`, `saas_in.db`) run on local SQLite files using Write-Ahead Logging (WAL) and memory mapping (`PRAGMA mmap_size`).
- **Risk:** SQLite is single-node and not horizontally scalable. While adequate for ~50,000 writes/second on SSD storage, it cannot scale across distributed cloud clusters or provide cross-datacenter multi-master replication.

### 4. Rule-Based Recommendations & Deterministic Heuristics
- **Current State:** The AIOps intelligence tier (`saas/aiops/`) uses deterministic statistical algorithms: 30-day sinusoidal baselines, standard deviations ($z > 3.0$), sliding topological correlation windows (120s), and a fixed expert recommendation decision matrix (`recommend.py`).
- **Risk:** Highly novel or complex multi-tier microservice failures not explicitly mapped in `contracts/topology.yaml` will fall back to general entity recommendations rather than generating novel synthetic insights.

### 5. Simulated Remediation Execution
- **Current State:** All automated recovery actions (`restart_service`, `flush_cache`, `reroute_traffic`) are executed inside an in-memory mock service registry (`saas/remediation.py:MockServiceRegistry`). Code strictly forbids executing real system calls (`os.system`, `subprocess`) to prevent security accidents during judging.
- **Risk:** Actions do not actually manipulate real operating system process trees, Docker daemons, or cloud network routing tables.

---

## 2. Production Roadmap & Enterprise Requirements

To evolve Sentinel Edge from a hackathon proof-of-concept into a mission-critical, enterprise-grade platform, the following production upgrades are required:

| Domain | Current Hackathon Implementation | Production Enterprise Requirement |
| :--- | :--- | :--- |
| **Collector Identity** | HMAC-SHA256 static secrets in `.env` | **Hardware-backed mTLS** via TPM 2.0 / HSM chips, short-lived X.509 client certificates rotated via ACME / HashiCorp Vault. |
| **Ingestion Pipeline** | FastAPI direct REST endpoints (`POST /v1/ingest`) | **Distributed Event Streaming Queue** (Apache Kafka or AWS Kinesis) buffering tens of millions of events/sec with consumer group autoscaling. |
| **Storage Engine** | Single-node SQLite WAL databases | **Dedicated Distributed Time-Series Database** (e.g., ClickHouse, TimescaleDB, or AWS Timestream) with partitioned columnar storage. |
| **Tenant Encryption** | Database-level row partitioning (`tenant_id`) | **Per-Tenant Envelope Encryption** using AWS KMS / Azure Key Vault with customer-managed keys (BYOK). |
| **Operator Access & RBAC**| Scoped Bearer Tokens in `sessionStorage` | **Enterprise SSO** (OIDC / SAML 2.0) integrated with Okta / Entra ID, enforcing granular RBAC (`viewer`, `operator`, `security_admin`). |
| **Real Remediation Tooling**| In-memory mock registry (`MockServiceRegistry`) | **Hardened Infrastructure Orchestration** via signed Ansible playbooks, Kubernetes Operator controllers, or AWS Systems Manager with canary health-checks. |
| **Edge Capture** | Python syslog/psutil HTTP adapters | **Native Kernel eBPF Probes** (BCC / libbpf) capturing socket lifecycles, TCP retransmissions, and syscall latencies with near-zero CPU overhead. |

---

## 3. High-Throughput Scaling Architecture

```
                    ┌──────────────────────────────────────────────────┐
                    │     Fleet of 10,000+ Edge Collectors Nodes       │
                    │   (Store-and-Forward SQLite Outbox on each host) │
                    └────────────────────────┬─────────────────────────┘
                                             │ HTTPS mTLS (JSON metadata)
                                             ▼
                    ┌──────────────────────────────────────────────────┐
                    │     Regional Ingestion Gateways (Autoscaled)     │
                    └────────────────────────┬─────────────────────────┘
                                             │
                                             ▼
                    ┌──────────────────────────────────────────────────┐
                    │      Distributed Message Bus (Apache Kafka)      │
                    │    Partitioned by (tenant_id, collector_id)      │
                    └────────────────────────┬─────────────────────────┘
                                             │
                        ┌────────────────────┴────────────────────┐
                        ▼                                         ▼
         ┌───────────────────────────────┐         ┌───────────────────────────────┐
         │   Stream Analytics Workers    │         │     Columnar Storage Tier     │
         │ (Flink / PySpark AIOps Model) │         │ (ClickHouse / TimescaleDB)    │
         └───────────────────────────────┘         └───────────────────────────────┘
```

This production architecture preserves Sentinel Edge's fundamental security guarantee: **the central stream and database never store, process, or see raw customer logs or secrets.**
