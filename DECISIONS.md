# DECISIONS.md
_Append one entry per decision. Never delete existing entries._

---

## Phase 1

**D-001** `RawRecord` is a frozen dataclass (not a Pydantic model) because it
represents data that has NOT yet been validated or redacted.  Pydantic is
reserved for validated payload schemas only.

**D-002** All three input adapters (`sim_stream`, `psutil`, `syslog`) yield
`RawRecord` objects.  The collector pipeline consumes a single `Iterable[RawRecord]`
regardless of adapter, making swap-out trivial.

**D-003** SQLite WAL mode is set at connection time (`PRAGMA journal_mode=WAL`)
and re-confirmed on every `get_db()` call.  The raw_events table is the only
Phase-1 write target; it stores raw_text exactly as received — secrets
intentionally included — which is why it stays strictly local (Hard Rule 1 / C5).

**D-004** `normalize.py` enforces timezone-aware datetimes throughout.  `datetime.utcnow()`
is banned; we use `datetime.now(timezone.utc)` and `dateutil.parser.parse()` with
`tzinfos` fallback.  Naive datetimes raise `ValueError` to fail loudly.

**D-005** `retention.py` runs as a background thread with a `threading.Event`
stop flag so the main process can shut it down cleanly.  It logs every deleted
batch via the standard `logging` module (Rich handler in CLI mode).

**D-006** The `source` field on `RawRecord` holds the **real** hostname/IP.
It is redacted into `source_ref` only in Phase 2 (`redact.py`).  Storing the
real value locally is intentional (Hard Rule 2).

**D-007** `inputs/syslog_input.py` uses `follow=True` tail logic implemented
with `seek(0, 2)` + polling so it works without `inotify` (cross-platform for
dev/Windows).  The `pyinotify` / `watchdog` path is an optional optimisation.

**D-008** `sim_stream.py` uses HTTP polling against the simulator server by
default; the `SIM_STREAM_URL` env var points to `tools/sim_stream_server.py`.
WebSocket upgrade is a later optional phase.

**D-009** `RAW_RETENTION_HOURS` defaults to 24 h.  Deleted row count is logged
at INFO so operators can verify compliance with their local data-minimisation
policy without auditing the DB directly.


---

## Phase 0

**D-010** Topology maps two tenants (`acme` in `eu-central-1` and `globex` in `ap-south-1`) with 3 collectors, documenting the exact physical-to-logical pathway: service -> host -> network device.

**D-011** `sim_stream_server.py` implements a 24-hour diurnal sinusoidal wave combined with Gaussian noise to simulate realistic human traffic patterns without synthetic step functions.

**D-012** The `TelemetryStreamAdapter` protocol in `collector/inputs/__init__.py` decouples the ingestion pipeline from the transport layer, allowing drop-in swapping of organizers' live streams without changing internal normalization or policy logic.

**D-013** The `aiopsctl` and `collector` CLIs standardize on Typer and Rich with ubiquitous `--json` flags to support headless automation, test harness verification, and interactive inspection.


---

## Phase 2

**D-014** `redact_text` utilizes typed placeholders (e.g. `[REDACTED:token]`, `[REDACTED:password]`) and returns discovered categories only, ensuring that secret text never enters telemetry or diagnostic structures.

**D-015** High-entropy strings are screened via Shannon entropy analysis ($\mathcal{H} > 4.2$) for tokens $\ge 18$ characters, catching unpredictable random API keys and hashes that evade fixed regexes.

**D-016** Pseudonymization computes `h_` + 8 hex digits from HMAC-SHA256, persisting the real-to-pseudonym reverse mapping exclusively in the local `source_mapping` SQLite table so that cleartext identities never egress.

**D-017** Tumbling 5-second windows collapse numeric metrics into `(avg, min, max)` and authentication failures into a scalar count per `source_ref`, permanently dropping raw lines and usernames before transmission.

**D-018** `policy.enforce_policy()` serves as the final egress barrier, executing full schema type/pattern validation and regex secret scanning across every string field, recording any rejection in `blocked_log` without logging the secret value.


---

## Phase 3

**D-019** Payloads are assigned RFC 9562 UUIDv7 identifiers containing a 48-bit millisecond timestamp and version 7 prefix, providing sub-millisecond chronological sortability before outbox insertion.

**D-020** `outbox.enqueue()` commits outgoing payloads to SQLite WAL with `status='pending'` prior to any network socket creation, ensuring that process crashes or power cuts cannot cause telemetry loss.

**D-021** Egress logging maintains an immutable append-only ledger (`egress_log`) storing the verbatim transmitted bytes, SHA-256 hash, destination, and subsequent SaaS ACK hash, strictly forbidding row deletion or in-place modification.

**D-022** `sender.send_batch()` batches up to 50 records in strict FIFO order, computing an HMAC-SHA256 request signature over the exact payload bytes (`X-Signature`), and requires an explicit 2xx ACK from the SaaS before transitioning outbox status to `sent`.

**D-023** Heartbeat payloads are emitted every 10 seconds through the identical validation, policy, and outbox pipeline as normal telemetry, carrying live collector CPU/memory, queue depth, and configuration hash.


---

## Security Hardening (Adversarial Review)

**D-024** `policy.py` and `contracts/allow-list.yaml` enforce comprehensive regex scanning covering bare AWS access keys, private key blocks, email addresses, IPv6, credit cards, URI credentials, and internal hostnames (`.internal`, `.corp`, `.local`).

**D-025** `aggregate.py` and `local_analysis.py` implement defensive runtime checks on `source_ref`, automatically hashing non-compliant strings to prevent cleartext hostnames or IPs from leaking into aggregates.

**D-026** Debug logs in `normalize.py` mask real source hostnames (`src***`), and `sender.py` formats sanitized error messages to prevent socket error dumps from leaking URLs or authentication headers.

**D-027** `saas/ingest.py` strips any `tenant_id` supplied in incoming payload bodies, relying strictly on the authenticated credential (`X-Api-Key`), and implements idempotent deduplication on `(tenant_id, payload_id)` (Hard Rules 3 & 5).


---

## Phase 4

**D-028** Collector authentication in `saas/auth.py` looks up collectors by SHA-256 API key hash and verifies request body HMAC-SHA256 signatures (`X-Signature`), deriving `tenant_id` and `collector_id` exclusively from credentials. Body claims of `tenant_id` are ignored and dropped. Unknown keys or bad signatures return 401.

**D-029** Regional isolation (`saas/regions.py`) pins tenants to specific regions (`acme` to `eu`, `globex` to `in`). Misdirected requests to incorrect regional SaaS instances are rejected with HTTP 421 and recorded in `audit_log`. Separate SQLite database files (`saas_eu.db`, `saas_in.db`) are maintained per region with zero replication across regions.

**D-030** Server-side validation in `saas/validate.py` enforces `contracts/allow-list.yaml` against all incoming payloads. Any payload with unrecognized fields (e.g. injected `password`), invalid types, over-length strings, or strings matching secret patterns is rejected with HTTP 400 and logged to the immutable `audit_log`.

**D-031** Database deduplication in `saas/ingest.py` executes `INSERT ... ON CONFLICT(tenant_id, payload_id) DO NOTHING`. Both new and duplicate payloads receive an ACK containing `payload_id` and the canonical SHA-256 body hash so retries are strictly idempotent. Event generation time (`event_time_utc`) and server arrival time (`received_at`) are stored separately.

**D-032** Multi-tenant read queries in `saas/tenancy.py` are routed through a single centralized function `get_scoped_query(tenant_id)`. Direct or raw un-scoped queries elsewhere are prohibited, enforcing complete tenant isolation at the data access layer (Hard Rule 4).


---

## Phase 5

**D-033** The health state machine in `saas/health.py` strictly evaluates four discrete tiers (`Excellent`, `Good`, `Fair`, `Poor`), resolving multiple signals via a deterministic maximum-severity strategy (`Poor` > `Fair` > `Good` > `Excellent`).

**D-034** Enforced Hard Rule 7: Missing/stale telemetry directly degrades health. A collector without heartbeats or a monitored source without telemetry transitions to `Fair` at 30 s (`Fair: data stale for N s`) and `Poor` at 60 s (`Poor: no heartbeat for N s`). The platform never presents the last good reading as healthy.

**D-035** State transitions are appended to the immutable `health_history` audit table recording `(tenant_id, entity_id, from_state, to_state, reason, at_utc)`. In-place updates to `health_state` only update the current snapshot; historical entries are never deleted or modified.

**D-036** Tenant thresholds are initialized from `contracts/thresholds.yaml` into the `thresholds` database table on regional DB creation, allowing real-time per-tenant customization via `PUT /api/thresholds` without restarting the SaaS services.

**D-037** Real-time dashboard updates utilize Server-Sent Events (SSE) via `saas/sse.py`. Whenever an entity transitions state, a JSON event frame is pushed to active subscriber queues filtered by `tenant_id`.


---

## Phase 6

**D-038** AIOps baselines (`saas/aiops/baseline.py`) maintain a rolling EWMA ($\alpha=0.15$), rolling window median/MAD, and a 168-hour time-of-day bucket distribution ($24 \times 7$ buckets) indexed strictly by `event_time_utc` rather than arrival time. Baselines are persisted in the `baselines` SQLite table to ensure complete continuity across SaaS process restarts.

**D-039** Anomaly detection (`saas/aiops/detect.py`) applies robust z-scores ($z = 0.6745 \times \frac{x - \text{median}}{\text{MAD}}$) against the diurnal blended baseline. A strict persistence filter requires $|z| \ge 3.0$ for at least 3 of the last 5 evaluation windows before flagging, successfully suppressing transient one-sample spikes and eliminating false alarms during normal diurnal ramp-ups (e.g. 9 am business hour rises).

**D-040** Explainability payloads (`saas/aiops/explain.py`) accompany every flagged anomaly, calculating normalized relative signal weights ($\sum w_i = 1.0$) based on standardized signal deviations, confidence ratings, persistence ratios (`"3/5"`), and plain English narrative summaries.

**D-041** Anomaly alert orchestration (`saas/aiops/engine.py`) writes anomalies to the `anomalies` table and generates corresponding alerts in the `events` table within 15 seconds of the event time, explicitly recording `event_time_utc` alongside `received_at` to benchmark alert generation latency.


---

## Phase 7

**D-042** Alert correlation (`saas/aiops/correlate.py`) merges alerts occurring within a sliding 2-minute window (120 s) sharing a tenant and topology component into a single unified incident. Subsequent alerts update the existing open incident, incrementing `suppressed_count`, escalating severity to the highest active alert, and accumulating affected components.

**D-043** Upstream root cause candidate selection utilizes the structural hierarchy from `contracts/topology.yaml` (`network device` > `host` > `service`), identifying physical switch/gateway anomalies (e.g. latency and packet loss) as the primary upstream root cause over downstream host resource starvation or application errors.

**D-044** Explainable remediation recommendations (`saas/aiops/recommend.py`) map multi-signal signatures (Link Congestion, Brute Force Abuse, Memory Leak, Upstream Outage) into transparent remediation actions, computing confidence from signal strengths and providing step-by-step reasoning paths persisted to the `recommendations` table.

---

## Phase 8

**D-045** The AIOps Fleet Dashboard (`dashboard/index.html`) is built as a thin, dependency-minimal single-page application using vanilla JavaScript and Chart.js. In accordance with platform guidelines ("function over polish"), all visualizations and state tables consume real SaaS REST APIs and subscribe to live Server-Sent Events (`GET /api/health/stream`) with zero mock or hardcoded values.

**D-046** UTC timestamp integrity is preserved across all database tables and network payloads. Timestamps are converted into the viewer's selected timezone (`UTC`, `Viewer Local`, `Europe/Berlin`, `Asia/Kolkata`, `America/New_York`) dynamically on the client side without altering original event values.

**D-047** Real-time telemetry pipeline calculates live collection-to-dashboard latency in milliseconds directly inside the client footer widget by comparing the payload's `event_time_utc` against browser arrival time. An explicit Stale Indicator badge is automatically raised whenever telemetry arrival exceeds 15 seconds.

**D-048** The operator CLI (`saas/cli_aiopsctl.py`) provides first-class terminal interfaces (`aiopsctl health`, `aiopsctl collectors`, `aiopsctl incidents`, `aiopsctl why <id>`) querying the tenant-scoped database directly, with complete support for `--json` machine output and human-readable Rich tables.

---

## Security Audit Pass 2 (SaaS Read Side & Dashboard)

**D-054** Read endpoint tenancy derivation (`saas/api.py:resolve_tenant_id`): Tenancy is derived strictly and exclusively from authenticated viewer credentials (via `X-Api-Key` header, `Authorization: Bearer <key>` header, or `?token=` query parameter). Caller-provided `?tenant=` query parameters and `X-Tenant-Id` headers are completely removed and ignored as tenancy resolvers; unauthenticated or invalid tokens unconditionally return HTTP 401 Unauthorized.

**D-055** Real-time Server-Sent Events isolation (`saas/sse.py`): The global subscriber list is eliminated entirely. `subscribe(tenant_id)` and `broadcast_event(tenant_id, ...)` dispatch frames strictly to `_SUBSCRIBERS[tenant_id]`, guaranteeing that Tenant B subscribers cannot receive events or telemetry belonging to Tenant A.

**D-056** Elimination of test signature bypass (`saas/auth.py`): The test-signature mock bypass (`"sig"`, `"test_sig"`, `"dummy_sig"`) is removed universally. All collector ingest requests must supply a valid HMAC-SHA256 signature calculated with the collector's HMAC secret; all automated test suites compute genuine cryptographic signatures.

**D-057** Constant-time cryptographic comparison & hashed storage at rest: Secret and cryptographic checksum comparisons across the platform (`saas/auth.py`, `collector/cli.py:egress show`, `collector/cli.py:verify-hash`) utilize `hmac.compare_digest` to prevent timing side-channel analysis. Viewer tokens and collector API keys are stored and evaluated exclusively via SHA-256 hashes.

**D-058** Explicit CORS origins (`saas/main.py`): Wildcard origin `allow_origins=["*"]` is strictly prohibited. CORS origin headers are constrained to an explicit whitelist of trusted origins (`http://localhost:8000`, `http://127.0.0.1:8000`, `http://localhost:3000`).

**D-059** Plain-text dashboard rendering & DOM XSS protection (`dashboard/index.html`): All telemetry strings, health transition reasons, incident summaries, and contributing signal explanations are constructed and attached using safe DOM nodes and `.textContent` / `.replaceChildren()`. `innerHTML` assignments with dynamic string interpolation are eradicated.

**D-060** Exception message sanitization (`saas/ingest.py`): Ingestion JSON decoding failures return generic `"Invalid JSON body format"` errors rather than embedding the raw exception string or payload byte fragments into the HTTP response.

**D-061** Credential and environment exclusion (`.gitignore`): `.gitignore` is established at the repository level to block committing `.env`, `*.db`, SQLite WAL files, and Python cache artifacts; only template `.env.example` is committed.

**D-062** Dynamic cryptographically random viewer tokens (`tools/gen_tokens.py`): Replaced predictable hardcoded viewer tokens (`viewer-token-acme`, `viewer-token-globex`) with high-entropy URL-safe random tokens (`secrets.token_urlsafe(32)`) generated per tenant into local uncommitted `.env`. The SaaS stores and compares only their SHA-256 hashes via `hmac.compare_digest`. The dashboard manages tokens strictly through an explicit user login box and browser `sessionStorage`, eliminating credentials from the client bundle.
_Note on Token Architecture:_ Demo tokens are static bearer tokens; production deployments would use enterprise SSO/OIDC, Role-Based Access Control (RBAC), and short-lived tokens (e.g., rotating JWTs).








