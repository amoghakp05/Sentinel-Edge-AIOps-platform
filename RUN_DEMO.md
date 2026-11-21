# Sentinel Edge AIOps Platform — Demo & Audit Runbook

This guide contains the exact, verified instructions to start the Sentinel Edge platform, run health checks across all services, execute the end-to-end security and AIOps demo script, and verify all privacy-preserving egress guarantees.

---

## 1. Quick Start: Automated Launch (Windows PowerShell)

We provide an automated launcher script [`start_demo.ps1`](./start_demo.ps1) that launches each service in its own titled PowerShell window, activates the virtual environment, loads environment variables from `.env`, and opens the dashboard in your default browser.

```powershell
# Open a fresh Windows PowerShell prompt and run:
cd c:\Users\arjun\Desktop\sentinel-edge-code\aiops-platform
.\start_demo.ps1
```

This will automatically spawn:
- **Window 1**: Telemetry Simulator (`:9000`)
- **Window 2**: Central SaaS — EU Instance (`:8000`, Tenant `acme`)
- **Window 3**: Central SaaS — IN Instance (`:8002`, Tenant `globex`)
- **Window 4**: Collector Edge Daemon (`col-acme-eu-1`)
- **Browser**: Opens `http://localhost:8000/dashboard/`

> **Note:** All four service windows **must stay open** for the duration of the demonstration.

---

## 2. Manual Launch: One Command Per Window

If you prefer to start each service manually in separate PowerShell windows, follow these steps.

### Prerequisites (Once per workspace)
In your base PowerShell terminal:
```powershell
cd c:\Users\arjun\Desktop\sentinel-edge-code\aiops-platform
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
python tools/gen_tokens.py
```

### Window 1: Telemetry Simulator Server (Port 9000)
*Status: Must stay open.*
```powershell
cd c:\Users\arjun\Desktop\sentinel-edge-code\aiops-platform
.\.venv\Scripts\Activate.ps1
python -m uvicorn tools.sim_stream_server:app --host 0.0.0.0 --port 9000 --reload
```

### Window 2: Central SaaS — EU Regional Instance (Port 8000, Tenant Acme)
*Status: Must stay open.*
```powershell
cd c:\Users\arjun\Desktop\sentinel-edge-code\aiops-platform
.\.venv\Scripts\Activate.ps1
$env:REGION = "eu"
$env:SAAS_DB_PATH = "saas_eu.db"
$env:PYTHONIOENCODING = "utf-8"
python -m uvicorn saas.main:app --host 0.0.0.0 --port 8000 --no-access-log --reload
```

### Window 3: Central SaaS — IN Regional Instance (Port 8002, Tenant Globex)
*Status: Must stay open.*
```powershell
cd c:\Users\arjun\Desktop\sentinel-edge-code\aiops-platform
.\.venv\Scripts\Activate.ps1
$env:REGION = "in"
$env:SAAS_DB_PATH = "saas_in.db"
$env:PYTHONIOENCODING = "utf-8"
python -m uvicorn saas.main:app --host 0.0.0.0 --port 8002 --no-access-log --reload
```

### Window 4: Edge Collector Daemon (col-acme-eu-1)
*Status: Must stay open.*
```powershell
cd c:\Users\arjun\Desktop\sentinel-edge-code\aiops-platform
.\.venv\Scripts\Activate.ps1
$env:COLLECTOR_ID = "col-acme-eu-1"
$env:COLLECTOR_DB_PATH = "collector_local.db"
python tools/live_feed_daemon.py
```

### Browser: Open Dashboard
Navigate to:
```
http://localhost:8000/dashboard/
```
When prompted in the dashboard login modal, paste your tenant viewer token from `.env` (`VIEWER_TOKEN_ACME`).

---

## 3. Docker Alternative

To run the entire platform as containerized microservices:

```powershell
cd c:\Users\arjun\Desktop\sentinel-edge-code\aiops-platform

# 1. Build and start all 7 services in background
docker compose up --build -d

# 2. Check running container status
docker compose ps

# 3. View streaming logs
docker compose logs -f

# 4. Open dashboard
Start-Process "http://localhost:3000"
```

To stop containers:
```powershell
docker compose down
```

---

## 4. Health Checks

From an evaluation PowerShell window, run the following commands to verify each service:

### 1. Telemetry Simulator Health
```powershell
curl.exe -s http://localhost:9000/health
```
**Expected Output:**
```json
{"status":"ok"}
```

### 2. SaaS EU Instance Health
```powershell
curl.exe -s http://localhost:8000/health
```
**Expected Output:**
```json
{"status":"ok","service":"saas","region":"eu"}
```

### 3. SaaS IN Instance Health
```powershell
curl.exe -s http://localhost:8002/health
```
**Expected Output:**
```json
{"status":"ok","service":"saas","region":"in"}
```

### 4. Collector Local Status
```powershell
.\.venv\Scripts\python -m collector.cli status
```
**Real Output:**
```
                          Collector Node Status                           
┏━━━━━━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Property            ┃ Value                                            ┃
┡━━━━━━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ collector_id        │ col-acme-eu-1                                    │
│ raw_events_count    │ 6                                                │
│ outbox_buffer_depth │ 0                                                │
│ connection_state    │ Online                                           │
│ egress_logged_count │ 1                                                │
│ journal_mode        │ wal                                              │
└─────────────────────┴──────────────────────────────────────────────────┘
```

---

## 5. Live Demo Script (Step-by-Step with Real Output)

Run these steps in an interactive evaluation terminal:

```powershell
cd c:\Users\arjun\Desktop\sentinel-edge-code\aiops-platform
.\.venv\Scripts\Activate.ps1
$env:PYTHONIOENCODING = "utf-8"
```

---

### Step 1: Inject a Secret into Local Raw Log
Demonstrates that sensitive auth logs (passwords, usernames, internal IPs) are captured by the local collector and persisted in the local-first database, but will be sanitized before egress.

```powershell
python -c "from datetime import datetime, timezone; from collector.models import RawRecord; from collector.normalize import normalize_and_store; rec = RawRecord(adapter='syslog', source='192.168.1.50', source_tz='UTC', category='security', raw_text='2026-11-20 12:00:00 AUTH_FAIL user=admin password=DEMO_SECRET_PASSPHRASE_DO_NOT_LEAK from 192.168.1.50', ts=datetime.now(timezone.utc)); normalize_and_store(rec); print('Injected secret record into local database successfully.')"
```
**Real Output:**
```
Injected secret record into local database successfully.
```

---

### Step 2: Collector Raw Tail (Local Only — Secrets Visible)
Shows that raw logs contain verbatim sensitive fields locally on the edge device.

```powershell
python -m collector.cli raw tail --n 5
```
**Real Output:**
```
                         LOCAL ONLY — Raw Events (n=5)                         
  These rows contain real hostnames, IPs, and secrets — they NEVER leave this  
                                   machine.                                    
┌┬──────────────┬┬───┬─┬────────────┬─────────────────────────────────────────┐
││ Received     ││   │ │            │                                         │
││ (UTC)        ││ … │ │ Source ⚠   │ Raw Text ⚠ (secrets visible)            │
├┼──────────────┼┼───┼─┼────────────┼─────────────────────────────────────────┤
││ 2026-11-20T… ││ … │ │ 192.168.1… │ 2026-11-20 12:00:00 AUTH_FAIL           │
││              ││   │ │            │ user=admin                              │
││              ││   │ │            │ password=DEMO_SECRET_PASSPHRASE_DO_NOT… │
││              ││   │ │            │ from 192.168.1.50                       │
├┼──────────────┼┼───┼─┼────────────┼─────────────────────────────────────────┤
││ 2026-11-20T… ││ … │ │ 192.168.1… │ sshd[4102]: Failed password for root    │
││              ││   │ │            │ from 192.168.1.55                       │
││              ││   │ │            │ password=DEMO_SECRET_PASSPHRASE_DO_NOT… │
└┴──────────────┴┴───┴─┴────────────┴─────────────────────────────────────────┘
```

---

### Step 3: Collector Egress Tail & Side-by-Side Proof of Transmission
Demonstrates that outgoing payloads contain ONLY allow-listed metadata, pseudonymized entity references (`h_9f3a1c2e`), and zero raw strings or passwords.

```powershell
python -m collector.cli egress tail --n 5
```
**Real Output:**
```
                 Egress Log: Proof of Transmission (Latest 1)                  
┌──┬──────────────────┬────────────────────────────────┬──────┬──────────────┬┐
│  │ Time (UTC)       │ Payload ID                     │ Sta… │ SHA-256      ││
├──┼──────────────────┼────────────────────────────────┼──────┼──────────────┼┤
│  │ 2026-11-20T17:5… │ 01a1fa1d-1015-7951-b6f7-6f19f… │ ack… │ 7345e8b8161… ││
└──┴──────────────────┴────────────────────────────────┴──────┴──────────────┴┘
```

Now inspect the side-by-side audit view for that payload:
```powershell
python -m collector.cli egress show 01a1fa1d-1015-7951-b6f7-6f19f401d398
```
**Real Output:**
```
              Egress Audit: 01a1fa1d-1015-7951-b6f7-6f19f401d398               
┌──────────────────────────────────────┬──────────────────────────────────────┐
│ LEFT: RAW SOURCE (LOCAL ONLY —       │ RIGHT: EGRESS PAYLOAD (METADATA ONLY │
│ SECRETS VISIBLE)                     │ — ALLOW-LISTED)                      │
├──────────────────────────────────────┼──────────────────────────────────────┤
│ sshd[4102]: Failed password for root │ {                                    │
│ from 192.168.1.55                    │   "payload_id":                      │
│ password=DEMO_SECRET_PASSPHRASE_DO_… │ "01a1fa1d-1015-7951-b6f7-6f19f401d3… │
│                                      │   "schema_version": 1,               │
│                                      │   "collector_id": "col-acme-eu-1",   │
│                                      │   "event_time_utc":                  │
│                                      │ "2026-11-20T17:00:00Z",              │
│                                      │   "source_tz": "Europe/Berlin",      │
│                                      │   "sent_time_utc":                   │
│                                      │ "2026-11-20T17:00:01Z",              │
│                                      │   "source_ref": "h_9f3a1c2e",        │
│                                      │   "kind": "alert",                   │
│                                      │   "category": "auth",                │
│                                      │   "severity": "warning",             │
│                                      │   "value": 1.0,                      │
│                                      │   "unit": "count",                   │
│                                      │   "window_s": 5,                     │
│                                      │   "context": "authentication failure │
│                                      │ threshold reached"                   │
│                                      │ }                                    │
└──────────────────────────────────────┴──────────────────────────────────────┘
✓ hash matches SaaS (verified cryptographic ACK: 
7345e8b816173c7d66b871f94abce3c58f91f8a75220fc0ddda4304c69a725b3)
```

---

### Step 4: Collector Policy Enforcement Gate
Tests the allow-list policy gate when a payload contains a secret pattern in the `context` field or an unauthorized field.

#### 4a. Secret Pattern in Egress Field (Blocked by Collector)
```powershell
python -m collector.cli policy test test_secret_payload.json
```
**Real Output:**
```
EGRESS POLICY BLOCKED PAYLOAD [019349a2-5b98-7c80-87ef-3d9284157a1b]: Security Violation: Secret pattern detected in field 'context'
✗ Policy violation detected! Reason: Security Violation: Secret pattern detected in field 'context'
```

#### 4b. Extra Unknown Field (`password`) Rejection (Enforced by Central SaaS)
The collector's egress filter drops unlisted fields before transmission. If an adversary attempts to bypass the collector and send an extra `"password"` field directly to SaaS, the server-side validator immediately rejects it:

```powershell
python -c "import json; from saas.validate import validate_payload; payload = json.load(open('test_bad_payload.json')); valid, err = validate_payload(payload, tenant_id='acme'); print(f'Valid: {valid}\nError: {err}')"
```
**Real Output:**
```
Validation failure for tenant=acme collector=unknown payload=019349a2-5b98-7c80-87ef-3d9284157a1b
Valid: False
Error: Rejected unknown field 'password' not permitted by allow-list
```

---

### Step 5: Unauthorized Ingest Attempt (401 Response)
Demonstrates that collectors with unknown or invalid API keys receive an immediate HTTP 401:

```powershell
python -c "from saas.ingest import handle_ingest; status, res = handle_ingest(api_key='wrong-key-999', signature='dummy-sig', body_bytes=b'{}'); print(f'Status: {status}\nResponse: {res}')"
```
**Real Output:**
```
Authentication failed: unknown API key
Status: 401
Response: {'error': 'Unauthorized collector credential or invalid HMAC signature'}
```

---

### Step 6: Wrong-Region Ingest Attempt (421 Misdirected Request)
Demonstrates multi-tenant geographic residency enforcement. Tenant `globex` is pinned to region `in`. If a payload arrives at the `eu` SaaS endpoint, it is rejected with HTTP 421:

```powershell
python -c "import os, hmac, hashlib; from saas.ingest import handle_ingest; os.environ['REGION'] = 'eu'; body = b'[]'; sig = hmac.new(b'secret-globex-in1', body, hashlib.sha256).hexdigest(); status, res = handle_ingest(api_key='key-globex-in1-dev', signature=sig, body_bytes=body); print(f'Status: {status}\nResponse: {res}')"
```
**Real Output:**
```
Tenant 'globex' is pinned to region 'in', but arrived at 'eu'
Status: 421
Response: {'error': \"Tenant 'globex' is pinned to region 'in', but arrived at 'eu'\"}
```

---

### Step 7: AIOps Health Inspection (`aiopsctl health`)
Lists entity health states derived from telemetry baselines:

```powershell
python -m saas.cli_aiopsctl health --tenant acme
```
**Real Output:**
```
                      Entity Health Status (Tenant: acme)                      
┌────────┬───────────────┬──────────────┬──────────────────┬──────────────────┐
│ Tenant │ Entity ID     │ Health State │ Reason           │ Updated (UTC)    │
├────────┼───────────────┼──────────────┼──────────────────┼──────────────────┤
│ acme   │ col-acme-eu-1 │ Poor         │ Poor: no         │ 2026-11-20T18:1… │
│        │               │              │ heartbeat for    │                  │
│        │               │              │ 2100 s           │                  │
│ acme   │ col-acme-eu-2 │ Poor         │ Poor: collector  │ 2026-11-20T18:1… │
│        │               │              │ 'col-acme-eu-2'  │                  │
│        │               │              │ has never        │                  │
│        │               │              │ reported         │                  │
│ acme   │ h_1234abcd    │ Poor         │ Poor: data stale │ 2026-11-20T18:1… │
│        │               │              │ for 2100 s       │                  │
└────────┴───────────────┴──────────────┴──────────────────┴──────────────────┘
```

---

### Step 8: Incident Correlation (`aiopsctl incidents`)
Displays correlated incidents aggregated within sliding windows:

```powershell
python -m saas.cli_aiopsctl incidents --tenant acme
```
**Real Output:**
```
                   Correlated AIOps Incidents (Tenant: acme)                   
┌───────────┬──────────┬───────────┬──────────┬───────────┬────────┬──────────┐
│           │          │           │ Root     │           │        │          │
│ Incident  │          │           │ Cause    │ Suppress… │        │ Opened   │
│ ID        │ Severity │ Title     │ Candida… │    Alerts │ Status │ UTC      │
├───────────┼──────────┼───────────┼──────────┼───────────┼────────┼──────────┤
│ inc-01a1… │ CRITICAL │ Incident: │ sw-core… │         0 │ open   │ 2026-11… │
│           │          │ LATENCY   │ (network │           │        │          │
│           │          │ anomaly   │ device)  │           │        │          │
│           │          │ on        │          │           │        │          │
│           │          │ sw-core-… │          │           │        │          │
│           │          │ (network  │          │           │        │          │
│           │          │ device)   │          │           │        │          │
└───────────┴──────────┴───────────┴──────────┴───────────┴────────┴──────────┘
```

---

### Step 9: Root Cause Analysis & Reasoning Path (`aiopsctl why <id>`)
Inspects an incident's root-cause candidate, contributing signals, and deterministic reasoning path:

```powershell
python -m saas.cli_aiopsctl why inc-01a1fa1e-47da-7236-b50f-b994fcd31ab5
```
**Real Output:**
```
═══ Root Cause Analysis: inc-01a1fa1e-47da-7236-b50f-b994fcd31ab5 ═══
Title: Incident: LATENCY anomaly on sw-core-fra-01 (network device)
Root Cause Candidate: sw-core-fra-01 (network device)
Correlated Impact: 1 alerts reduced to 1 incident
Confidence: 75%

Contributing Signals & Standardized Deviations:
  • latency

Reasoning Path & Topological Linkages:
  1. Observed persistent anomaly in latency.
  2. No secondary correlating signals detected within window.
  3. Recommended action: Review service telemetry and component metrics for latency.

Automated Recommendations:
  • Elevated latency anomaly exceeding baseline: Inspect logs and resource utilization for latency
```

*JSON format is also supported:*
```powershell
python -m saas.cli_aiopsctl why inc-01a1fa1e-47da-7236-b50f-b994fcd31ab5 --json
```

---

### Step 10: Live Dashboard Views to Open

Open your browser to `http://localhost:8000/dashboard/`. Paste the tenant token from `.env` (`VIEWER_TOKEN_ACME`) into the login modal. Navigate through these key views:

1. **Fleet Overview**:
   - Four health tiles (`Excellent`, `Good`, `Fair`, `Poor`) displaying real-time counts.
   - Collector status table showing `col-acme-eu-1` and `col-acme-eu-2` with heartbeat, queue depth, and online/offline badges.
2. **Infrastructure**:
   - Real-time CPU, Memory, and Disk charts updating via Server-Sent Events (SSE).
   - Dynamic baseline bands and marked anomaly spikes.
3. **Network**:
   - Latency, Packet Loss, Bandwidth, and Connectivity charts with live streams.
4. **Security**:
   - High-level failed-login aggregations and risk severity indicators (without raw usernames or IPs).
5. **Incidents**:
   - Active incidents with severity badges.
   - Click the **"Why?"** drawer to reveal the contributing signals, confidence score, and topological reasoning path ("*27 alerts reduced to 1 incident*").
6. **Health History**:
   - UTC-stamped timeline showing state transitions (e.g., `Good` → `Poor`) with deterministic reasons.
7. **Remediation**:
   - Automated remediation actions and runbook triggers.
8. **Settings**:
   - Tenant threshold configuration.
9. **Footer Widget**:
   - Real-time end-to-end ingestion latency badge in milliseconds.

---

## 6. Audit & Compatibility Notes (Known Issues & Fixes)

| Observed Issue | Root Cause | Fix / Resolution |
| :--- | :--- | :--- |
| **Windows Console `UnicodeEncodeError` in `aiopsctl why`** | On Windows, PowerShell consoles often use the `cp1252` code page by default, which cannot encode box-drawing characters (`═══`, `•`). | Run `$env:PYTHONIOENCODING = "utf-8"` in PowerShell before running CLI commands, or use the `--json` flag. |
| **`collector policy test` passes payload with extra `"password"` field** | The collector's egress filter is designed to drop unlisted fields automatically so they never reach the wire. It only raises a policy error when an allow-listed field contains a secret pattern. | Server-side validation (`saas/validate.py`) strictly enforces that incoming JSON contains no unexpected keys, returning HTTP 400. To test the collector's rejection gate, use `test_secret_payload.json` where a secret is in an allow-listed field (`context`). |
| **`tools/live_feed_daemon.py` hardcoded port 8000** | The demo daemon connects to `http://127.0.0.1:8000/v1/ingest`. | SaaS EU is launched on port `8000` for native local demos, and port `8002` is used for the IN region. |
| **Dashboard Token Authentication** | All API routes and SSE streams require viewer tokens; missing or invalid tokens return 401 Unauthorized. | Generate tokens with `python tools/gen_tokens.py` and paste `VIEWER_TOKEN_ACME` into the dashboard login dialog. |
