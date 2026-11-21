"""
tools/sim_stream_server.py
───────────────────────────
FastAPI Telemetry Simulator Server.

Emits per-collector telemetry every second:
  - CPU, memory, disk, bandwidth, latency, packet loss, connectivity
  - Auth log lines with realistic usernames, IPs, and occasional fake secrets
  - Diurnal baseline cycle (daily pattern) + Gaussian noise

Exposes POST /inject/{collector_id} to trigger:
  - cpu_spike
  - mem_leak (gradual ramp)
  - latency_rise
  - packet_loss
  - failed_login_burst
  - secret_in_log
  - collector_outage
  - duplicate_delivery
  - out_of_order
"""

from __future__ import annotations

import math
import random
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Query
from pydantic import BaseModel
import uvicorn

app = FastAPI(title="Sentinel Edge Telemetry Simulator", version="2.0.0")

# ── Fleet Topology ────────────────────────────────────────────────────────────

COLLECTORS: dict[str, dict[str, Any]] = {
    "col-acme-eu-1": {
        "tenant_id": "acme",
        "region": "eu-central-1",
        "source": "app-node-01.fra.acme.internal",
        "source_tz": "Europe/Berlin",
        "base": {"cpu": 35.0, "memory": 52.0, "disk": 60.0, "bandwidth": 450.0, "latency": 28.0, "packet_loss": 0.1},
    },
    "col-acme-eu-2": {
        "tenant_id": "acme",
        "region": "eu-central-1",
        "source": "edge-gw-01.lon.acme.internal",
        "source_tz": "Europe/London",
        "base": {"cpu": 28.0, "memory": 45.0, "disk": 50.0, "bandwidth": 600.0, "latency": 22.0, "packet_loss": 0.05},
    },
    "col-globex-in-1": {
        "tenant_id": "globex",
        "region": "ap-south-1",
        "source": "tracking-srv-01.blr.globex.internal",
        "source_tz": "Asia/Kolkata",
        "base": {"cpu": 42.0, "memory": 58.0, "disk": 68.0, "bandwidth": 320.0, "latency": 38.0, "packet_loss": 0.2},
    },
}

# State tracking
_ticks: dict[str, int] = {cid: 0 for cid in COLLECTORS}
_injections: dict[str, dict[str, Any]] = {cid: {} for cid in COLLECTORS}
_mem_leak_accum: dict[str, float] = {cid: 0.0 for cid in COLLECTORS}

FAKE_SECRETS = [
    "password=P@ssw0rd2026!Secured",
    "token=Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-412fake",
    "api_key=AKIAIOSFODNN7EXAMPLE",
    "db_auth=postgres://admin:SuperSecretKey42@10.0.0.5:5432/finance",
    "user_email=ciso-alert@acme-bank.internal secret=corp_token_99182a",
]

USERNAMES = ["alice", "bob.k", "svc_backup", "root", "deployer", "priya.s", "sec_ops"]
INTERNAL_IPS = ["10.10.1.15", "10.10.2.88", "192.168.10.4", "172.16.5.99"]
EXTERNAL_IPS = ["185.220.101.5", "198.51.100.42", "203.0.113.19"]


class ScenarioPayload(BaseModel):
    cpu_spike: Optional[float] = 0.0
    mem_leak: Optional[bool] = False
    latency_rise: Optional[float] = 0.0
    packet_loss: Optional[float] = 0.0
    failed_login_burst: Optional[bool] = False
    secret_in_log: Optional[bool] = False
    collector_outage: Optional[bool] = False
    duplicate_delivery: Optional[bool] = False
    out_of_order: Optional[bool] = False


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok", "collectors": list(COLLECTORS.keys()), "ticks": _ticks}


@app.get("/events")
def get_events(collector_id: str = Query("col-acme-eu-1")) -> list[dict[str, Any]]:
    """
    Returns simulated telemetry events for one second.
    """
    cfg = COLLECTORS.get(collector_id)
    if not cfg:
        # Fallback config if unknown collector requested
        cfg = {
            "tenant_id": "default",
            "region": "global",
            "source": f"{collector_id}.internal",
            "source_tz": "UTC",
            "base": {"cpu": 35.0, "memory": 50.0, "disk": 50.0, "bandwidth": 400.0, "latency": 30.0, "packet_loss": 0.1},
        }

    inj = _injections.get(collector_id, {})

    # Check collector outage scenario
    if inj.get("collector_outage"):
        raise HTTPException(status_code=503, detail="Simulated collector host down / network severed")

    _ticks[collector_id] = _ticks.get(collector_id, 0) + 1
    tick = _ticks[collector_id]

    now = datetime.now(timezone.utc)
    # Diurnal cycle: 24-hour periodic wave
    time_of_day_s = (now.hour * 3600) + (now.minute * 60) + now.second
    diurnal = math.sin(2 * math.pi * (time_of_day_s / 86400.0)) * 8.0

    base = cfg["base"]
    source = cfg["source"]
    source_tz = cfg["source_tz"]

    # Compute metric values with diurnal + noise + injections
    cpu_val = max(1.0, min(100.0, base["cpu"] + diurnal + random.uniform(-3, 3) + inj.get("cpu_spike", 0.0)))
    
    if inj.get("mem_leak"):
        _mem_leak_accum[collector_id] = _mem_leak_accum.get(collector_id, 0.0) + 0.8
    mem_val = max(1.0, min(99.9, base["memory"] + random.uniform(-1, 1) + _mem_leak_accum.get(collector_id, 0.0)))

    disk_val = max(1.0, min(99.0, base["disk"] + random.uniform(-0.1, 0.1)))
    lat_val = max(5.0, base["latency"] + random.uniform(-4, 4) + inj.get("latency_rise", 0.0))
    loss_val = max(0.0, base["packet_loss"] + random.uniform(-0.05, 0.05) + inj.get("packet_loss", 0.0))
    bw_val = max(1.0, base["bandwidth"] + random.uniform(-20, 20) - (inj.get("latency_rise", 0.0) * 0.8))

    events: list[dict[str, Any]] = []

    def mk_metric(cat: str, val: float, unit: str) -> dict[str, Any]:
        return {
            "category": cat,
            "value": round(val, 2),
            "unit": unit,
            "source": source,
            "source_tz": source_tz,
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "raw_text": f"{cat}={val:.2f}{unit} host={source}",
        }

    events.append(mk_metric("cpu", cpu_val, "percent"))
    events.append(mk_metric("memory", mem_val, "percent"))
    events.append(mk_metric("disk", disk_val, "percent"))
    events.append(mk_metric("bandwidth", bw_val, "mbps"))
    events.append(mk_metric("latency", lat_val, "ms"))
    events.append(mk_metric("packet_loss", loss_val, "percent"))
    events.append({
        "category": "connectivity",
        "value": 1.0,
        "unit": "boolean",
        "source": source,
        "source_tz": source_tz,
        "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "raw_text": f"heartbeat seq={tick} host={source}",
    })

    # Auth logs & Secret Injection
    auth_lines: list[str] = []
    user = random.choice(USERNAMES)
    src_ip = random.choice(INTERNAL_IPS)
    auth_lines.append(f"sshd[{1000 + (tick % 5000)}]: Accepted publickey for {user} from {src_ip} port {random.randint(30000, 60000)} ssh2")

    if inj.get("failed_login_burst"):
        for i in range(4):
            ext_ip = random.choice(EXTERNAL_IPS)
            auth_lines.append(
                f"sshd[{2000 + i}]: Failed password for root from {ext_ip} port {random.randint(40000, 65000)} ssh2 password=hunter2_{i}"
            )
    elif tick % 8 == 0 or inj.get("secret_in_log"):
        secret = random.choice(FAKE_SECRETS)
        auth_lines.append(f"app-service: auth check failed user={user} ip={src_ip} {secret}")

    for line in auth_lines:
        events.append({
            "category": "auth",
            "value": 1.0 if "Failed password" in line else 0.0,
            "unit": "count",
            "source": source,
            "source_tz": source_tz,
            "timestamp": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "raw_text": line,
        })

    # Duplication scenario: duplicate the first 2 events
    if inj.get("duplicate_delivery") and len(events) >= 2:
        events.extend([dict(events[0]), dict(events[1])])

    # Out-of-order scenario: jitter timestamps in the past
    if inj.get("out_of_order") and len(events) >= 3:
        random.shuffle(events)
        for i, ev in enumerate(events):
            jitter_sec = (i * 3)
            ev_ts = now - timedelta(seconds=jitter_sec)
            ev["timestamp"] = ev_ts.strftime("%Y-%m-%dT%H:%M:%SZ")

    return events


@app.post("/inject/{collector_id}")
def set_injection(collector_id: str, scenario: ScenarioPayload) -> dict[str, Any]:
    _injections[collector_id] = scenario.model_dump()
    return {"status": "ok", "collector_id": collector_id, "active_scenario": _injections[collector_id]}


@app.post("/clear/{collector_id}")
def clear_injection(collector_id: str) -> dict[str, Any]:
    if collector_id in ("all", "fleet"):
        for cid in COLLECTORS:
            _injections[cid] = {}
            _mem_leak_accum[cid] = 0.0
        return {"status": "all_cleared", "collectors": list(COLLECTORS.keys())}
    _injections[collector_id] = {}
    _mem_leak_accum[collector_id] = 0.0
    return {"status": "cleared", "collector_id": collector_id}


@app.post("/clear")
def clear_all_injections() -> dict[str, Any]:
    for cid in COLLECTORS:
        _injections[cid] = {}
        _mem_leak_accum[cid] = 0.0
    return {"status": "all_cleared", "collectors": list(COLLECTORS.keys())}


if __name__ == "__main__":
    uvicorn.run("tools.sim_stream_server:app", host="0.0.0.0", port=9000, reload=True)
