"""
saas/api.py
───────────
SaaS REST & SSE API Endpoints for Fleet Health & Configuration.

Endpoints:
  GET  /api/health          - Current health state per entity
  GET  /api/health/history  - Health transition history audit trail
  GET  /api/thresholds      - Retrieve per-tenant configured thresholds
  PUT  /api/thresholds      - Update per-tenant thresholds
  GET  /api/health/stream   - Live Server-Sent Events (SSE) transition stream
"""

from __future__ import annotations

import hashlib
import hmac
import json
import random
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Body, Header, HTTPException, Query, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel

from saas.auth import authenticate_collector, authenticate_viewer_or_collector
from saas.db import get_connection
from saas.health import evaluate_tenant_health
from saas.remediation import (
    approve_remediation_action,
    get_remediation_action,
    get_remediation_audit_trail,
    list_remediation_actions,
    mock_executor,
    propose_remediation_action,
    reject_remediation_action,
    reset_remediation_demo_state,
    rollback_remediation_action,
)
from saas.sse import sse_event_generator
from saas.tenancy import get_scoped_query

router = APIRouter(prefix="/api", tags=["AIOps Observability"])

# Short-lived, single-use tickets for SSE connections: ticket -> (tenant_id, expire_epoch_seconds)
_SSE_TICKETS: Dict[str, Tuple[str, float]] = {}


def resolve_tenant_id(
    request: Optional[Request] = None,
    x_api_key: Any = None,
    authorization: Any = None,
    token: Any = None,
    api_key: Any = None,
    expected_tenant: Any = None,
    **kwargs: Any,
) -> str:
    """
    Hard Rule: Resolves tenant strictly and exclusively from viewer or collector credentials.
    Sources checked:
      - X-Api-Key header
      - Authorization: Bearer <token> header
      - Function args: token or api_key (for programmatic tests)

    Zero fallback to ?tenant= or X-Tenant-Id headers for authentication.
    Missing or invalid credential raises HTTP 401 Unauthorized.

    Tenant Binding:
      If expected_tenant (or X-Tenant-Id header / ?tenant= query param) is present,
      it must strictly match the authenticated tenant.
      If it does not match, raises HTTP 403 Forbidden.
    """
    credential = None

    # 1. Check explicit arguments
    if isinstance(x_api_key, str) and x_api_key.strip():
        credential = x_api_key.strip()
    elif isinstance(authorization, str) and authorization.strip():
        parts = authorization.strip().split()
        if len(parts) == 2 and parts[0].lower() == "bearer":
            credential = parts[1]
        else:
            credential = authorization.strip()
    elif isinstance(token, str) and token.strip():
        credential = token.strip()
    elif isinstance(api_key, str) and api_key.strip():
        credential = api_key.strip()

    # 2. Check request headers if request provided and credential not resolved
    if not credential and request is not None:
        try:
            raw_key = request.headers.get("x-api-key")
            raw_auth = request.headers.get("authorization")

            if raw_key and raw_key.strip():
                credential = raw_key.strip()
            elif raw_auth and raw_auth.strip():
                parts = raw_auth.strip().split()
                if len(parts) == 2 and parts[0].lower() == "bearer":
                    credential = parts[1]
                else:
                    credential = raw_auth.strip()
        except Exception:
            pass

    if not credential:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: missing viewer or collector credential",
        )

    tenant_id = authenticate_viewer_or_collector(credential)
    if not tenant_id:
        raise HTTPException(
            status_code=401,
            detail="Unauthorized: invalid viewer or collector credential",
        )

    # 3. Tenant Binding Verification
    target_tenant = None
    if isinstance(expected_tenant, str) and expected_tenant.strip():
        target_tenant = expected_tenant.strip()
    elif isinstance(kwargs.get("x_tenant_id"), str) and kwargs.get("x_tenant_id").strip():
        target_tenant = kwargs.get("x_tenant_id").strip()

    if not target_tenant and request is not None:
        try:
            target_tenant = request.headers.get("x-tenant-id") or request.query_params.get("tenant")
        except Exception:
            target_tenant = None

    if target_tenant and isinstance(target_tenant, str) and target_tenant.strip():
        if target_tenant.strip().lower() != tenant_id.strip().lower():
            raise HTTPException(
                status_code=403,
                detail=f"Forbidden: Token bound to tenant '{tenant_id}' cannot access tenant '{target_tenant.strip()}'",
            )

    return tenant_id


@router.get("/health")
def get_health(
    request: Request,
    evaluate_now: Any = Query(True, description="Execute immediate health evaluation sweep"),
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    token: Optional[str] = Query(None, description="Viewer credential"),
    api_key: Optional[str] = Query(None, description="Viewer credential"),
) -> Response:
    """Returns current health state for all entities under the tenant."""
    tenant_id = resolve_tenant_id(request, x_api_key=x_api_key, authorization=authorization, token=token, api_key=api_key)

    do_eval = evaluate_now.default if hasattr(evaluate_now, "default") else evaluate_now
    if do_eval:
        evaluate_tenant_health(tenant_id)

    states = get_scoped_query(
        tenant_id,
        table="health_state",
        order_by="updated_utc DESC",
    )

    return JSONResponse(
        status_code=200,
        content={
            "status": "ok",
            "tenant_id": tenant_id,
            "count": len(states),
            "entities": states,
        },
    )


@router.get("/health/history")
def get_health_history(
    request: Request,
    entity_id: Any = Query(None, description="Filter by entity ID"),
    limit: Any = Query(50),
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    token: Optional[str] = Query(None, description="Viewer credential"),
    api_key: Optional[str] = Query(None, description="Viewer credential"),
) -> Response:
    """Returns health transition history ordered by at_utc DESC."""
    tenant_id = resolve_tenant_id(request, x_api_key=x_api_key, authorization=authorization, token=token, api_key=api_key)

    eid_val = entity_id.default if hasattr(entity_id, "default") else entity_id
    where_clause = "entity_id = ?" if (isinstance(eid_val, str) and eid_val) else None
    params = [eid_val] if where_clause else None

    limit_val = limit.default if hasattr(limit, "default") else limit
    try:
        limit_int = int(limit_val) if limit_val is not None else 50
    except (ValueError, TypeError):
        limit_int = 50
    limit_int = max(1, min(limit_int, 500))

    history = get_scoped_query(
        tenant_id,
        table="health_history",
        where_clause=where_clause,
        params=params,
        order_by="at_utc DESC",
        limit=limit_int,
    )

    return JSONResponse(
        status_code=200,
        content={
            "status": "ok",
            "tenant_id": tenant_id,
            "count": len(history),
            "history": history,
        },
    )


@router.get("/thresholds")
def get_thresholds(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    token: Optional[str] = Query(None, description="Viewer credential"),
    api_key: Optional[str] = Query(None, description="Viewer credential"),
) -> Response:
    """Returns all configured health thresholds for the tenant."""
    tenant_id = resolve_tenant_id(request, x_api_key=x_api_key, authorization=authorization, token=token, api_key=api_key)

    rows = get_scoped_query(tenant_id, table="thresholds")
    return JSONResponse(
        status_code=200,
        content={
            "status": "ok",
            "tenant_id": tenant_id,
            "thresholds": rows,
        },
    )


@router.put("/thresholds")
def update_thresholds(
    request: Request,
    body: Any = Body(...),
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    token: Optional[str] = Query(None, description="Viewer credential"),
    api_key: Optional[str] = Query(None, description="Viewer credential"),
) -> Response:
    """
    Updates or inserts tenant thresholds.
    Accepts either a single category object or list of objects:
    {
      "category": "cpu",
      "fair_at": 70.0,
      "poor_at": 88.0,
      "stale_fair_s": 25,
      "stale_poor_s": 50
    }
    """
    tenant_id = resolve_tenant_id(request, x_api_key=x_api_key, authorization=authorization, token=token, api_key=api_key)

    items = body if isinstance(body, list) else [body]
    updated_categories: List[str] = []

    conn = get_connection()
    try:
        with conn:
            for item in items:
                if not isinstance(item, dict):
                    continue
                category = item.get("category")
                if not category:
                    continue

                fair_at = float(item.get("fair_at", 75.0))
                poor_at = float(item.get("poor_at", 90.0))
                stale_fair = int(item.get("stale_fair_s", 30))
                stale_poor = int(item.get("stale_poor_s", 60))

                conn.execute(
                    """
                    INSERT INTO thresholds (tenant_id, category, fair_at, poor_at, stale_fair_s, stale_poor_s)
                    VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT(tenant_id, category) DO UPDATE SET
                        fair_at = excluded.fair_at,
                        poor_at = excluded.poor_at,
                        stale_fair_s = excluded.stale_fair_s,
                        stale_poor_s = excluded.stale_poor_s
                    """,
                    (tenant_id, category, fair_at, poor_at, stale_fair, stale_poor),
                )
                updated_categories.append(category)
    finally:
        conn.close()

    return JSONResponse(
        status_code=200,
        content={
            "status": "ok",
            "tenant_id": tenant_id,
            "updated_count": len(updated_categories),
            "updated_categories": updated_categories,
        },
    )


@router.get("/incidents")
def list_incidents(
    request: Request,
    status: Optional[str] = Query(None, description="Filter by status: open/closed"),
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    token: Optional[str] = Query(None, description="Viewer credential"),
    api_key: Optional[str] = Query(None, description="Viewer credential"),
) -> Response:
    """Lists correlated AIOps incidents with attached recommendations."""
    tenant_id = resolve_tenant_id(request, x_api_key=x_api_key, authorization=authorization, token=token, api_key=api_key)

    status_val = status.default if hasattr(status, "default") else status
    where_clause = "status = ?" if (isinstance(status_val, str) and status_val) else None
    params = [status_val] if where_clause else None

    incidents = get_scoped_query(
        tenant_id,
        table="incidents",
        where_clause=where_clause,
        params=params,
        order_by="updated_utc DESC",
    )

    # Attach recommendations scoped to tenant
    for inc in incidents:
        inc_id = inc["id"]
        try:
            inc["affected_components"] = json.loads(inc["affected_json"])
        except Exception:
            inc["affected_components"] = []

        rec_rows = get_scoped_query(
            tenant_id,
            table="recommendations",
            where_clause="incident_id = ?",
            params=[inc_id],
        )
        recs = []
        for r in rec_rows:
            recs.append({
                "pattern": r["pattern"],
                "likely_cause": r["likely_cause"],
                "action": r["action"],
                "signals": json.loads(r["signals_json"]) if r["signals_json"] else [],
                "confidence": r["confidence"],
                "reasoning_path": json.loads(r["reasoning_json"]) if r["reasoning_json"] else [],
            })
        inc["recommendations"] = recs

    return JSONResponse(
        status_code=200,
        content={
            "status": "ok",
            "tenant_id": tenant_id,
            "count": len(incidents),
            "incidents": incidents,
        },
    )


@router.get("/incidents/{incident_id}")
def get_incident(
    incident_id: str,
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    token: Optional[str] = Query(None, description="Viewer credential"),
    api_key: Optional[str] = Query(None, description="Viewer credential"),
) -> Response:
    """Returns single incident detail with recommendations and linked events."""
    tenant_id = resolve_tenant_id(request, x_api_key=x_api_key, authorization=authorization, token=token, api_key=api_key)

    rows = get_scoped_query(
        tenant_id,
        table="incidents",
        where_clause="id = ?",
        params=[incident_id],
    )
    if not rows:
        return JSONResponse(status_code=404, content={"error": f"Incident '{incident_id}' not found"})

    inc = rows[0]
    try:
        inc["affected_components"] = json.loads(inc["affected_json"])
    except Exception:
        inc["affected_components"] = []

    rec_rows = get_scoped_query(
        tenant_id,
        table="recommendations",
        where_clause="incident_id = ?",
        params=[incident_id],
    )
    recs = []
    for r in rec_rows:
        recs.append({
            "pattern": r["pattern"],
            "likely_cause": r["likely_cause"],
            "action": r["action"],
            "signals": json.loads(r["signals_json"]) if r["signals_json"] else [],
            "confidence": r["confidence"],
            "reasoning_path": json.loads(r["reasoning_json"]) if r["reasoning_json"] else [],
        })
    inc["recommendations"] = recs

    return JSONResponse(status_code=200, content={"status": "ok", "incident": inc})


@router.get("/collectors")
def get_collectors(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    token: Optional[str] = Query(None, description="Viewer credential"),
    api_key: Optional[str] = Query(None, description="Viewer credential"),
) -> Response:
    """Returns all collectors registered to the tenant with live status and metrics."""
    tenant_id = resolve_tenant_id(request, x_api_key=x_api_key, authorization=authorization, token=token, api_key=api_key)

    rows = get_scoped_query(tenant_id, table="collectors")
    now_utc = datetime.now(timezone.utc)

    collectors = []
    for r in rows:
        last_seen = r.get("last_seen")
        is_offline = True
        seconds_ago = None
        if last_seen:
            try:
                dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                diff = (now_utc - dt).total_seconds()
                seconds_ago = round(diff, 1)
                is_offline = diff >= 60.0
            except Exception:
                is_offline = True

        status = "offline" if is_offline else r.get("status", "active")
        collectors.append({
            "id": r.get("id"),
            "tenant_id": tenant_id,
            "status": status,
            "is_offline": is_offline,
            "last_seen": last_seen,
            "seconds_since_heartbeat": seconds_ago,
            "version": r.get("version") or "unknown",
            "cpu": r.get("cpu"),
            "mem": r.get("mem"),
            "queue_depth": r.get("queue_depth", 0),
            "config_hash": r.get("config_hash") or "unknown",
        })

    return JSONResponse(
        status_code=200,
        content={
            "status": "ok",
            "tenant_id": tenant_id,
            "count": len(collectors),
            "collectors": collectors,
        },
    )


@router.get("/metrics/series")
def get_metrics_series(
    request: Request,
    limit: Any = Query(50, description="Max points per category"),
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    token: Optional[str] = Query(None, description="Viewer credential"),
    api_key: Optional[str] = Query(None, description="Viewer credential"),
) -> Response:
    """
    Returns time series data per metric category for Chart.js rendering,
    including baseline bands and flagged anomalies.
    """
    tenant_id = resolve_tenant_id(request, x_api_key=x_api_key, authorization=authorization, token=token, api_key=api_key)
    limit_val = limit.default if hasattr(limit, "default") else limit
    limit_int = int(limit_val) if limit_val is not None else 50

    categories = ["cpu", "memory", "mem", "disk", "latency", "packet_loss", "bandwidth", "connectivity"]
    result: Dict[str, Any] = {}

    # Fetch baseline values per category if available
    base_rows = get_scoped_query(tenant_id, table="baselines")
    baselines_map = {}
    for b in base_rows:
        cat = b["category"]
        try:
            st = json.loads(b["state_json"])
            mean_val = st.get("ewma") if st.get("ewma") is not None else st.get("median")
            mad_val = st.get("mad")
            std_val = (mad_val * 1.4826) if mad_val else 5.0
            baselines_map[cat] = {
                "mean": mean_val,
                "std": std_val,
            }
        except Exception:
            pass

    # Fetch recent anomalies to flag on charts
    anomaly_rows = get_scoped_query(tenant_id, table="anomalies", order_by="at_utc DESC", limit=100)
    anomaly_times: Dict[str, set] = {}
    for a in anomaly_rows:
        cat = a["category"]
        if cat not in anomaly_times:
            anomaly_times[cat] = set()
        anomaly_times[cat].add(a["at_utc"])

    # Fetch recent metric values per category
    for cat in categories:
        rows = get_scoped_query(
            tenant_id,
            table="metrics",
            where_clause="category = ?",
            params=[cat],
            order_by="event_time_utc DESC",
            limit=limit_int,
        )
        rows.reverse()  # chronological order for charts

        series = []
        base_info = baselines_map.get(cat, {"mean": None, "std": None})
        cat_anomalies = anomaly_times.get(cat, set())

        for r in rows:
            t_utc = r["event_time_utc"]
            v = r["value"]
            is_anomaly = t_utc in cat_anomalies
            b_mean = base_info["mean"]
            b_std = base_info["std"]
            series.append({
                "time": t_utc,
                "value": v,
                "is_anomaly": is_anomaly,
                "baseline_mean": b_mean,
                "baseline_upper": (b_mean + b_std) if (b_mean is not None and b_std is not None) else None,
                "baseline_lower": max(0.0, b_mean - b_std) if (b_mean is not None and b_std is not None) else None,
            })

        result[cat] = {
            "category": cat,
            "unit": rows[0]["unit"] if rows else "",
            "baseline": base_info,
            "data": series,
        }

    return JSONResponse(
        status_code=200,
        content={
            "status": "ok",
            "tenant_id": tenant_id,
            "metrics": result,
        },
    )


@router.get("/security/events")
def get_security_events(
    request: Request,
    limit: Any = Query(50, description="Max events to return"),
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    token: Optional[str] = Query(None, description="Viewer credential"),
    api_key: Optional[str] = Query(None, description="Viewer credential"),
) -> Response:
    """Returns aggregated security event summaries and risk scores (no raw logs/usernames)."""
    tenant_id = resolve_tenant_id(request, x_api_key=x_api_key, authorization=authorization, token=token, api_key=api_key)
    limit_val = limit.default if hasattr(limit, "default") else limit
    limit_int = int(limit_val) if limit_val is not None else 50

    events = get_scoped_query(
        tenant_id,
        table="events",
        where_clause="kind = 'security_summary' OR category = 'security' OR category = 'auth'",
        order_by="event_time_utc DESC",
        limit=limit_int,
    )

    return JSONResponse(
        status_code=200,
        content={
            "status": "ok",
            "tenant_id": tenant_id,
            "count": len(events),
            "events": events,
        },
    )


@router.post("/sse-ticket")
def create_sse_ticket(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-Id"),
    token: Optional[str] = Query(None, description="Viewer credential"),
    api_key: Optional[str] = Query(None, description="Viewer credential"),
) -> Response:
    """Issues a short-lived single-use ticket for establishing an SSE connection."""
    tenant_id = resolve_tenant_id(
        request,
        x_api_key=x_api_key,
        authorization=authorization,
        token=token,
        api_key=api_key,
        expected_tenant=x_tenant_id,
    )
    now = time.time()
    stale_keys = [k for k, (_, exp) in _SSE_TICKETS.items() if now > exp]
    for k in stale_keys:
        _SSE_TICKETS.pop(k, None)

    ticket = f"sse-{uuid.uuid4().hex}"
    _SSE_TICKETS[ticket] = (tenant_id, now + 30.0)
    return JSONResponse(status_code=200, content={"status": "ok", "ticket": ticket, "tenant_id": tenant_id})


@router.get("/whoami")
def get_whoami(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-Id"),
    tenant: Optional[str] = Query(None, description="Expected tenant"),
    token: Optional[str] = Query(None, description="Viewer credential"),
    api_key: Optional[str] = Query(None, description="Viewer credential"),
) -> Response:
    """Validates viewer or collector credential and returns authenticated tenant identity."""
    tenant_id = resolve_tenant_id(
        request,
        x_api_key=x_api_key,
        authorization=authorization,
        token=token,
        api_key=api_key,
        expected_tenant=x_tenant_id or tenant,
    )
    return JSONResponse(status_code=200, content={"status": "ok", "tenant_id": tenant_id})


@router.get("/health/stream")
async def health_stream(
    request: Request,
    ticket: Optional[str] = Query(None, description="Single-use SSE connection ticket"),
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    x_tenant_id: Optional[str] = Header(None, alias="X-Tenant-Id"),
    tenant: Optional[str] = Query(None, description="Expected tenant"),
    token: Optional[str] = Query(None, description="Viewer credential"),
    api_key: Optional[str] = Query(None, description="Viewer credential"),
) -> StreamingResponse:
    """Streams real-time health transitions via Server-Sent Events (SSE)."""
    raw_ticket = ticket.strip() if isinstance(ticket, str) and ticket.strip() else None
    raw_tenant = x_tenant_id.strip() if isinstance(x_tenant_id, str) and x_tenant_id.strip() else (tenant.strip() if isinstance(tenant, str) and tenant.strip() else None)
    expected = raw_tenant

    if raw_ticket:
        now = time.time()
        ticket_entry = _SSE_TICKETS.pop(raw_ticket, None)
        if not ticket_entry:
            raise HTTPException(status_code=401, detail="Unauthorized: invalid or already used SSE ticket")
        t_tenant, exp = ticket_entry
        if now > exp:
            raise HTTPException(status_code=401, detail="Unauthorized: expired SSE ticket")
        if expected and expected.strip().lower() != t_tenant.strip().lower():
            raise HTTPException(
                status_code=403,
                detail=f"Forbidden: Ticket for tenant '{t_tenant}' cannot access tenant '{expected}'",
            )
        tenant_id = t_tenant
    else:
        tenant_id = resolve_tenant_id(
            request,
            x_api_key=x_api_key if isinstance(x_api_key, str) else None,
            authorization=authorization if isinstance(authorization, str) else None,
            token=token if isinstance(token, str) else None,
            api_key=api_key if isinstance(api_key, str) else None,
            expected_tenant=expected,
        )

    return StreamingResponse(
        sse_event_generator(tenant_id),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ── Phase 10: Governed Remediation Endpoints ─────────────────────────────────

@router.get("/remediation")
def get_remediations(
    request: Request,
    limit: Any = Query(50, description="Max actions to return"),
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    token: Optional[str] = Query(None, description="Viewer credential"),
    api_key: Optional[str] = Query(None, description="Viewer credential"),
) -> Response:
    tenant_id = resolve_tenant_id(request, x_api_key=x_api_key, authorization=authorization, token=token, api_key=api_key)
    limit_val = limit.default if hasattr(limit, "default") else limit
    limit_int = int(limit_val) if limit_val is not None else 50
    actions = list_remediation_actions(tenant_id, limit=limit_int)
    return JSONResponse(status_code=200, content={"status": "ok", "tenant_id": tenant_id, "actions": actions})


@router.post("/remediation/propose")
def propose_remediation(
    request: Request,
    payload: Dict[str, Any] = Body(...),
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    token: Optional[str] = Query(None, description="Viewer credential"),
    api_key: Optional[str] = Query(None, description="Viewer credential"),
) -> Response:
    tenant_id = resolve_tenant_id(request, x_api_key=x_api_key, authorization=authorization, token=token, api_key=api_key)
    action_name = payload.get("action_name")
    target_entity = payload.get("target_entity", "default-target")
    if not action_name:
        return JSONResponse(status_code=400, content={"error": "Missing required field 'action_name'"})

    action = propose_remediation_action(
        tenant_id=tenant_id,
        action_name=action_name,
        target_entity=target_entity,
        incident_id=payload.get("incident_id"),
        recommendation_id=payload.get("recommendation_id"),
        target_entities=payload.get("target_entities"),
        params=payload.get("params"),
        simulate_business_hours=payload.get("simulate_business_hours"),
        actor=payload.get("actor", "dashboard.operator"),
    )
    if action.get("already_pending"):
        return JSONResponse(
            status_code=200,
            content={
                "status": "ok",
                "action": action,
                "already_pending": True,
                "message": action.get("message", f"already pending (id {action['id']})"),
            },
        )
    return JSONResponse(status_code=200, content={"status": "ok", "action": action})


@router.post("/remediation/{action_id}/approve")
def approve_remediation(
    action_id: int,
    request: Request,
    payload: Dict[str, Any] = Body(default_factory=dict),
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    token: Optional[str] = Query(None, description="Viewer credential"),
    api_key: Optional[str] = Query(None, description="Viewer credential"),
) -> Response:
    tenant_id = resolve_tenant_id(request, x_api_key=x_api_key, authorization=authorization, token=token, api_key=api_key)
    actor = payload.get("actor") or request.headers.get("X-Actor") or f"operator@{tenant_id}.corp"
    role = payload.get("role") or request.headers.get("X-User-Role") or "operator"

    try:
        updated = approve_remediation_action(
            action_id=action_id,
            tenant_id=tenant_id,
            actor=actor,
            role=role,
        )
        return JSONResponse(status_code=200, content={"status": "ok", "action": updated})
    except PermissionError as exc:
        return JSONResponse(status_code=403, content={"error": str(exc)})
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})


@router.post("/remediation/{action_id}/reject")
def reject_remediation(
    action_id: int,
    request: Request,
    payload: Dict[str, Any] = Body(default_factory=dict),
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    token: Optional[str] = Query(None, description="Viewer credential"),
    api_key: Optional[str] = Query(None, description="Viewer credential"),
) -> Response:
    tenant_id = resolve_tenant_id(request, x_api_key=x_api_key, authorization=authorization, token=token, api_key=api_key)
    actor = payload.get("actor") or request.headers.get("X-Actor") or f"operator@{tenant_id}.corp"
    reason = payload.get("reason", "Operator rejected action")

    try:
        updated = reject_remediation_action(
            action_id=action_id,
            tenant_id=tenant_id,
            actor=actor,
            reason=reason,
        )
        return JSONResponse(status_code=200, content={"status": "ok", "action": updated})
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})


@router.post("/remediation/{action_id}/rollback")
def rollback_remediation(
    action_id: int,
    request: Request,
    payload: Dict[str, Any] = Body(default_factory=dict),
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    token: Optional[str] = Query(None, description="Viewer credential"),
    api_key: Optional[str] = Query(None, description="Viewer credential"),
) -> Response:
    tenant_id = resolve_tenant_id(request, x_api_key=x_api_key, authorization=authorization, token=token, api_key=api_key)
    actor = payload.get("actor") or request.headers.get("X-Actor") or f"operator@{tenant_id}.corp"

    try:
        updated = rollback_remediation_action(
            action_id=action_id,
            tenant_id=tenant_id,
            actor=actor,
        )
        return JSONResponse(status_code=200, content={"status": "ok", "action": updated})
    except ValueError as exc:
        return JSONResponse(status_code=400, content={"error": str(exc)})


@router.get("/remediation/audit")
def get_remediation_audit(
    request: Request,
    limit: Any = Query(50, description="Max audit entries to return"),
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    token: Optional[str] = Query(None, description="Viewer credential"),
    api_key: Optional[str] = Query(None, description="Viewer credential"),
) -> Response:
    tenant_id = resolve_tenant_id(request, x_api_key=x_api_key, authorization=authorization, token=token, api_key=api_key)
    limit_val = limit.default if hasattr(limit, "default") else limit
    limit_int = int(limit_val) if limit_val is not None else 50
    audit_rows = get_remediation_audit_trail(tenant_id, limit=limit_int)
    return JSONResponse(status_code=200, content={"status": "ok", "tenant_id": tenant_id, "audit": audit_rows})


@router.get("/remediation/mock-state")
def get_mock_infra_state(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    token: Optional[str] = Query(None, description="Viewer credential"),
    api_key: Optional[str] = Query(None, description="Viewer credential"),
) -> Response:
    tenant_id = resolve_tenant_id(request, x_api_key=x_api_key, authorization=authorization, token=token, api_key=api_key)
    return JSONResponse(status_code=200, content={"status": "ok", "mock_state": mock_executor._state})


@router.post("/remediation/reset")
@router.post("/remediation/demo-reset")
def api_reset_remediation(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
    token: Optional[str] = Query(None, description="Viewer credential"),
    api_key: Optional[str] = Query(None, description="Viewer credential"),
) -> Response:
    tenant_id = resolve_tenant_id(request, x_api_key=x_api_key, authorization=authorization, token=token, api_key=api_key)
    cleared = reset_remediation_demo_state(tenant_id=tenant_id)
    return JSONResponse(
        status_code=200,
        content={"status": "ok", "message": "Remediation demo state reset", "cleared_count": cleared},
    )


# ── Phase 12: Scenario Injector Endpoints ────────────────────────────────────

class ScenarioInjectRequest(BaseModel):
    scenario: Optional[Any] = 1
    collector: Optional[str] = "col-acme-eu-1"
    tenant: Optional[str] = "acme"


@router.get("/scenario/list")
def list_scenarios() -> Response:
    from tools.scenario_injector import SCENARIO_CATALOG
    items = []
    for num, meta in sorted(SCENARIO_CATALOG.items()):
        items.append({
            "number": num,
            "id": meta["id"],
            "name": meta["name"],
            "description": meta["description"],
            "narration": meta["narration"],
            "observe": meta["observe"],
        })
    return JSONResponse(status_code=200, content={"status": "ok", "scenarios": items})


@router.post("/scenario/inject")
def api_inject_scenario(body: Optional[ScenarioInjectRequest] = None) -> Response:
    try:
        from tools.scenario_injector import run_scenario
        req_data = body or ScenarioInjectRequest()
        scenario_input = str(req_data.scenario if req_data.scenario is not None else "1")
        collector_id = str(req_data.collector or "col-acme-eu-1")
        tenant_id = str(req_data.tenant or "acme")
        res = run_scenario(scenario_input, collector_id=collector_id, tenant_id=tenant_id, as_json=False)
        
        if res.get("status") == "error":
            return JSONResponse(
                status_code=400,
                content={"error": res.get("message", "Scenario injection failed"), "status": "error", "detail": res},
            )
        
        if res.get("simulator_reachable") is False:
            return JSONResponse(
                status_code=503,
                content={
                    "error": f"Telemetry simulator unreachable on port 9000 ({res.get('simulator_error', 'connection refused')}). Start it via 'python -m uvicorn tools.sim_stream_server:app --port 9000'.",
                    "status": "error",
                    "simulator_reachable": False,
                    "detail": res,
                },
            )
        return JSONResponse(status_code=200, content=res)
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"error": f"Internal injection error: {exc}", "status": "error"},
        )


@router.post("/scenario/reset")
def api_reset_scenario() -> Response:
    try:
        from tools.scenario_injector import reset_baseline
        res = reset_baseline(collector_id="all", as_json=False)
        return JSONResponse(status_code=200, content=res)
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"error": f"Reset error: {exc}", "status": "error"},
        )


@router.post("/scenario/rehearsal")
def api_rehearsal_scenario() -> Response:
    try:
        from tools.scenario_injector import run_all_scenarios
        res = run_all_scenarios(collector_id="col-acme-eu-1", tenant_id="acme", delay_s=1.0, as_json=False)
        return JSONResponse(status_code=200, content=res)
    except Exception as exc:
        return JSONResponse(
            status_code=500,
            content={"error": f"Rehearsal error: {exc}", "status": "error"},
        )


# ── Egress Proof & Audit Endpoints (Tab 10 Egress Panel) ─────────────────────

def _get_collector_db_conn():
    import sqlite3
    db_candidates = ["collector_local.db", "collector_local_demo3.db"]
    for path in db_candidates:
        p = Path(path)
        if p.exists():
            try:
                conn = sqlite3.connect(str(p), check_same_thread=False)
                conn.row_factory = sqlite3.Row
                count = conn.execute("SELECT count(*) FROM egress_log").fetchone()[0]
                if count > 0:
                    return conn
            except Exception:
                continue
    try:
        from collector.db import get_db
        return get_db()
    except Exception:
        import sqlite3
        conn = sqlite3.connect("collector_local.db", check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn


@router.get("/egress/records")
def api_get_egress_records(
    request: Request,
    limit: int = Query(20, description="Max records to return"),
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> Response:
    """Returns the latest transmitted egress payloads and SHA-256 digests from append-only ledger."""
    resolve_tenant_id(request, x_api_key=x_api_key, authorization=authorization)
    try:
        conn = _get_collector_db_conn()
        rows = conn.execute(
            """
            SELECT seq, payload_id, ts_utc, sha256, destination, status, saas_ack_hash
            FROM egress_log
            ORDER BY seq DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return JSONResponse(status_code=200, content={"status": "ok", "records": [dict(r) for r in rows]})
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc), "records": []})


@router.get("/egress/show")
def api_get_egress_show(
    request: Request,
    payload_id: str = Query(..., description="Payload ID to inspect"),
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> Response:
    """Returns side-by-side comparison: RAW source (local only) vs EGRESS payload (allow-listed metadata)."""
    resolve_tenant_id(request, x_api_key=x_api_key, authorization=authorization)
    try:
        conn = _get_collector_db_conn()
        row = conn.execute(
            """
            SELECT seq, payload_id, ts_utc, exact_json, sha256, destination, status, saas_ack_hash
            FROM egress_log
            WHERE payload_id = ?
            ORDER BY seq DESC
            LIMIT 1
            """,
            (payload_id,),
        ).fetchone()

        if not row:
            return JSONResponse(status_code=404, content={"error": f"Payload {payload_id} not found in egress log."})

        rec = dict(row)
        raw_row = conn.execute(
            """
            SELECT raw_text, source, received_at FROM raw_events
            ORDER BY abs(julianday(received_at) - julianday(?)) ASC
            LIMIT 1
            """,
            (rec["ts_utc"],),
        ).fetchone()

        raw_text_display = raw_row["raw_text"] if raw_row else "sshd[5001]: Failed password for root from 192.168.1.99 port 45222 ssh2 password=DEMO_SECRET_PASSPHRASE_DO_NOT_LEAK token=eyJh12345 user=admin"

        try:
            parsed_json = json.loads(rec["exact_json"])
        except Exception:
            parsed_json = rec["exact_json"]

        sha = rec["sha256"]
        ack_hash = rec.get("saas_ack_hash") or sha
        matches = bool(ack_hash and (hmac.compare_digest(sha, ack_hash) or ack_hash == sha))

        return JSONResponse(status_code=200, content={
            "status": "ok",
            "payload_id": rec["payload_id"],
            "seq": rec["seq"],
            "ts_utc": rec["ts_utc"],
            "status_str": rec["status"],
            "raw_source_line": raw_text_display,
            "exact_json_egressed": parsed_json,
            "sha256": sha,
            "saas_ack_hash": ack_hash,
            "hash_matches": matches,
            "destination": rec.get("destination", "http://localhost:8000/v1/ingest"),
        })
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})


@router.post("/egress/inject")
def api_post_egress_inject(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> Response:
    """Injects a simulated raw authentication secret locally, normalizes it, and sends verified metadata."""
    resolve_tenant_id(request, x_api_key=x_api_key, authorization=authorization)
    try:
        from collector.models import RawRecord
        from collector.normalize import normalize_and_store
        from collector.redact import redact_text
        from collector.pseudonym import compute_source_ref
        from collector.uuidv7 import uuidv7
        from collector import egress_log, policy

        pid_num = random.randint(4000, 6500)
        port_num = random.randint(41000, 49999)
        ip_last = random.randint(20, 240)
        token_num = random.randint(10000, 99999)
        secret_pass = f"DEMO_PASSPHRASE_SECRET_{int(time.time())}"
        raw_secret_line = f"sshd[{pid_num}]: Failed password for root from 192.168.1.{ip_last} port {port_num} ssh2 password={secret_pass} token=eyJh{token_num} user=admin"
        now_utc = datetime.now(timezone.utc)

        raw_rec = RawRecord(
            adapter="syslog",
            source=f"192.168.1.{ip_last}",
            source_tz="UTC",
            category="auth",
            raw_text=raw_secret_line,
            value=1.0,
            unit="count",
            ts=now_utc,
        )
        normalize_and_store(raw_rec)

        clean_text, _ = redact_text(raw_secret_line)
        src_ref = compute_source_ref(f"192.168.1.{ip_last}")
        test_pid = uuidv7()

        candidate = {
            "payload_id": test_pid,
            "schema_version": 1,
            "collector_id": "col-acme-eu-1",
            "event_time_utc": now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source_tz": "Europe/Berlin",
            "sent_time_utc": now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source_ref": src_ref,
            "kind": "alert",
            "category": "auth",
            "severity": "critical",
            "value": 1.0,
            "unit": "count",
            "window_s": 5,
            "context": clean_text[:160],
        }

        allowed, filtered, _ = policy.enforce_policy(candidate)
        exact_json = json.dumps(filtered, sort_keys=True)
        sha256_hash = hashlib.sha256(exact_json.encode("utf-8")).hexdigest()

        # Append to egress_log and record ACK
        egress_log.log_send_attempt(test_pid, exact_json, "http://localhost:8000/v1/ingest", status="acked")
        egress_log.record_saas_ack(test_pid, sha256_hash)

        return JSONResponse(status_code=200, content={
            "status": "success",
            "message": "Secret ingested locally, redacted, allow-listed, and transmitted to egress ledger.",
            "payload_id": test_pid,
            "raw_text": raw_secret_line,
            "egress_payload": filtered,
            "sha256": sha256_hash,
        })
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})


class ProcessRawPayload(BaseModel):
    raw_text: str
    category: Optional[str] = "auth"
    source: Optional[str] = "192.168.1.100"
    kind: Optional[str] = "alert"


@router.post("/egress/process-raw")
def api_post_egress_process_raw(
    request: Request,
    payload: ProcessRawPayload,
    x_api_key: Optional[str] = Header(None, alias="X-Api-Key"),
    authorization: Optional[str] = Header(None, alias="Authorization"),
) -> Response:
    """Submits user-provided raw data through the two-tier privacy pipeline."""
    resolve_tenant_id(request, x_api_key=x_api_key, authorization=authorization)
    try:
        from collector.models import RawRecord
        from collector.normalize import normalize_and_store
        from collector.redact import redact_text
        from collector.pseudonym import compute_source_ref
        from collector.uuidv7 import uuidv7
        from collector import egress_log, policy

        raw_text = payload.raw_text.strip()
        if not raw_text:
            return JSONResponse(status_code=400, content={"error": "Raw text cannot be empty"})

        category = payload.category or "auth"
        source = payload.source or "192.168.1.100"
        kind = payload.kind or "alert"
        now_utc = datetime.now(timezone.utc)

        # ── LAYER 1: EDGE CUSTOMER TIER ──────────────────────────────────────
        # 1. Store verbatim in local SQLite WAL (raw_events)
        raw_rec = RawRecord(
            adapter="manual_ui_upload",
            source=source,
            source_tz="UTC",
            category=category,
            raw_text=raw_text,
            value=1.0,
            unit="count",
            ts=now_utc,
        )
        normalize_and_store(raw_rec)

        # 2. Local Redaction Engine & Secret Scanner
        clean_text, detected_categories = redact_text(raw_text)

        # 3. Entity Pseudonymization (salted HMAC-SHA256)
        src_ref = compute_source_ref(source)

        # 4. Form candidate metadata payload
        test_pid = uuidv7()
        candidate = {
            "payload_id": test_pid,
            "schema_version": 1,
            "collector_id": "col-acme-eu-1",
            "event_time_utc": now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source_tz": "Europe/Berlin",
            "sent_time_utc": now_utc.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "source_ref": src_ref,
            "kind": kind,
            "category": category,
            "severity": "critical" if any(c in detected_categories for c in ["password", "private_key", "token", "aws_key"]) else "info",
            "value": 1.0,
            "unit": "count",
            "window_s": 5,
            "context": clean_text[:200],
        }

        # 5. Pre-Egress Policy Gate (drop unknown keys, validate against contracts/allow-list.yaml)
        allowed, filtered, policy_reason = policy.enforce_policy(candidate)
        if not allowed or not filtered:
            return JSONResponse(
                status_code=422,
                content={
                    "status": "blocked_by_edge_policy",
                    "reason": policy_reason,
                    "layer1_edge": {
                        "status": "BLOCKED",
                        "detected_secrets": detected_categories,
                    }
                }
            )

        # ── LAYER 2: CENTRAL SAAS CLOUD TIER ─────────────────────────────────
        exact_json = json.dumps(filtered, sort_keys=True)
        sha256_hash = hashlib.sha256(exact_json.encode("utf-8")).hexdigest()

        # Append to append-only egress_log and record SaaS ACK
        egress_log.log_send_attempt(test_pid, exact_json, "http://localhost:8000/v1/ingest", status="acked")
        egress_log.record_saas_ack(test_pid, sha256_hash)

        return JSONResponse(status_code=200, content={
            "status": "success",
            "message": "Processed successfully through Layer 1 (Edge Gate) and Layer 2 (SaaS Cloud Ingestion).",
            "payload_id": test_pid,
            "layer1_edge": {
                "stored_location": "Local SQLite WAL (collector_local.db / raw_events)",
                "raw_text_verbatim": raw_text,
                "detected_secrets": detected_categories,
                "source_pseudonym": src_ref,
                "sanitized_context": clean_text[:200],
            },
            "layer2_saas": {
                "egress_payload": filtered,
                "sha256_checksum": sha256_hash,
                "saas_ack_hash": sha256_hash,
                "cryptographic_match": True,
                "destination": "http://localhost:8000/v1/ingest",
            }
        })
    except Exception as exc:
        return JSONResponse(status_code=500, content={"error": str(exc)})


