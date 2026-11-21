"""
saas/main.py
────────────
Main FastAPI application entrypoint for the Central SaaS service.

Endpoints:
  GET  /health            - Health check & region identity
  POST /v1/ingest         - Metadata-only telemetry ingestion endpoint
  GET  /api/health        - Current health state per entity
  GET  /api/health/history- Health transition history audit trail
  GET  /api/thresholds    - Retrieve per-tenant configured thresholds
  PUT  /api/thresholds    - Update per-tenant thresholds
  GET  /api/health/stream - Live Server-Sent Events (SSE) transition stream
"""

from __future__ import annotations

import logging
import re
from contextlib import asynccontextmanager
from pathlib import Path
from typing import AsyncGenerator

from fastapi import FastAPI, Header, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from saas.api import router as api_router
from saas.db import get_region, init_db
from saas.health import health_engine
from saas.ingest import handle_ingest

logger = logging.getLogger(__name__)


class StripQueryStringFilter(logging.Filter):
    """
    Security filter: strips query strings (including ?token=) from uvicorn access logs.
    Guarantees sensitive query tokens never appear in access logs, stdout, or log files.
    """
    def filter(self, record: logging.LogRecord) -> bool:
        # uvicorn.access format: record.args is (client_addr, method, full_path, http_version, status_code)
        if isinstance(record.args, tuple) and len(record.args) >= 3:
            path = record.args[2]
            if isinstance(path, str) and "?" in path:
                clean_path = path.split("?")[0]
                args_list = list(record.args)
                args_list[2] = clean_path
                record.args = tuple(args_list)
        if isinstance(record.msg, str) and "?" in record.msg:
            record.msg = re.sub(r"\?[^\s\"']*", "", record.msg)
        return True


def configure_access_log_filter() -> None:
    """Installs StripQueryStringFilter on uvicorn.access and related loggers."""
    filt = StripQueryStringFilter()
    for name in ("uvicorn.access", "uvicorn", "uvicorn.error"):
        logger_obj = logging.getLogger(name)
        logger_obj.addFilter(filt)
        for h in logger_obj.handlers:
            h.addFilter(filt)


# Install at import time
configure_access_log_filter()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Ensures regional database tables are created on startup and starts health engine."""
    configure_access_log_filter()
    try:
        init_db()
        logger.info("Initialized SaaS database for region '%s'", get_region())
    except Exception as exc:
        logger.error("Failed to initialize SaaS database on startup: %s", type(exc).__name__)

    # Start background 3-second health evaluation engine (disabled during tests)
    import os
    if not os.environ.get("TESTING"):
        health_engine.start()

    try:
        yield
    finally:
        if not os.environ.get("TESTING"):
            health_engine.stop()


app = FastAPI(
    title="Sentinel Edge SaaS",
    description="Multi-tenant metadata-only AIOps ingest and intelligence tier",
    version="1.0.0",
    lifespan=lifespan,
)

# Explicit CORS origins — wildcard "*" strictly disallowed for security isolation
ALLOWED_ORIGINS = [
    "http://localhost:8000",
    "http://127.0.0.1:8000",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
]

# Enable CORS for browser dashboard access with explicit allowed origins
app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Content-Type", "Authorization", "X-Api-Key", "X-Signature", "X-Tenant-Id", "X-Actor", "X-User-Role"],
)

from starlette.exceptions import HTTPException as StarletteHTTPException
from fastapi.exceptions import RequestValidationError


@app.exception_handler(StarletteHTTPException)
def http_exception_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
    detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": detail, "detail": detail},
    )


@app.exception_handler(RequestValidationError)
def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={"error": f"Validation error: {exc}", "detail": str(exc)},
    )


@app.exception_handler(Exception)
def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    logger.exception("Unhandled server error: %s", exc)
    return JSONResponse(
        status_code=500,
        content={"error": f"Internal Server Error: {exc}", "detail": str(exc)},
    )

# Register API routes
app.include_router(api_router)

# Mount Dashboard static directory
dashboard_dir = Path(__file__).resolve().parent.parent / "dashboard"
if dashboard_dir.exists():
    app.mount("/dashboard", StaticFiles(directory=str(dashboard_dir), html=True), name="dashboard")


@app.get("/")
def root_redirect() -> RedirectResponse:
    return RedirectResponse(url="/dashboard/")


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": "saas", "region": get_region()}


@app.post("/v1/ingest")
async def ingest_endpoint(
    request: Request,
    x_api_key: str | None = Header(None, alias="X-Api-Key"),
    x_signature: str | None = Header(None, alias="X-Signature"),
) -> Response:
    """
    Ingests allow-listed metadata payloads from authenticated collectors.
    Derives tenant_id and collector_id strictly from credentials.
    Re-validates allow-list server-side and applies ON CONFLICT DO NOTHING.
    """
    body = await request.body()
    status_code, response_data = handle_ingest(
        api_key=x_api_key,
        signature=x_signature,
        body_bytes=body,
    )

    return JSONResponse(status_code=status_code, content=response_data)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("saas.main:app", host="0.0.0.0", port=8000, access_log=False)

