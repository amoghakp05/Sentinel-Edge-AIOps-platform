"""
tests/test_token_log_leak.py
────────────────────────────
Regression test: Verify that tokens passed via ?token= never reach any log,
stdout, stderr, or uvicorn access logs.

Tests:
1. Calls /api/health?token=SECRETTOKEN123 with caplog and capsys active.
2. Asserts 'SECRETTOKEN123' appears nowhere in caplog text, captured stdout, or captured stderr.
3. Verifies StripQueryStringFilter removes query strings from uvicorn.access records.
4. Verifies no application loggers print request.url or query parameters.
"""

from __future__ import annotations

import io
import logging
import sys
from pathlib import Path

import pytest
from starlette.requests import Request

from saas.api import get_health, resolve_tenant_id
from saas.main import StripQueryStringFilter, configure_access_log_filter


def test_token_in_query_param_never_appears_in_logs_or_stdout(
    caplog: pytest.LogCaptureFixture,
    capsys: pytest.CaptureFixture,
):
    """
    Core Requirement:
    Call /api/health?token=SECRETTOKEN123, capture all logs (caplog and stdout),
    and assert 'SECRETTOKEN123' appears nowhere.
    """
    secret_token = "SECRETTOKEN123"
    caplog.set_level(logging.DEBUG)

    req = Request({
        "type": "http",
        "method": "GET",
        "url": f"http://localhost:8000/api/health?token={secret_token}",
        "headers": [],
        "query_string": f"token={secret_token}".encode(),
    })

    # Execute endpoint call (will reject invalid token with 401)
    with pytest.raises(Exception):
        get_health(request=req, token=secret_token)

    # Capture stdout and stderr
    captured = capsys.readouterr()

    # Assert SECRETTOKEN123 appears nowhere in logs or captured output
    assert secret_token not in caplog.text, "Secret token leaked into application logs!"
    assert secret_token not in captured.out, "Secret token leaked into stdout!"
    assert secret_token not in captured.err, "Secret token leaked into stderr!"


def test_uvicorn_access_log_filter_strips_query_token(caplog: pytest.LogCaptureFixture):
    """
    Verifies that StripQueryStringFilter strips ?token=... from uvicorn.access logs.
    """
    secret_token = "SECRETTOKEN123"
    access_logger = logging.getLogger("uvicorn.access")
    filt = StripQueryStringFilter()

    # Simulate an access log record created by uvicorn
    # format: '%s - "%s %s HTTP/%s" %d'
    # args: (client_addr, method, full_path, http_version, status_code)
    record = logging.LogRecord(
        name="uvicorn.access",
        level=logging.INFO,
        pathname="uvicorn/protocols/http",
        lineno=100,
        msg='%s - "%s %s HTTP/%s" %d',
        args=("127.0.0.1:50000", "GET", f"/api/health?token={secret_token}", "1.1", 401),
        exc_info=None,
    )

    filt.filter(record)

    formatted = record.getMessage()
    assert secret_token not in formatted, "Secret token leaked into formatted access log!"
    assert f"?token={secret_token}" not in record.args[2]
    assert record.args[2] == "/api/health"


def test_no_application_logger_logs_request_url():
    """
    Static scan across saas and collector codebases confirming no logger calls
    reference request.url or query params.
    """
    src_dir = Path(__file__).resolve().parent.parent
    saas_files = list((src_dir / "saas").glob("*.py"))
    collector_files = list((src_dir / "collector").glob("*.py"))

    for py_file in saas_files + collector_files:
        content = py_file.read_text(encoding="utf-8")
        for line_no, line in enumerate(content.splitlines(), start=1):
            if "logger." in line or "logging." in line:
                assert "request.url" not in line, f"{py_file.name}:{line_no} logs request.url"
                assert "query_params" not in line, f"{py_file.name}:{line_no} logs query_params"
