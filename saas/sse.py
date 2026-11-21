"""
saas/sse.py
───────────
Server-Sent Events (SSE) Event Broker for Real-time Dashboard Updates.

Pushes state changes and health transitions live over SSE connections.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, AsyncGenerator, Dict, Set

logger = logging.getLogger(__name__)

# Active subscriber queues: tenant_id -> set of asyncio.Queue
_SUBSCRIBERS: Dict[str, Set[asyncio.Queue]] = {}


def subscribe(tenant_id: str) -> asyncio.Queue:
    """Registers a new listener queue for a specific tenant strictly."""
    q: asyncio.Queue = asyncio.Queue(maxsize=100)
    if tenant_id not in _SUBSCRIBERS:
        _SUBSCRIBERS[tenant_id] = set()
    _SUBSCRIBERS[tenant_id].add(q)
    return q


def unsubscribe(tenant_id: str, q: asyncio.Queue) -> None:
    """Removes a listener queue upon client disconnect."""
    if tenant_id in _SUBSCRIBERS and q in _SUBSCRIBERS[tenant_id]:
        _SUBSCRIBERS[tenant_id].discard(q)
        if not _SUBSCRIBERS[tenant_id]:
            _SUBSCRIBERS.pop(tenant_id, None)


def broadcast_event(tenant_id: str, event_type: str, data: Dict[str, Any]) -> None:
    """
    Broadcasts any structured event to tenant subscribers ONLY.
    Hard Rule: Tenant B never receives Tenant A events.
    Thread-safe non-blocking enqueue.
    """
    message = {
        "type": event_type,
        "tenant_id": tenant_id,
        "data": data,
    }
    encoded = f"event: {event_type}\ndata: {json.dumps(message)}\n\n"

    # Only send to subscribers of this exact tenant_id
    target_queues = list(_SUBSCRIBERS.get(tenant_id, set()))

    for q in target_queues:
        try:
            q.put_nowait(encoded)
        except asyncio.QueueFull:
            try:
                q.get_nowait()
                q.put_nowait(encoded)
            except Exception:
                pass
        except Exception as exc:
            logger.debug("Failed to enqueue SSE event: %s", type(exc).__name__)


def broadcast_health_change(tenant_id: str, event_data: Dict[str, Any]) -> None:
    """
    Broadcasts a health transition event to all subscribers listening for this tenant.
    Thread-safe non-blocking enqueue.
    """
    broadcast_event(tenant_id, "health_change", event_data)


async def sse_event_generator(tenant_id: str) -> AsyncGenerator[str, None]:
    """Async generator yielding formatted SSE message frames."""
    q = subscribe(tenant_id)
    try:
        # Initial greeting event
        init_frame = f"event: connected\ndata: {json.dumps({'status': 'connected', 'tenant_id': tenant_id})}\n\n"
        yield init_frame

        while True:
            msg = await q.get()
            yield msg
    finally:
        unsubscribe(tenant_id, q)
