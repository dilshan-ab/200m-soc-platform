from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from fastapi import APIRouter, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from sqlalchemy.exc import IntegrityError

from ..config import get_settings
from ..connectors.base import get_connector_cls
from ..db import session_scope
from ..models import Tool, WebhookReplay
from ..ratelimit import limiter
from ..security import constant_eq, hmac_sha256, is_private_ip, sha256_hex
from ..services import polling, tools_svc

router = APIRouter(prefix="/api/webhooks", tags=["webhooks"])


def _uniform() -> HTTPException:
    return HTTPException(404, "not found")


async def _read_body(request: Request, limit: int) -> bytes:
    cl = request.headers.get("content-length")
    if cl and cl.isdigit() and int(cl) > limit:
        raise HTTPException(413, "payload too large")
    buf = bytearray()
    async for chunk in request.stream():
        buf += chunk
        if len(buf) > limit:
            raise HTTPException(413, "payload too large")
    return bytes(buf)


@router.post("/{tool_id}", status_code=202)
async def receive(tool_id: str, request: Request) -> dict[str, Any]:
    s = get_settings()
    ip = request.client.host if request.client else ""
    if not limiter.allow(f"wh:{tool_id}", s.webhook_rate_per_minute) or not limiter.allow(f"wh-ip:{ip}", s.webhook_rate_per_minute):
        raise HTTPException(429, "rate limited")
    if not is_private_ip(ip):
        raise _uniform()
    body = await _read_body(request, s.webhook_max_body_bytes)
    headers = {k.lower(): v for k, v in request.headers.items()}
    return await run_in_threadpool(_process, tool_id, body, headers)


def _process(tool_id: str, body: bytes, headers: dict[str, str]) -> dict[str, Any]:
    s = get_settings()
    with session_scope() as db:
        tool = db.get(Tool, tool_id)
        if tool is None or not tool.enabled and tool.status not in ("draft", "tested"):
            raise _uniform()
        cls = get_connector_cls(tool.type)
        if not cls.manifest.webhook:
            raise _uniform()
        secret = tools_svc.load_secrets(db, tool).get("_webhook")
        if not secret:
            raise _uniform()
        if tool.webhook_auth_mode == "bearer":
            auth = headers.get("authorization", "")
            if not auth.lower().startswith("bearer ") or not constant_eq(auth[7:].strip(), secret):
                raise HTTPException(401, "invalid credentials")
        else:
            ts, sig = headers.get("x-soc-timestamp", ""), headers.get("x-soc-signature", "")
            try:
                skew = abs(datetime.now(UTC).timestamp() - float(ts))
            except ValueError as e:
                raise HTTPException(401, "invalid credentials") from e
            if skew > s.webhook_max_skew_seconds:
                raise HTTPException(401, "stale timestamp")
            expected = hmac_sha256(secret, f"{ts}.".encode() + body)
            if not constant_eq(sig.removeprefix("sha256="), expected):
                raise HTTPException(401, "invalid credentials")
            try:
                with db.begin_nested():
                    db.add(WebhookReplay(tool_id=tool.id, digest=sha256_hex(f"{ts}.".encode() + body)))
                    db.flush()
            except IntegrityError as e:
                raise HTTPException(409, "replayed request") from e
        try:
            payload = json.loads(body or b"{}")
        except ValueError as e:
            raise HTTPException(400, "invalid JSON") from e
        if not isinstance(payload, dict):
            raise HTTPException(400, "JSON object expected")
        tool.last_test = {**(tool.last_test or {}), "webhook_at": datetime.now(UTC).isoformat()}
        if not tool.enabled:
            return {"accepted": 0, "note": "test event recorded"}
        alerts = cls({}, {}).parse_webhook(payload)
        created = polling.ingest_batch(db, tool, alerts)
        st = tools_svc.ensure_state(db, tool)
        st.last_success_at = datetime.now(UTC)
        st.items_total += created
        return {"accepted": len(alerts), "created": created}
