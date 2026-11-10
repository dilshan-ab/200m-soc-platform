from __future__ import annotations

import json
from typing import Any

import httpx

from app import db as dbmod
from app.connectors import base as cbase
from app.connectors.base import NormAlert
from app.models import Tool
from app.services import ingest, tools_svc
from app.vault import get_secret_store


def mk_alert(client_id: str | None = None, title: str = "Test alert", severity: str = "high", host: str = "ws-001", src_ip: str = "203.0.113.7", rule_id: str = "100", source_id: str | None = None, **kw: Any) -> str:
    with dbmod.session_scope() as db:
        n = NormAlert(source_id=source_id or "", title=title, severity=severity, host=host, src_ip=src_ip, rule_id=rule_id, **kw)
        a, _ = ingest.ingest_alert(db, None, n, source="manual")
        a.client_id = client_id
        db.flush()
        return a.id


def mk_tool(type_: str, name: str, cfg: dict[str, Any] | None = None, secrets: dict[str, str] | None = None, enabled: bool = True, **kw: Any) -> str:
    with dbmod.session_scope() as db:
        t = Tool(type=type_, name=name, config=cfg or {}, enabled=enabled, status="enabled" if enabled else "draft", **kw)
        db.add(t)
        db.flush()
        tools_svc.store_secrets(db, t, secrets or {})
        tools_svc.ensure_state(db, t)
        if kw.get("webhook_secret_ref") is None and type_ in ("wazuh_manager", "uptime_kuma", "thehive", "shuffle", "clickup"):
            tools_svc.new_webhook_secret(db, t)
        return t.id


def webhook_secret(tool_id: str) -> str:
    with dbmod.session_scope() as db:
        t = db.get(Tool, tool_id)
        return get_secret_store().get(db, t.webhook_secret_ref)  # type: ignore[return-value]


def mock_http(handler) -> None:
    """Route every connector HTTP call through `handler(request) -> httpx.Response`."""
    cbase.set_http_factory(lambda verify: httpx.Client(transport=httpx.MockTransport(handler)))


def jresp(data: Any, status: int = 200) -> httpx.Response:
    return httpx.Response(status, content=json.dumps(data), headers={"content-type": "application/json"})
