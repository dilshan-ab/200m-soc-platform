"""Log search API: search raw logs from Wazuh indexer or local alert database."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from ..connectors.base import ConnectorError
from ..db import get_db
from ..deps import Principal, require
from ..services import log_search as svc

router = APIRouter(prefix="/api/logs", tags=["logs"])


@router.get("/search")
def search_logs(
    p: Principal = Depends(require("logs.read")),
    db: Session = Depends(get_db),
    q: str = Query(default="", max_length=500),
    source: str = Query(default="auto", pattern="^(auto|wazuh|local)$"),
    index: str = Query(default="", max_length=200),
    start: str | None = Query(default=None, max_length=30),
    end: str | None = Query(default=None, max_length=30),
    severity: str | None = None,
    host: str | None = Query(default=None, max_length=255),
    rule_id: str | None = Query(default=None, max_length=80),
    agent_id: str | None = Query(default=None, max_length=20),
    src_ip: str | None = Query(default=None, max_length=64),
    size: int = Query(default=50, ge=1, le=500),
    page: int = Query(default=1, ge=1),
    sort: str = Query(default="desc", pattern="^(asc|desc)$"),
) -> dict[str, Any]:
    from_ = (page - 1) * size

    if source == "wazuh" or source == "auto":
        try:
            return svc.search_wazuh(db, q=q, index=index, start=start, end=end, severity=severity,
                                     host=host, rule_id=rule_id, agent_id=agent_id, src_ip=src_ip,
                                     size=size, from_=from_, sort_order=sort)
        except ConnectorError:
            if source == "wazuh":
                raise HTTPException(503, "Wazuh indexer not available")

    return svc.search_local(db, p.scope(None), q=q, start=start, end=end, severity=severity,
                             host=host, rule_id=rule_id, src_ip=src_ip, size=size, from_=from_, sort_order=sort)


@router.get("/indices")
def list_indices(p: Principal = Depends(require("logs.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return svc.get_indices(db)


@router.get("/fields/{field}")
def field_values(field: str, p: Principal = Depends(require("logs.read")), db: Session = Depends(get_db)) -> list[str]:
    values = svc.get_field_values(db, field)
    if not values:
        raise HTTPException(404, "unknown field")
    return values
