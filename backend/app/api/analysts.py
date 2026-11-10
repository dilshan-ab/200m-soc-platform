"""Analyst performance: per-analyst MTTA/MTTR, SLA adherence and case volume."""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import Principal, require
from ..models import utcnow
from ..services.metrics import analyst_metrics

router = APIRouter(prefix="/api/analysts", tags=["analysts"])


@router.get("/performance")
def performance(
    p: Principal = Depends(require("metrics.read")),
    db: Session = Depends(get_db),
    days: int = Query(default=30, ge=1, le=365),
    client_id: str | None = None,
) -> dict[str, Any]:
    since = utcnow() - timedelta(days=days)
    data = analyst_metrics(db, p, since, client_id)
    data["days"] = days
    return data
