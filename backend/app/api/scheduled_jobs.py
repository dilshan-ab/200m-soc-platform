"""Scheduled jobs dashboard API: unified view of all platform jobs and schedules."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import Principal, require
from ..services import scheduled_jobs as svc

router = APIRouter(prefix="/api/jobs", tags=["scheduled-jobs"])


@router.get("/overview")
def overview(p: Principal = Depends(require("automation.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    return svc.get_overview(db)


@router.get("/")
def list_jobs(
    p: Principal = Depends(require("automation.read")),
    db: Session = Depends(get_db),
    category: str | None = Query(default=None, pattern="^(enrichment|report|automation|playbook|backup)$"),
    status: str | None = Query(default=None, max_length=30),
    size: int = Query(default=50, ge=1, le=200),
    page: int = Query(default=1, ge=1),
) -> dict[str, Any]:
    return svc.list_jobs(db, category=category, status=status, size=size, page=page)


@router.get("/schedules")
def list_schedules(p: Principal = Depends(require("automation.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return svc.list_schedules(db)
