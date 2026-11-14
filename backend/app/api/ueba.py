from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import Principal, require
from ..services import ueba as svc

router = APIRouter(prefix="/api/ueba", tags=["ueba"])


@router.get("/summary")
def summary(p: Principal = Depends(require("ueba.read")), db: Session = Depends(get_db), client_id: str | None = None) -> dict[str, Any]:
    if client_id and not p.can_see_client(client_id):
        client_id = None
    return svc.get_entity_summary(db, client_id=client_id)


@router.get("/profiles")
def profiles(p: Principal = Depends(require("ueba.read")), db: Session = Depends(get_db),
             entity_type: str | None = None, client_id: str | None = None,
             min_risk: float = Query(default=0, ge=0, le=100), limit: int = Query(default=100, ge=1, le=500)) -> list[dict[str, Any]]:
    if client_id and not p.can_see_client(client_id):
        client_id = None
    return svc.list_profiles(db, entity_type=entity_type, client_id=client_id, min_risk=min_risk, limit=limit)


@router.get("/entity/{entity_type}/{entity_value}")
def entity_detail(entity_type: str, entity_value: str, p: Principal = Depends(require("ueba.read")), db: Session = Depends(get_db),
                  days: int = Query(default=30, ge=1, le=365)) -> dict[str, Any]:
    profiles = svc.list_profiles(db, entity_type=entity_type, limit=1)
    profile = next((pr for pr in profiles if pr["entity_value"] == entity_value), None)
    timeline = svc.get_entity_timeline(db, entity_type, entity_value, days=days)
    return {"profile": profile, "timeline": timeline}


@router.post("/compute", status_code=202)
def compute(p: Principal = Depends(require("ueba.write")), db: Session = Depends(get_db),
            days: int = Query(default=30, ge=1, le=365), client_id: str | None = None) -> dict[str, Any]:
    if client_id and not p.can_see_client(client_id):
        client_id = None
    result = svc.compute_entity_profiles(db, days=days, client_id=client_id)
    return result
