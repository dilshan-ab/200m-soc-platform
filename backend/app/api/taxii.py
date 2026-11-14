"""A minimal read-only TAXII 2.1 server exposing our own threat indicators as one
collection, so partners can pull from us with any standard TAXII client. Authenticated
the same way as the rest of the API (session cookie or bearer API token)."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import Principal, require
from ..models import ThreatIndicator
from .common import iso
from .threat_intel import _indicator_to_pattern

router = APIRouter(prefix="/taxii2", tags=["taxii"])
COLLECTION_ID = "f4c9a000-0000-4000-8000-000000000001"
COLLECTION_TITLE = "200M SOC shared indicators"


def _api_root(request: Request) -> str:
    return str(request.base_url).rstrip("/") + "/taxii2/api1"


@router.get("")
@router.get("/")
def discovery(request: Request, p: Principal = Depends(require("threat_intel.read"))) -> dict[str, Any]:
    root = _api_root(request)
    return {"title": "200M SOC TAXII feed", "description": "Outbound threat indicator sharing.", "default": root, "api_roots": [root]}


@router.get("/api1")
@router.get("/api1/")
def api_root_info(request: Request, p: Principal = Depends(require("threat_intel.read"))) -> dict[str, Any]:
    return {"title": "200M SOC API root", "versions": ["application/taxii+json;version=2.1"], "max_content_length": 10_000_000}


@router.get("/api1/collections")
@router.get("/api1/collections/")
def list_collections(p: Principal = Depends(require("threat_intel.read"))) -> dict[str, Any]:
    return {"collections": [{"id": COLLECTION_ID, "title": COLLECTION_TITLE, "description": "All active, non-revoked indicators visible to this account.", "can_read": True, "can_write": False, "media_types": ["application/stix+json;version=2.1"]}]}


@router.get("/api1/collections/{cid}")
@router.get("/api1/collections/{cid}/")
def get_collection(cid: str, p: Principal = Depends(require("threat_intel.read"))) -> dict[str, Any]:
    return {"id": COLLECTION_ID, "title": COLLECTION_TITLE, "can_read": True, "can_write": False, "media_types": ["application/stix+json;version=2.1"]}


@router.get("/api1/collections/{cid}/objects")
@router.get("/api1/collections/{cid}/objects/")
def get_objects(
    cid: str, p: Principal = Depends(require("threat_intel.read")), db: Session = Depends(get_db),
    added_after: str | None = Query(default=None), limit: int = Query(default=500, ge=1, le=5000),
) -> dict[str, Any]:
    qy = select(ThreatIndicator).where(p.scope(ThreatIndicator.client_id) | ThreatIndicator.client_id.is_(None), ThreatIndicator.revoked.is_(False))
    if added_after:
        qy = qy.where(ThreatIndicator.last_seen > added_after)
    rows = db.execute(qy.order_by(ThreatIndicator.last_seen.desc()).limit(limit)).scalars().all()
    objects = [{
        "type": "indicator", "spec_version": "2.1", "id": r.stix_id or f"indicator--{r.id}",
        "created": iso(r.first_seen), "modified": iso(r.last_seen), "pattern": r.pattern or _indicator_to_pattern(r.type, r.value),
        "pattern_type": "stix", "valid_from": iso(r.first_seen), "indicator_types": r.labels or ["malicious-activity"], "confidence": r.confidence,
    } for r in rows]
    return {"objects": objects, "more": False}
