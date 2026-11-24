"""Threat intel sharing: a durable indicator store exchanged as STIX 2.1 bundles, with
optional pull from external TAXII 2.1 feeds, and (in taxii.py) a small read-only TAXII
2.1 server so partners can pull our own indicators."""
from __future__ import annotations

import json
import re
import uuid
from datetime import timedelta
from typing import Any, Literal

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import Principal, require, require_admin_step_up, scoped_get
from ..models import ThreatFeed, ThreatIndicator, utcnow
from ..security import SecurityError, validate_external_egress_url
from ..vault import get_secret_store
from .common import iso, page_out, paginate

router = APIRouter(prefix="/api/threat-intel", tags=["threat-intel"])
TYPES = ("ip", "domain", "url", "hash", "email")
_PATTERN_RE = re.compile(r"([a-zA-Z0-9_\-:.']+)\s*=\s*'([^']+)'")
_HASH_ALGO_BY_LEN = {32: "MD5", 40: "SHA-1", 64: "SHA-256"}


def _pattern_to_indicator(pattern: str) -> tuple[str, str] | None:
    """Best-effort extraction of (type, value) from a single-comparison STIX pattern."""
    m = _PATTERN_RE.search(pattern or "")
    if not m:
        return None
    path, value = m.group(1), m.group(2)
    if path.startswith(("ipv4-addr", "ipv6-addr")):
        return "ip", value
    if path.startswith("domain-name"):
        return "domain", value
    if path.startswith("url"):
        return "url", value
    if path.startswith("file:hashes"):
        return "hash", value
    if path.startswith(("email-addr", "email-message")):
        return "email", value
    return None


def _indicator_to_pattern(type_: str, value: str) -> str:
    if type_ == "hash":
        algo = _HASH_ALGO_BY_LEN.get(len(value), "SHA-256")
        return f"[file:hashes.'{algo}' = '{value}']"
    path = {"ip": "ipv4-addr:value", "domain": "domain-name:value", "url": "url:value", "email": "email-addr:value"}.get(type_, "ipv4-addr:value")
    return f"[{path} = '{value}']"


def _ind_out(i: ThreatIndicator) -> dict[str, Any]:
    return {
        "id": i.id, "stix_id": i.stix_id, "type": i.type, "value": i.value, "pattern": i.pattern or _indicator_to_pattern(i.type, i.value),
        "labels": i.labels, "confidence": i.confidence, "tlp": i.tlp, "verdict": i.verdict, "source": i.source, "sightings": i.sightings,
        "revoked": i.revoked, "valid_until": iso(i.valid_until), "first_seen": iso(i.first_seen), "last_seen": iso(i.last_seen), "client_id": i.client_id,
    }


def _upsert_indicator(db: Session, *, type_: str, value: str, pattern: str = "", labels: list[str] | None = None, confidence: int = 50,
                       tlp: str = "AMBER", source: str = "manual", stix_id: str = "", valid_until=None, client_id: str | None = None,
                       created_by: str | None = None) -> tuple[ThreatIndicator, bool]:
    existing = db.execute(select(ThreatIndicator).where(ThreatIndicator.type == type_, ThreatIndicator.value == value)).scalars().first()
    now = utcnow()
    if existing:
        existing.sightings += 1
        existing.last_seen = now
        existing.revoked = False
        if pattern:
            existing.pattern = pattern
        if labels:
            existing.labels = labels
        if stix_id:
            existing.stix_id = stix_id
        return existing, False
    ind = ThreatIndicator(type=type_, value=value, pattern=pattern or _indicator_to_pattern(type_, value), labels=labels or [], confidence=confidence,
                          tlp=tlp, source=source, stix_id=stix_id, valid_until=valid_until, client_id=client_id, created_by=created_by)
    db.add(ind)
    db.flush()
    return ind, True


@router.get("/indicators")
def list_indicators(
    p: Principal = Depends(require("threat_intel.read")), db: Session = Depends(get_db),
    type: str | None = None, tlp: str | None = None, verdict: str | None = None, revoked: bool | None = None,
    q: str | None = Query(default=None, max_length=200), page: int = 1, limit: int = 50,
) -> dict[str, Any]:
    qy = select(ThreatIndicator).where(p.scope(ThreatIndicator.client_id) | ThreatIndicator.client_id.is_(None)).order_by(ThreatIndicator.last_seen.desc())
    if type:
        qy = qy.where(ThreatIndicator.type == type)
    if tlp:
        qy = qy.where(ThreatIndicator.tlp == tlp.upper())
    if verdict:
        qy = qy.where(ThreatIndicator.verdict == verdict)
    if revoked is not None:
        qy = qy.where(ThreatIndicator.revoked.is_(revoked))
    if q:
        qy = qy.where(ThreatIndicator.value.icontains(q, autoescape=True))
    rows, total = paginate(db, qy, page, limit)
    return page_out([_ind_out(i) for i in rows], total, page, limit)


@router.get("/stats")
def indicator_stats(p: Principal = Depends(require("threat_intel.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    from sqlalchemy import func

    scope = (p.scope(ThreatIndicator.client_id) | ThreatIndicator.client_id.is_(None),)
    by_type = dict(db.execute(select(ThreatIndicator.type, func.count()).where(*scope).group_by(ThreatIndicator.type)).all())
    by_verdict = dict(db.execute(select(ThreatIndicator.verdict, func.count()).where(*scope).group_by(ThreatIndicator.verdict)).all())
    total = db.execute(select(func.count()).select_from(ThreatIndicator).where(*scope)).scalar_one()
    active = db.execute(select(func.count()).select_from(ThreatIndicator).where(*scope, ThreatIndicator.revoked.is_(False))).scalar_one()
    return {"total": total, "active": active, "revoked": total - active, "by_type": by_type, "by_verdict": by_verdict}


class IndicatorIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["ip", "domain", "url", "hash", "email"]
    value: str = Field(min_length=1, max_length=500)
    labels: list[str] = Field(default_factory=list, max_length=10)
    confidence: int = Field(default=50, ge=0, le=100)
    tlp: Literal["WHITE", "GREEN", "AMBER", "RED"] = "AMBER"
    client_id: str | None = None


@router.post("/indicators", status_code=201)
def create_indicator(body: IndicatorIn, p: Principal = Depends(require("threat_intel.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    if body.client_id and not p.can_see_client(body.client_id):
        raise HTTPException(404, "not found")
    ind, created = _upsert_indicator(db, type_=body.type, value=body.value.strip(), labels=body.labels, confidence=body.confidence,
                                      tlp=body.tlp, source="manual", client_id=body.client_id, created_by=p.user.id)
    audit.record(db, "threat_intel.indicator.create", actor=p.label, actor_id=p.user.id, resource_type="threat_indicator", resource_id=ind.id, ip=p.ip, meta={"value": ind.value, "new": created})
    return _ind_out(ind)


@router.post("/indicators/{iid}/revoke")
def revoke_indicator(iid: str, p: Principal = Depends(require("threat_intel.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    ind = scoped_get(db, ThreatIndicator, iid, p)
    ind.revoked = True
    audit.record(db, "threat_intel.indicator.revoke", actor=p.label, actor_id=p.user.id, resource_type="threat_indicator", resource_id=ind.id, ip=p.ip)
    return _ind_out(ind)


@router.delete("/indicators/{iid}", status_code=204)
def delete_indicator(iid: str, p: Principal = Depends(require("threat_intel.admin")), db: Session = Depends(get_db)) -> None:
    ind = scoped_get(db, ThreatIndicator, iid, p)
    audit.record(db, "threat_intel.indicator.delete", actor=p.label, actor_id=p.user.id, resource_type="threat_indicator", resource_id=ind.id, ip=p.ip, meta={"value": ind.value})
    db.delete(ind)


def _stix_object_to_indicator(obj: dict[str, Any], *, source: str, client_id: str | None, created_by: str | None, db: Session) -> bool:
    if obj.get("type") != "indicator":
        return False
    parsed = _pattern_to_indicator(obj.get("pattern", ""))
    if parsed is None:
        return False
    type_, value = parsed
    labels = obj.get("indicator_types") or obj.get("labels") or []
    valid_until = None
    if obj.get("valid_until"):
        from datetime import datetime

        try:
            valid_until = datetime.fromisoformat(str(obj["valid_until"]).replace("Z", "+00:00"))
        except ValueError:
            valid_until = None
    _upsert_indicator(db, type_=type_, value=value, pattern=obj.get("pattern", ""), labels=labels, confidence=int(obj.get("confidence", 50)),
                       tlp="AMBER", source=source, stix_id=str(obj.get("id", "")), valid_until=valid_until, client_id=client_id, created_by=created_by)
    return True


class ImportIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    bundle: Any
    client_id: str | None = None


@router.post("/import")
def import_bundle(body: ImportIn, p: Principal = Depends(require("threat_intel.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    if body.client_id and not p.can_see_client(body.client_id):
        raise HTTPException(404, "not found")
    bundle = body.bundle
    if isinstance(bundle, str):
        try:
            bundle = json.loads(bundle)
        except json.JSONDecodeError as e:
            raise HTTPException(400, f"invalid JSON: {e}") from e
    if not isinstance(bundle, dict) or not isinstance(bundle.get("objects"), list):
        raise HTTPException(400, "expected a STIX bundle with an 'objects' array")
    imported, skipped = 0, 0
    for obj in bundle["objects"][:5000]:
        if isinstance(obj, dict) and _stix_object_to_indicator(obj, source="import", client_id=body.client_id, created_by=p.user.id, db=db):
            imported += 1
        else:
            skipped += 1
    audit.record(db, "threat_intel.import", actor=p.label, actor_id=p.user.id, resource_type="threat_feed", ip=p.ip, meta={"imported": imported, "skipped": skipped})
    return {"imported": imported, "skipped": skipped, "total_objects": len(bundle["objects"])}


@router.get("/export")
def export_bundle(
    p: Principal = Depends(require("threat_intel.read")), db: Session = Depends(get_db),
    type: str | None = None, tlp: str | None = None, days: int | None = Query(default=None, ge=1, le=365),
) -> dict[str, Any]:
    qy = select(ThreatIndicator).where(p.scope(ThreatIndicator.client_id) | ThreatIndicator.client_id.is_(None), ThreatIndicator.revoked.is_(False))
    if type:
        qy = qy.where(ThreatIndicator.type == type)
    if tlp:
        qy = qy.where(ThreatIndicator.tlp == tlp.upper())
    if days:
        qy = qy.where(ThreatIndicator.last_seen >= utcnow() - timedelta(days=days))
    rows = db.execute(qy.limit(5000)).scalars().all()
    objects = [{
        "type": "indicator", "spec_version": "2.1", "id": r.stix_id or f"indicator--{uuid.uuid4()}",
        "created": iso(r.first_seen), "modified": iso(r.last_seen), "pattern": r.pattern or _indicator_to_pattern(r.type, r.value),
        "pattern_type": "stix", "valid_from": iso(r.first_seen), **({"valid_until": iso(r.valid_until)} if r.valid_until else {}),
        "indicator_types": r.labels or ["malicious-activity"], "confidence": r.confidence,
    } for r in rows]
    audit.record(db, "threat_intel.export", actor=p.label, actor_id=p.user.id, resource_type="threat_feed", ip=p.ip, meta={"count": len(objects)})
    return {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}


# ------------------------------------------------------------------------ feeds (TAXII pull)
def _feed_out(f: ThreatFeed) -> dict[str, Any]:
    return {
        "id": f.id, "name": f.name, "direction": f.direction, "taxii_discovery_url": f.taxii_discovery_url, "taxii_collection_id": f.taxii_collection_id,
        "taxii_username": f.taxii_username, "has_credentials": bool(f.auth_secret_ref), "enabled": f.enabled, "last_sync_at": iso(f.last_sync_at),
        "last_sync_status": f.last_sync_status, "last_sync_count": f.last_sync_count, "last_error": f.last_error, "created_at": iso(f.created_at),
    }


@router.get("/feeds")
def list_feeds(p: Principal = Depends(require("threat_intel.admin")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [_feed_out(f) for f in db.execute(select(ThreatFeed).order_by(ThreatFeed.name)).scalars()]


class FeedIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=2, max_length=160)
    taxii_discovery_url: str = Field(max_length=500)
    taxii_collection_id: str = Field(default="", max_length=120)
    taxii_username: str = Field(default="", max_length=160)
    taxii_password: str = Field(default="", max_length=400)


@router.post("/feeds", status_code=201)
def create_feed(body: FeedIn, p: Principal = Depends(require_admin_step_up("threat_intel.admin")), db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        validate_external_egress_url(body.taxii_discovery_url)
    except SecurityError as e:
        raise HTTPException(400, f"egress policy: {e}") from e
    f = ThreatFeed(name=body.name, taxii_discovery_url=body.taxii_discovery_url, taxii_collection_id=body.taxii_collection_id,
                    taxii_username=body.taxii_username, created_by=p.user.id)
    db.add(f)
    db.flush()
    if body.taxii_password:
        ref = f"threat_feed:{f.id}:password"
        get_secret_store().put(db, ref, body.taxii_password)
        f.auth_secret_ref = ref
    audit.record(db, "threat_intel.feed.create", actor=p.label, actor_id=p.user.id, resource_type="threat_feed", resource_id=f.id, ip=p.ip, meta={"name": f.name})
    return _feed_out(f)


@router.delete("/feeds/{fid}", status_code=204)
def delete_feed(fid: str, p: Principal = Depends(require_admin_step_up("threat_intel.admin")), db: Session = Depends(get_db)) -> None:
    f = db.get(ThreatFeed, fid)
    if f is None:
        raise HTTPException(404, "not found")
    if f.auth_secret_ref:
        get_secret_store().delete(db, f.auth_secret_ref)
    audit.record(db, "threat_intel.feed.delete", actor=p.label, actor_id=p.user.id, resource_type="threat_feed", resource_id=fid, ip=p.ip, meta={"name": f.name})
    db.delete(f)


@router.post("/feeds/{fid}/sync")
def sync_feed(fid: str, p: Principal = Depends(require("threat_intel.admin")), db: Session = Depends(get_db)) -> dict[str, Any]:
    f = db.get(ThreatFeed, fid)
    if f is None:
        raise HTTPException(404, "not found")
    try:
        validate_external_egress_url(f.taxii_discovery_url)
        auth = None
        if f.auth_secret_ref:
            pw = get_secret_store().get(db, f.auth_secret_ref)
            if pw:
                auth = (f.taxii_username, pw)
        base = f.taxii_discovery_url.rstrip("/")
        with httpx.Client(timeout=15.0, auth=auth) as client:
            disco = client.get(base)
            disco.raise_for_status()
            api_roots = disco.json().get("api_roots") or [base.rsplit("/taxii2", 1)[0] + "/taxii2/api1/"]
            api_root = api_roots[0].rstrip("/")
            objs_url = f"{api_root}/collections/{f.taxii_collection_id}/objects/"
            validate_external_egress_url(objs_url)
            resp = client.get(objs_url, headers={"Accept": "application/taxii+json;version=2.1"})
            resp.raise_for_status()
            envelope = resp.json()
        objects = envelope.get("objects", [])
        count = 0
        for obj in objects[:5000]:
            if isinstance(obj, dict) and _stix_object_to_indicator(obj, source=f"feed:{f.id}", client_id=None, created_by=f.created_by, db=db):
                count += 1
        f.last_sync_at, f.last_sync_status, f.last_sync_count, f.last_error = utcnow(), "ok", count, ""
    except (SecurityError, httpx.HTTPError, ValueError) as e:
        f.last_sync_at, f.last_sync_status, f.last_error = utcnow(), "error", str(e)[:400]
        audit.record(db, "threat_intel.feed.sync", actor=p.label, actor_id=p.user.id, resource_type="threat_feed", resource_id=f.id, outcome="failure", ip=p.ip)
        return _feed_out(f)
    audit.record(db, "threat_intel.feed.sync", actor=p.label, actor_id=p.user.id, resource_type="threat_feed", resource_id=f.id, outcome="success", ip=p.ip, meta={"imported": f.last_sync_count})
    return _feed_out(f)
