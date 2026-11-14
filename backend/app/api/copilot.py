from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from .. import audit
from ..config import get_settings
from ..db import get_db
from ..deps import Principal, require, scoped_get
from ..models import Alert, Case
from ..ratelimit import limiter
from ..services import copilot as svc
from ..services.copilot import CopilotError

router = APIRouter(prefix="/api/copilot", tags=["copilot"])


@router.get("/status")
def status(p: Principal = Depends(require("copilot.read"))) -> dict[str, Any]:
    cfg = get_settings()
    return {"enabled": cfg.llm_provider != "none" and bool(cfg.llm_api_key), "provider": cfg.llm_provider, "model": cfg.llm_model}


class AnalyzeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    alert_id: str


@router.post("/analyze")
def analyze(body: AnalyzeIn, p: Principal = Depends(require("copilot.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    if not limiter.allow(f"copilot:{p.user.id}", 20):
        raise HTTPException(429, "copilot rate limit")
    a = scoped_get(db, Alert, body.alert_id, p)
    try:
        result = svc.analyze_alert(db, a.id)
    except CopilotError as e:
        raise HTTPException(503, str(e)) from e
    audit.record(db, "copilot.analyze", actor=p.label, actor_id=p.user.id, resource_type="alert", resource_id=a.id, client_id=a.client_id, ip=p.ip)
    return result


@router.post("/triage")
def triage(body: AnalyzeIn, p: Principal = Depends(require("copilot.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    if not limiter.allow(f"copilot:{p.user.id}", 20):
        raise HTTPException(429, "copilot rate limit")
    a = scoped_get(db, Alert, body.alert_id, p)
    try:
        result = svc.triage_alert(db, a.id)
    except CopilotError as e:
        raise HTTPException(503, str(e)) from e
    audit.record(db, "copilot.triage", actor=p.label, actor_id=p.user.id, resource_type="alert", resource_id=a.id, client_id=a.client_id, ip=p.ip)
    return result


class SummarizeIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    case_id: str


@router.post("/summarize")
def summarize(body: SummarizeIn, p: Principal = Depends(require("copilot.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    if not limiter.allow(f"copilot:{p.user.id}", 10):
        raise HTTPException(429, "copilot rate limit")
    c = scoped_get(db, Case, body.case_id, p)
    try:
        result = svc.summarize_case(db, c.id)
    except CopilotError as e:
        raise HTTPException(503, str(e)) from e
    audit.record(db, "copilot.summarize", actor=p.label, actor_id=p.user.id, resource_type="case", resource_id=c.id, client_id=c.client_id, ip=p.ip)
    return result


@router.post("/suggest-response")
def suggest_response(body: AnalyzeIn, p: Principal = Depends(require("copilot.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    if not limiter.allow(f"copilot:{p.user.id}", 20):
        raise HTTPException(429, "copilot rate limit")
    a = scoped_get(db, Alert, body.alert_id, p)
    try:
        result = svc.suggest_response(db, a.id)
    except CopilotError as e:
        raise HTTPException(503, str(e)) from e
    audit.record(db, "copilot.suggest", actor=p.label, actor_id=p.user.id, resource_type="alert", resource_id=a.id, client_id=a.client_id, ip=p.ip)
    return result


@router.post("/explain")
def explain(body: AnalyzeIn, p: Principal = Depends(require("copilot.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    if not limiter.allow(f"copilot:{p.user.id}", 20):
        raise HTTPException(429, "copilot rate limit")
    a = scoped_get(db, Alert, body.alert_id, p)
    try:
        result = svc.explain_alert(db, a.id)
    except CopilotError as e:
        raise HTTPException(503, str(e)) from e
    return result
