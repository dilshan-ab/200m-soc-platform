"""Evidence file storage API: upload, download, and browse evidence across all cases."""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import Principal, require
from ..models import Case, CaseEvidence, utcnow
from .. import audit
from ..services import cases as case_svc, evidence as svc

router = APIRouter(prefix="/api/evidence", tags=["evidence"])


@router.get("/")
def list_evidence(
    p: Principal = Depends(require("evidence.read")),
    db: Session = Depends(get_db),
    case_id: str | None = Query(default=None, max_length=36),
    type: str | None = Query(default=None, max_length=30),
    q: str | None = Query(default=None, max_length=200),
    size: int = Query(default=50, ge=1, le=200),
    page: int = Query(default=1, ge=1),
) -> dict[str, Any]:
    offset = (page - 1) * size
    return svc.list_all(db, p.scope(None), case_id=case_id, evidence_type=type, q=q, size=size, offset=offset)


@router.get("/stats")
def evidence_stats(p: Principal = Depends(require("evidence.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    return svc.get_stats(db, p.scope(None))


@router.post("/upload/{case_id}", status_code=201)
async def upload_evidence(
    case_id: str,
    file: UploadFile,
    p: Principal = Depends(require("evidence.write")),
    db: Session = Depends(get_db),
    evidence_type: str = Query(default="file", pattern="^(file|screenshot|pcap|log|artifact)$"),
    description: str = Query(default="", max_length=5000),
    tags: str = Query(default=""),
) -> dict[str, Any]:
    case = db.get(Case, case_id)
    if case is None:
        raise HTTPException(404, "Case not found")

    data = await file.read()
    if len(data) > svc.MAX_FILE_SIZE:
        raise HTTPException(413, f"File exceeds maximum size of {svc.MAX_FILE_SIZE // (1024 * 1024)} MB")

    now = utcnow()
    tag_list = [t.strip() for t in tags.split(",") if t.strip()] if tags else []
    e = CaseEvidence(
        case_id=case.id, name=file.filename or "unnamed", type=evidence_type,
        description=description, tags=tag_list,
        collected_by=p.label, collected_at=now, client_id=case.client_id,
        chain_of_custody=[{"actor": p.label, "action": "uploaded", "at": now.isoformat(), "note": f"File uploaded: {file.filename}"}],
    )
    db.add(e)
    db.flush()

    storage_ref, sha256, size = svc.save_file(case.id, e.id, file.filename or "file", data)
    e.storage_ref = storage_ref
    e.hash_sha256 = sha256
    e.file_size = size
    db.flush()

    case_svc.add_event(db, case, p.label, "evidence", f"Evidence uploaded: {file.filename}")
    audit.record(db, "evidence.upload", actor=p.label, actor_id=p.user.id, resource_type="evidence", resource_id=e.id, client_id=case.client_id, ip=p.ip)

    return svc._out(e)


@router.get("/download/{evidence_id}")
def download_evidence(evidence_id: str, p: Principal = Depends(require("evidence.read")), db: Session = Depends(get_db)):
    e = db.get(CaseEvidence, evidence_id)
    if e is None:
        raise HTTPException(404, "Evidence not found")
    if not e.storage_ref:
        raise HTTPException(404, "No file attached to this evidence item")

    try:
        path, filename = svc.read_file(e.storage_ref)
    except FileNotFoundError:
        raise HTTPException(404, "Evidence file not found on disk")

    chain = list(e.chain_of_custody or [])
    chain.append({"actor": p.label, "action": "downloaded", "at": utcnow().isoformat(), "note": "File downloaded"})
    e.chain_of_custody = chain
    db.flush()

    return FileResponse(path, filename=filename, media_type="application/octet-stream")


@router.delete("/{evidence_id}", status_code=204)
def delete_evidence(evidence_id: str, p: Principal = Depends(require("evidence.write")), db: Session = Depends(get_db)):
    e = db.get(CaseEvidence, evidence_id)
    if e is None:
        raise HTTPException(404, "Evidence not found")
    svc.delete_file(e.storage_ref)
    db.delete(e)
    db.flush()
    audit.record(db, "evidence.delete", actor=p.label, actor_id=p.user.id, resource_type="evidence", resource_id=evidence_id, ip=p.ip)
