"""Evidence file storage service: upload, download, and manage forensic evidence files."""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import CaseEvidence

EVIDENCE_DIR = Path(os.environ.get("EVIDENCE_DIR", "/data/evidence"))
MAX_FILE_SIZE = 100 * 1024 * 1024  # 100 MB


def _ensure_dir(case_id: str) -> Path:
    d = EVIDENCE_DIR / case_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_file(case_id: str, evidence_id: str, filename: str, data: bytes) -> tuple[str, str, int]:
    """Save evidence file, return (storage_ref, sha256, size)."""
    if len(data) > MAX_FILE_SIZE:
        raise ValueError(f"File exceeds maximum size of {MAX_FILE_SIZE // (1024 * 1024)} MB")
    d = _ensure_dir(case_id)
    safe_name = evidence_id + "_" + filename.replace("/", "_").replace("\\", "_")
    path = d / safe_name
    path.write_bytes(data)
    sha256 = hashlib.sha256(data).hexdigest()
    return str(path.relative_to(EVIDENCE_DIR)), sha256, len(data)


def read_file(storage_ref: str) -> tuple[Path, str]:
    """Return (path, filename) for download."""
    path = EVIDENCE_DIR / storage_ref
    if not path.exists() or not path.is_file():
        raise FileNotFoundError("Evidence file not found on disk")
    filename = path.name.split("_", 1)[1] if "_" in path.name else path.name
    return path, filename


def delete_file(storage_ref: str) -> None:
    if not storage_ref:
        return
    path = EVIDENCE_DIR / storage_ref
    if path.exists():
        path.unlink()


def list_all(db: Session, p_scope, case_id: str | None = None, evidence_type: str | None = None,
             q: str | None = None, size: int = 50, offset: int = 0) -> dict[str, Any]:
    filters = [p_scope]
    if case_id:
        filters.append(CaseEvidence.case_id == case_id)
    if evidence_type:
        filters.append(CaseEvidence.type == evidence_type)
    if q:
        like = f"%{q}%"
        filters.append(CaseEvidence.name.ilike(like) | CaseEvidence.description.ilike(like) | CaseEvidence.tags.cast(str).ilike(like))

    total = db.execute(select(func.count()).select_from(CaseEvidence).where(*filters)).scalar_one()
    rows = db.execute(
        select(CaseEvidence).where(*filters).order_by(CaseEvidence.collected_at.desc()).offset(offset).limit(min(size, 200))
    ).scalars().all()

    return {"total": total, "items": [_out(e) for e in rows]}


def get_stats(db: Session, p_scope) -> dict[str, Any]:
    base = [p_scope]
    total = db.execute(select(func.count()).select_from(CaseEvidence).where(*base)).scalar_one()
    total_size = db.execute(select(func.coalesce(func.sum(CaseEvidence.file_size), 0)).where(*base)).scalar_one()
    with_files = db.execute(select(func.count()).select_from(CaseEvidence).where(*base, CaseEvidence.storage_ref != "")).scalar_one()

    type_counts = {}
    for row in db.execute(select(CaseEvidence.type, func.count()).where(*base).group_by(CaseEvidence.type)):
        type_counts[row[0]] = row[1]

    return {
        "total_items": total,
        "total_size_bytes": total_size,
        "items_with_files": with_files,
        "items_metadata_only": total - with_files,
        "by_type": type_counts,
    }


def _out(e: CaseEvidence) -> dict[str, Any]:
    return {
        "id": e.id, "case_id": e.case_id, "name": e.name, "type": e.type,
        "description": e.description, "hash_sha256": e.hash_sha256,
        "file_size": e.file_size, "storage_ref": e.storage_ref,
        "has_file": bool(e.storage_ref), "tags": e.tags,
        "collected_by": e.collected_by,
        "collected_at": e.collected_at.isoformat() if e.collected_at else "",
        "chain_of_custody": e.chain_of_custody,
        "observable_id": e.observable_id, "alert_id": e.alert_id,
        "client_id": e.client_id, "created_at": e.created_at.isoformat() if e.created_at else "",
    }
