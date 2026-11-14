from __future__ import annotations

import uuid
from typing import Any, Literal

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import Principal, require, scoped_get
from ..models import Case, Notebook
from .common import iso

router = APIRouter(prefix="/api/notebooks", tags=["notebooks"])
CELL_TYPES = ("note", "query", "finding", "ioc")


def _notebook_out(nb: Notebook) -> dict[str, Any]:
    return {
        "id": nb.id, "title": nb.title, "description": nb.description, "case_id": nb.case_id, "client_id": nb.client_id,
        "tags": nb.tags, "cells": nb.cells, "created_by": nb.created_by, "version": nb.version,
        "created_at": iso(nb.created_at), "updated_at": iso(nb.updated_at),
    }


@router.get("")
def list_notebooks(p: Principal = Depends(require("notebooks.read")), db: Session = Depends(get_db), case_id: str | None = None, q: str | None = Query(default=None, max_length=200)) -> list[dict[str, Any]]:
    qy = select(Notebook).where(p.scope(Notebook.client_id)).order_by(Notebook.updated_at.desc())
    if case_id:
        qy = qy.where(Notebook.case_id == case_id)
    if q:
        qy = qy.where(Notebook.title.contains(q, autoescape=True))
    return [_notebook_out(nb) for nb in db.execute(qy).scalars()]


class NotebookIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=2, max_length=300)
    description: str = Field(default="", max_length=4000)
    case_id: str | None = None
    tags: list[str] = Field(default_factory=list, max_length=20)


@router.post("", status_code=201)
def create_notebook(body: NotebookIn, p: Principal = Depends(require("notebooks.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    client_id = None
    if body.case_id:
        case = scoped_get(db, Case, body.case_id, p)
        client_id = case.client_id
    nb = Notebook(title=body.title, description=body.description, case_id=body.case_id, client_id=client_id, tags=body.tags, cells=[], created_by=p.user.id)
    db.add(nb)
    db.flush()
    audit.record(db, "notebook.create", actor=p.label, actor_id=p.user.id, resource_type="notebook", resource_id=nb.id, client_id=nb.client_id, ip=p.ip)
    return _notebook_out(nb)


@router.get("/{nid}")
def get_notebook(nid: str, p: Principal = Depends(require("notebooks.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    return _notebook_out(scoped_get(db, Notebook, nid, p))


class NotebookPatch(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str | None = Field(default=None, min_length=2, max_length=300)
    description: str | None = Field(default=None, max_length=4000)
    tags: list[str] | None = Field(default=None, max_length=20)


@router.patch("/{nid}")
def patch_notebook(nid: str, body: NotebookPatch, p: Principal = Depends(require("notebooks.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    nb = scoped_get(db, Notebook, nid, p)
    if body.title is not None:
        nb.title = body.title
    if body.description is not None:
        nb.description = body.description
    if body.tags is not None:
        nb.tags = body.tags
    nb.version += 1
    audit.record(db, "notebook.update", actor=p.label, actor_id=p.user.id, resource_type="notebook", resource_id=nb.id, client_id=nb.client_id, ip=p.ip)
    return _notebook_out(nb)


@router.delete("/{nid}", status_code=204)
def delete_notebook(nid: str, p: Principal = Depends(require("notebooks.write")), db: Session = Depends(get_db)) -> None:
    nb = scoped_get(db, Notebook, nid, p)
    audit.record(db, "notebook.delete", actor=p.label, actor_id=p.user.id, resource_type="notebook", resource_id=nb.id, client_id=nb.client_id, ip=p.ip, meta={"title": nb.title})
    db.delete(nb)


class CellIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: Literal["note", "query", "finding", "ioc"]
    content: str = Field(default="", max_length=20000)
    filters: dict[str, Any] = Field(default_factory=dict)


def _cell_out(c: CellIn, *, actor: str) -> dict[str, Any]:
    from ..models import utcnow

    return {"id": uuid.uuid4().hex[:12], "type": c.type, "content": c.content, "filters": c.filters, "result_count": None, "result_sample": [], "ran_at": None, "created_by": actor, "created_at": iso(utcnow())}


class CellsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: int
    cells: list[dict[str, Any]] = Field(max_length=300)


@router.put("/{nid}/cells")
def replace_cells(nid: str, body: CellsIn, p: Principal = Depends(require("notebooks.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    """Replace the full ordered cell list (optimistic concurrency via `version`). The client adds, edits, reorders, or removes cells, then saves the whole array."""
    nb = scoped_get(db, Notebook, nid, p)
    if nb.version != body.version:
        raise HTTPException(409, "notebook was modified by someone else; reload")
    for c in body.cells:
        if c.get("type") not in CELL_TYPES:
            raise HTTPException(400, f"invalid cell type: {c.get('type')}")
        if "id" not in c:
            c["id"] = uuid.uuid4().hex[:12]
    nb.cells = body.cells
    nb.version += 1
    audit.record(db, "notebook.cells", actor=p.label, actor_id=p.user.id, resource_type="notebook", resource_id=nb.id, client_id=nb.client_id, ip=p.ip, meta={"cell_count": len(body.cells)})
    return _notebook_out(nb)


@router.post("/{nid}/cells/new")
def new_cell(nid: str, body: CellIn, p: Principal = Depends(require("notebooks.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    """Convenience endpoint: append one cell without needing to resend the whole array."""
    nb = scoped_get(db, Notebook, nid, p)
    nb.cells = [*nb.cells, _cell_out(body, actor=p.label)]
    nb.version += 1
    return _notebook_out(nb)
