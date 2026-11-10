from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import HTTPException
from sqlalchemy import Select, func, select
from sqlalchemy.orm import Session

from ..models import User


def paginate(db: Session, q: Select[Any], page: int, limit: int) -> tuple[list[Any], int]:
    limit = max(1, min(limit, 200))
    page = max(1, page)
    total = db.execute(select(func.count()).select_from(q.order_by(None).subquery())).scalar_one()
    rows = db.execute(q.limit(limit).offset((page - 1) * limit)).scalars().all()
    return list(rows), int(total)


def page_out(items: list[Any], total: int, page: int, limit: int) -> dict[str, Any]:
    return {"items": items, "total": total, "page": page, "limit": min(max(limit, 1), 200)}


def iso(d: datetime | None) -> str | None:
    return d.isoformat() if d else None


def user_label(db: Session, uid: str | None) -> str | None:
    if not uid:
        return None
    u = db.get(User, uid)
    return u.name or u.email if u else None


def bad(msg: str, code: int = 400) -> HTTPException:
    return HTTPException(code, msg)
