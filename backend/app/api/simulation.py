from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import audit
from ..connectors.base import REGISTRY
from ..db import get_db
from ..deps import Principal, require
from ..models import Tool
from ..services import tools_svc

router = APIRouter(prefix="/api/simulation", tags=["simulation"])
SIM_TYPES = ("caldera", "atomic_red_team", "attack_simulator")


@router.get("/platforms")
def list_platforms(p: Principal = Depends(require("simulation.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    """List attack simulation platforms: built-in connector types and whether each is configured."""
    platforms = []
    for sys_type in SIM_TYPES:
        cls = REGISTRY.get(sys_type)
        if cls is None:
            continue
        manifest = cls.manifest
        tool = db.execute(select(Tool).where(Tool.type == sys_type)).scalars().first()
        platforms.append({
            "system_type": sys_type,
            "name": manifest.label,
            "description": manifest.setup_hint,
            "configured": tool is not None,
            "tool_id": tool.id if tool else None,
            "capabilities": manifest.capabilities,
        })
    return platforms


class RunSimIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool_id: str
    action_key: str
    targets: list[str] = []
    params: dict[str, Any] = {}


def _get_sim_tool(db: Session, tool_id: str) -> Tool:
    tool = db.get(Tool, tool_id)
    if tool is None or tool.type not in SIM_TYPES:
        raise HTTPException(404, "simulation tool not found")
    return tool


@router.post("/run")
def run_simulation(body: RunSimIn, p: Principal = Depends(require("simulation.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    """Execute an attack simulation action."""
    tool = _get_sim_tool(db, body.tool_id)
    try:
        conn = tools_svc.build_connector(db, tool)
        try:
            result = conn.execute(body.action_key, body.targets, body.params)
        finally:
            conn.close()
    except Exception as e:
        raise HTTPException(502, f"simulation execution failed: {e}") from e
    audit.record(db, "simulation.run", actor=p.label, actor_id=p.user.id, resource_type="tool", resource_id=tool.id, ip=p.ip, meta={"action": body.action_key, "targets": body.targets})
    return {"status": "ok", "result": result}


class ResultsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool_id: str


@router.post("/results")
def get_results(body: ResultsIn, p: Principal = Depends(require("simulation.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    """Poll simulation results from a platform."""
    tool = _get_sim_tool(db, body.tool_id)
    try:
        conn = tools_svc.build_connector(db, tool)
        try:
            poll = conn.poll({}, limit=200)
        finally:
            conn.close()
    except Exception as e:
        raise HTTPException(502, f"failed to fetch results: {e}") from e
    return {"findings": poll.findings, "count": len(poll.findings)}
