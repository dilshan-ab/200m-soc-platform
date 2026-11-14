from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from .. import audit
from ..db import get_db
from ..deps import Principal, require
from ..models import Tool
from ..services import tools_svc

router = APIRouter(prefix="/api/simulation", tags=["simulation"])


@router.get("/platforms")
def list_platforms(p: Principal = Depends(require("simulation.read")), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    """List configured attack simulation platforms."""
    from ..connectors.plugins import REGISTRY
    sim_types = {"caldera", "atomic_red_team", "attack_simulator"}
    platforms = []
    for sys_type in sim_types:
        manifest = REGISTRY.get(sys_type)
        if not manifest:
            continue
        tool = db.query(Tool).filter(Tool.system_type == sys_type, Tool.client_id.in_(p.client_ids)).first() if not p.all_clients else db.query(Tool).filter(Tool.system_type == sys_type).first()
        platforms.append({
            "system_type": sys_type,
            "name": manifest.name,
            "description": manifest.description,
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


@router.post("/run")
def run_simulation(body: RunSimIn, p: Principal = Depends(require("simulation.write")), db: Session = Depends(get_db)) -> dict[str, Any]:
    """Execute an attack simulation action."""
    tool = db.get(Tool, body.tool_id)
    if not tool:
        raise HTTPException(404, "Simulation tool not found")
    try:
        conn = tools_svc.build_connector(db, tool)
        result = conn.execute(body.action_key, body.targets, body.params)
    except Exception as e:
        raise HTTPException(502, f"Simulation execution failed: {e}") from e
    audit.record(db, "simulation.run", actor=p.label, actor_id=p.user.id, resource_type="tool", resource_id=tool.id, client_id=tool.client_id, ip=p.ip, meta={"action": body.action_key, "targets": body.targets})
    return {"status": "ok", "result": result}


@router.post("/results")
def get_results(body: RunSimIn, p: Principal = Depends(require("simulation.read")), db: Session = Depends(get_db)) -> dict[str, Any]:
    """Poll simulation results from a platform."""
    tool = db.get(Tool, body.tool_id)
    if not tool:
        raise HTTPException(404, "Simulation tool not found")
    try:
        conn = tools_svc.build_connector(db, tool)
        poll = conn.poll({}, limit=200)
    except Exception as e:
        raise HTTPException(502, f"Failed to fetch results: {e}") from e
    return {"findings": poll.findings, "count": len(poll.findings)}
