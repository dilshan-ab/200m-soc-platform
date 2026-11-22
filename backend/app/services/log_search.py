"""Log search service: queries Wazuh indexer (OpenSearch) and falls back to local alerts DB."""
from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..connectors.base import ConnectorError
from ..models import Alert, Tool
from . import tools_svc


def _build_opensearch_query(
    q: str,
    index: str,
    start: str | None,
    end: str | None,
    severity: str | None,
    host: str | None,
    rule_id: str | None,
    agent_id: str | None,
    src_ip: str | None,
    size: int,
    from_: int,
    sort_field: str,
    sort_order: str,
) -> dict[str, Any]:
    must: list[dict[str, Any]] = []
    if q:
        must.append({"query_string": {"query": q, "default_operator": "AND"}})
    range_filter: dict[str, Any] = {}
    if start:
        range_filter["gte"] = start
    if end:
        range_filter["lte"] = end
    if range_filter:
        must.append({"range": {"timestamp": range_filter}})
    if severity:
        must.append({"match": {"rule.level": severity}})
    if host:
        must.append({"match": {"agent.name": host}})
    if rule_id:
        must.append({"match": {"rule.id": rule_id}})
    if agent_id:
        must.append({"match": {"agent.id": agent_id}})
    if src_ip:
        must.append({"match": {"data.srcip": src_ip}})

    body: dict[str, Any] = {
        "size": min(size, 500),
        "from": from_,
        "sort": [{sort_field: {"order": sort_order}}],
        "track_total_hits": True,
    }
    if must:
        body["query"] = {"bool": {"must": must}}
    return body


def search_wazuh(
    db: Session,
    q: str = "",
    index: str = "",
    start: str | None = None,
    end: str | None = None,
    severity: str | None = None,
    host: str | None = None,
    rule_id: str | None = None,
    agent_id: str | None = None,
    src_ip: str | None = None,
    size: int = 50,
    from_: int = 0,
    sort_field: str = "timestamp",
    sort_order: str = "desc",
) -> dict[str, Any]:
    """Search Wazuh indexer directly via OpenSearch API."""
    tool = db.execute(
        select(Tool).where(Tool.type == "wazuh_indexer", Tool.enabled.is_(True)).limit(1)
    ).scalars().first()
    if tool is None:
        raise ConnectorError("No Wazuh indexer configured. Add one in Integrations.")

    connector = tools_svc.build_connector(db, tool)
    idx = index or tool.config.get("index_pattern") or "wazuh-alerts-*"
    body = _build_opensearch_query(q, idx, start, end, severity, host, rule_id, agent_id, src_ip, size, from_, sort_field, sort_order)
    try:
        result = connector.json("POST", f"/{idx}/_search", json=body, auth=(str(tool.config.get("username", "")), connector.secrets.get("password", "")))
    finally:
        connector.close()

    hits = result.get("hits", {})
    total = hits.get("total", {})
    total_count = total.get("value", 0) if isinstance(total, dict) else total

    logs = []
    for hit in hits.get("hits", []):
        src = hit.get("_source", {})
        rule = src.get("rule", {})
        agent = src.get("agent", {})
        data = src.get("data", {})
        logs.append({
            "id": hit.get("_id", ""),
            "index": hit.get("_index", ""),
            "timestamp": src.get("timestamp", ""),
            "rule_id": str(rule.get("id", "")),
            "rule_level": rule.get("level"),
            "rule_description": str(rule.get("description", "")),
            "rule_groups": rule.get("groups", []),
            "mitre": rule.get("mitre", {}),
            "agent_id": str(agent.get("id", "")),
            "agent_name": str(agent.get("name", "")),
            "agent_ip": str(agent.get("ip", "")),
            "src_ip": str(data.get("srcip", "")),
            "dst_ip": str(data.get("dstip", "")),
            "src_port": data.get("srcport"),
            "dst_port": data.get("dstport"),
            "username": str(data.get("dstuser", data.get("srcuser", ""))),
            "location": str(src.get("location", "")),
            "full_log": str(src.get("full_log", "")),
            "raw": src,
        })

    return {
        "source": "wazuh",
        "total": total_count,
        "from": from_,
        "size": len(logs),
        "logs": logs,
    }


def search_local(
    db: Session,
    p_scope,
    q: str = "",
    start: str | None = None,
    end: str | None = None,
    severity: str | None = None,
    host: str | None = None,
    rule_id: str | None = None,
    src_ip: str | None = None,
    size: int = 50,
    from_: int = 0,
    sort_order: str = "desc",
) -> dict[str, Any]:
    """Search local alerts database as fallback or complement."""
    filters = [p_scope]
    if q:
        like = f"%{q}%"
        filters.append(
            Alert.title.ilike(like) | Alert.description.ilike(like) | Alert.host.ilike(like) |
            Alert.src_ip.ilike(like) | Alert.username.ilike(like) | Alert.rule_id.ilike(like)
        )
    if start:
        filters.append(Alert.time >= start)
    if end:
        filters.append(Alert.time <= end)
    if severity:
        filters.append(Alert.severity == severity)
    if host:
        filters.append(Alert.host.ilike(f"%{host}%"))
    if rule_id:
        filters.append(Alert.rule_id == rule_id)
    if src_ip:
        filters.append(Alert.src_ip == src_ip)

    total = db.execute(select(func.count()).where(*filters)).scalar_one()
    order = Alert.time.desc() if sort_order == "desc" else Alert.time.asc()
    rows = db.execute(
        select(Alert).where(*filters).order_by(order).offset(from_).limit(min(size, 500))
    ).scalars().all()

    logs = []
    for a in rows:
        logs.append({
            "id": a.id,
            "index": "local",
            "timestamp": a.time.isoformat() if a.time else "",
            "rule_id": a.rule_id,
            "rule_level": {"info": 1, "low": 3, "medium": 7, "high": 10, "critical": 14}.get(a.severity, 3),
            "rule_description": a.title,
            "rule_groups": [],
            "mitre": {"id": a.mitre} if a.mitre else {},
            "agent_id": "",
            "agent_name": a.host,
            "agent_ip": "",
            "src_ip": a.src_ip,
            "dst_ip": a.dst_ip,
            "src_port": None,
            "dst_port": None,
            "username": a.username,
            "location": a.source,
            "full_log": a.description,
            "raw": {
                "id": a.id,
                "title": a.title,
                "description": a.description,
                "severity": a.severity,
                "status": a.status,
                "host": a.host,
                "src_ip": a.src_ip,
                "dst_ip": a.dst_ip,
                "username": a.username,
                "rule_id": a.rule_id,
                "mitre": a.mitre,
                "compliance": a.compliance,
                "raw": a.raw,
                "enrichment": a.enrichment,
                "time": a.time.isoformat() if a.time else "",
            },
        })

    return {
        "source": "local",
        "total": total,
        "from": from_,
        "size": len(logs),
        "logs": logs,
    }


def get_field_values(db: Session, field: str) -> list[str]:
    """Get distinct values for a field (for filter dropdowns)."""
    col_map = {
        "severity": Alert.severity,
        "host": Alert.host,
        "rule_id": Alert.rule_id,
        "source": Alert.source,
        "status": Alert.status,
    }
    col = col_map.get(field)
    if col is None:
        return []
    rows = db.execute(
        select(col).where(col != "").group_by(col).order_by(func.count().desc()).limit(50)
    ).scalars().all()
    return [str(r) for r in rows]


def get_indices(db: Session) -> list[dict[str, Any]]:
    """List available Wazuh indices."""
    tool = db.execute(
        select(Tool).where(Tool.type == "wazuh_indexer", Tool.enabled.is_(True)).limit(1)
    ).scalars().first()
    if tool is None:
        return [{"name": "local", "docs": 0, "label": "Platform alerts (local DB)"}]

    connector = tools_svc.build_connector(db, tool)
    try:
        result = connector.json("GET", "/_cat/indices/wazuh-*?format=json&h=index,docs.count,store.size",
                                auth=(str(tool.config.get("username", "")), connector.secrets.get("password", "")))
    except ConnectorError:
        return [{"name": "local", "docs": 0, "label": "Platform alerts (local DB)"}]
    finally:
        connector.close()

    indices = []
    for idx in (result if isinstance(result, list) else []):
        indices.append({
            "name": idx.get("index", ""),
            "docs": int(idx.get("docs.count", 0)),
            "size": idx.get("store.size", ""),
        })
    indices.sort(key=lambda x: x["name"], reverse=True)
    return indices
