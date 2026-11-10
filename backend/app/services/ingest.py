"""Alert normalisation pipeline: dedup, enrichment with asset/client context, SLA, events."""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..connectors.base import NormAlert
from ..models import Alert, AlertReceipt, Asset, Server, Tool, utcnow
from ..policy import SEVERITIES, sev_rank
from ..security import sha256_hex
from ..sla import apply_sla
from . import events
from .settings_svc import get_setting

WAZUH_DEFAULT_LEVELS = [(15, "critical"), (12, "high"), (7, "medium"), (4, "low")]


def map_severity(tool: Tool | None, value: str) -> str:
    sm = (tool.severity_map if tool else None) or {}
    v = str(value).strip().lower()
    if v in sm and sm[v] in SEVERITIES:
        return str(sm[v])
    if v in SEVERITIES:
        return v
    if v.isdigit():
        n = int(v)
        for threshold, sev in WAZUH_DEFAULT_LEVELS:
            if n >= threshold:
                return sev
        return "info"
    return "low"


def _dedup_key(source: str, n: NormAlert) -> str:
    return sha256_hex("|".join([source, n.rule_id, n.host.lower(), n.src_ip, n.title.lower()]))[:64]


def _find_asset(db: Session, n: NormAlert) -> Asset | None:
    conds = []
    if n.agent_id:
        conds.append(Asset.agent_id == n.agent_id)
    if n.host:
        conds.append(Asset.name == n.host)
        conds.append(Asset.hostname == n.host)
    if not conds:
        return None
    return db.execute(select(Asset).where(or_(*conds), Asset.decommissioned.is_(False)).limit(1)).scalars().first()


def _find_server(db: Session, host: str) -> Server | None:
    if not host:
        return None
    return db.execute(select(Server).where(or_(Server.host == host, Server.name == host)).limit(1)).scalars().first()


def ingest_alert(db: Session, tool: Tool | None, n: NormAlert, *, source: str | None = None) -> tuple[Alert, bool]:
    """Store one normalised alert. Returns (alert, created). Idempotent per (tool, source_id)."""
    src = source or (tool.type if tool else "manual")
    tool_id = tool.id if tool else None
    if tool_id and n.source_id:
        existing = db.execute(select(AlertReceipt).where(AlertReceipt.tool_id == tool_id, AlertReceipt.source_id == n.source_id)).scalar_one_or_none()
        if existing and existing.alert_id:
            a = db.get(Alert, existing.alert_id)
            if a is not None:
                return a, False
    now = utcnow()
    sev = map_severity(tool, n.severity)
    key = _dedup_key(src, n)
    window = int(get_setting(db, "alert_dedup_minutes", 10))
    dup = db.execute(
        select(Alert).where(Alert.dedup_key == key, Alert.last_seen >= now - timedelta(minutes=window), Alert.status.in_(["new", "acknowledged", "investigating"])).order_by(Alert.last_seen.desc()).limit(1)
    ).scalars().first()
    if dup is not None:
        dup.count += 1
        dup.last_seen = now
        if sev_rank(sev) > sev_rank(dup.severity):
            dup.severity = sev
        if tool_id and n.source_id:
            _receipt(db, tool_id, n.source_id, dup.id)
        return dup, False
    asset = _find_asset(db, n)
    server = _find_server(db, n.host)
    client_id = (asset.client_id if asset else None) or (server.client_id if server else None) or (tool.config.get("client_id") if tool else None)
    t = n.time or now
    a = Alert(
        tool_id=tool_id, source=src, source_id=n.source_id, time=t, first_seen=t, last_seen=now, severity=sev, title=n.title[:500],
        description=n.description[:20000], rule_id=n.rule_id[:80], mitre=n.mitre, compliance=n.compliance, host=n.host[:255],
        src_ip=n.src_ip[:64], dst_ip=n.dst_ip[:64], username=n.username[:160], file_hash=n.file_hash[:128], raw=n.raw,
        asset_id=asset.id if asset else None, client_id=client_id, dedup_key=key, category=n.category, ingested_at=now,
    )
    apply_sla(db, a)
    db.add(a)
    db.flush()
    if tool_id and n.source_id:
        _receipt(db, tool_id, n.source_id, a.id)
    events.publish(db, "alert.created", id=a.id, severity=a.severity, client_id=a.client_id, category=a.category)
    return a, True


def _receipt(db: Session, tool_id: str, source_id: str, alert_id: str) -> None:
    try:
        with db.begin_nested():
            db.add(AlertReceipt(tool_id=tool_id, source_id=source_id, alert_id=alert_id))
            db.flush()
    except IntegrityError:
        pass


def handle_infra_status(db: Session, a: Alert) -> None:
    """Uptime-style alerts drive server status; recovery closes the matching down alert."""
    if a.category != "infrastructure":
        return
    srv = _find_server(db, a.host)
    if a.rule_id == "kuma.down":
        if srv is not None and srv.status != "down":
            srv.status, srv.status_changed_at = "down", utcnow()
            events.publish(db, "server.down", id=srv.id, severity="critical", client_id=srv.client_id)
    elif a.rule_id == "kuma.up":
        if srv is not None:
            srv.status, srv.status_changed_at = "up", utcnow()
        for d in db.execute(select(Alert).where(Alert.rule_id == "kuma.down", Alert.host == a.host, Alert.status.in_(["new", "acknowledged", "investigating"]))).scalars():
            d.status, d.resolved_at = "resolved", utcnow()
        a.status, a.resolved_at = "resolved", utcnow()


def upsert_assets(db: Session, tool: Tool, items: list[dict[str, Any]]) -> int:
    from datetime import datetime

    n = 0
    for it in items:
        agent_id = str(it.get("agent_id") or "")
        name = str(it.get("name") or "")
        if not (agent_id or name):
            continue
        a = None
        if agent_id:
            a = db.execute(select(Asset).where(Asset.agent_id == agent_id)).scalars().first()
        if a is None and name:
            a = db.execute(select(Asset).where(Asset.name == name)).scalars().first()
        if a is None:
            a = Asset(name=name or agent_id, agent_id=agent_id or None, client_id=tool.config.get("client_id"))
            db.add(a)
        a.hostname = name or a.hostname
        if it.get("ips"):
            a.ips = it["ips"]
        a.os = it.get("os") or a.os
        a.agent_status = it.get("agent_status", a.agent_status)
        ls = it.get("last_seen")
        if isinstance(ls, str):
            try:
                a.last_seen = datetime.fromisoformat(ls.replace("Z", "+00:00"))
            except ValueError:
                pass
        a.source_ids = {**(a.source_ids or {}), tool.type: agent_id}
        n += 1
    db.flush()
    return n
