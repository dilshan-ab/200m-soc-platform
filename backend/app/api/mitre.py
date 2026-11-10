"""MITRE ATT&CK matrix API – technique catalog and alert coverage heatmap."""
from __future__ import annotations

import json
from datetime import timedelta
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import cast, func, select, String
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import Principal, require
from ..models import Alert, SigmaRule, utcnow

router = APIRouter(prefix="/api/mitre", tags=["mitre"])

_TECHNIQUES: list[dict[str, Any]] = []


def _load_techniques() -> list[dict[str, Any]]:
    global _TECHNIQUES
    if _TECHNIQUES:
        return _TECHNIQUES
    p = Path(__file__).resolve().parent.parent / "data" / "mitre_attack.json"
    if p.exists():
        _TECHNIQUES = json.loads(p.read_text())
    return _TECHNIQUES


TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]


@router.get("/techniques")
def list_techniques() -> dict[str, Any]:
    techniques = _load_techniques()
    return {"techniques": techniques, "tactics": TACTIC_ORDER}


@router.get("/matrix")
def attack_matrix(
    p: Principal = Depends(require("alerts.read")),
    db: Session = Depends(get_db),
    days: int = Query(default=90, ge=1, le=365),
) -> dict[str, Any]:
    techniques = _load_techniques()
    cutoff = utcnow() - timedelta(days=days)

    rows = db.execute(
        select(Alert.mitre, Alert.severity)
        .where(p.scope(Alert.client_id))
        .where(Alert.time >= cutoff)
        .where(Alert.mitre.isnot(None))
    ).all()

    counts: dict[str, int] = {}
    severities: dict[str, str] = {}
    sev_rank = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}

    for mitre_json, sev in rows:
        ids = mitre_json if isinstance(mitre_json, list) else json.loads(mitre_json or "[]")
        if not ids:
            continue
        for tid in set(ids):
            counts[tid] = counts.get(tid, 0) + 1
            if sev_rank.get(sev, 0) > sev_rank.get(severities.get(tid, ""), -1):
                severities[tid] = sev

    rule_counts: dict[str, int] = {}
    for (technique_ids,) in db.execute(select(SigmaRule.technique_ids).where(SigmaRule.enabled.is_(True))).all():
        for tid in set(technique_ids or []):
            rule_counts[tid] = rule_counts.get(tid, 0) + 1

    by_tactic: dict[str, list[dict[str, Any]]] = {t: [] for t in TACTIC_ORDER}
    covered = 0
    rules_covered = 0
    for tech in techniques:
        tid = tech["id"]
        alert_count = counts.get(tid, 0)
        rule_count = rule_counts.get(tid, 0)
        if alert_count > 0:
            covered += 1
        if rule_count > 0:
            rules_covered += 1
        entry = {
            "id": tid,
            "name": tech["name"],
            "count": alert_count,
            "max_severity": severities.get(tid, "none"),
            "rule_count": rule_count,
        }
        for tactic in tech.get("tactics", []):
            if tactic in by_tactic:
                by_tactic[tactic].append(entry)

    return {
        "tactics": TACTIC_ORDER,
        "matrix": by_tactic,
        "total_techniques": len(techniques),
        "covered": covered,
        "coverage_pct": round(covered / max(len(techniques), 1) * 100, 1),
        "total_alerts_mapped": sum(counts.values()),
        "rules_covered": rules_covered,
        "rules_coverage_pct": round(rules_covered / max(len(techniques), 1) * 100, 1),
        "total_rules_mapped": sum(rule_counts.values()),
        "days": days,
    }


@router.get("/technique/{technique_id}/alerts")
def technique_alerts(
    technique_id: str,
    p: Principal = Depends(require("alerts.read")),
    db: Session = Depends(get_db),
    page: int = Query(default=1, ge=1),
    limit: int = Query(default=20, ge=1, le=100),
    days: int | None = Query(default=None, ge=1, le=365),
) -> dict[str, Any]:
    from .common import page_out

    techniques = _load_techniques()
    tech = next((t for t in techniques if t["id"] == technique_id), None)

    q = (
        select(Alert)
        .where(p.scope(Alert.client_id))
        .where(cast(Alert.mitre, String).contains(f'"{technique_id}"', autoescape=True))
        .order_by(Alert.time.desc(), Alert.id)
    )

    if days is not None:
        q = q.where(Alert.time >= utcnow() - timedelta(days=days))

    total_q = select(func.count()).select_from(q.order_by(None).subquery())
    total = db.execute(total_q).scalar_one()
    alerts = db.execute(q.limit(limit).offset((page - 1) * limit)).scalars().all()

    items = [
        {
            "id": a.id,
            "title": a.title,
            "severity": a.severity,
            "status": a.status,
            "time": a.time.isoformat() + "Z" if a.time else None,
            "src_ip": a.src_ip,
            "host": a.host,
            "mitre": a.mitre,
        }
        for a in alerts
    ]

    result = page_out(items, total, page, limit)
    if tech:
        result["technique"] = tech
    return result
