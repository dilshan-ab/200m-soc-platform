"""User Entity Behavior Analytics: baseline computation, anomaly detection, risk scoring."""
from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Alert, EntityProfile, utcnow


def _get_or_create_profile(db: Session, entity_type: str, entity_value: str, client_id: str | None) -> EntityProfile:
    p = db.execute(
        select(EntityProfile).where(EntityProfile.entity_type == entity_type, EntityProfile.entity_value == entity_value, EntityProfile.client_id == client_id)
    ).scalars().first()
    if p is None:
        p = EntityProfile(entity_type=entity_type, entity_value=entity_value, client_id=client_id)
        db.add(p)
        db.flush()
    return p


def compute_entity_profiles(db: Session, days: int = 30, client_id: str | None = None) -> dict[str, int]:
    """Rebuild behavioral baselines for all entities seen in the last N days."""
    since = utcnow() - timedelta(days=days)
    q = select(Alert).where(Alert.time >= since, Alert.category == "security")
    if client_id:
        q = q.where(Alert.client_id == client_id)
    alerts = db.execute(q).scalars().all()

    entities: dict[tuple[str, str, str | None], list[Alert]] = defaultdict(list)
    for a in alerts:
        cid = a.client_id
        if a.username:
            entities[("user", a.username, cid)].append(a)
        if a.host:
            entities[("host", a.host, cid)].append(a)
        if a.src_ip and a.src_ip not in ("", "0.0.0.0", "127.0.0.1", "::1"):
            entities[("ip", a.src_ip, cid)].append(a)

    updated = 0
    for (etype, evalue, cid), alert_list in entities.items():
        profile = _get_or_create_profile(db, etype, evalue, cid)
        baseline = _compute_baseline(alert_list, days)
        anomalies = _detect_anomalies(alert_list, baseline)
        risk_score = _calculate_risk_score(alert_list, anomalies)

        profile.alert_count = len(alert_list)
        profile.baseline = baseline
        profile.anomalies = anomalies
        profile.risk_score = round(risk_score, 1)
        profile.first_seen = min(a.time for a in alert_list)
        profile.last_seen = max(a.time for a in alert_list)
        profile.updated_at = utcnow()
        updated += 1

    db.flush()
    return {"entities_updated": updated, "alerts_analyzed": len(alerts)}


def _compute_baseline(alerts: list[Alert], days: int) -> dict[str, Any]:
    """Compute behavioral baseline from historical alerts."""
    if not alerts:
        return {}
    severities = Counter(a.severity for a in alerts)
    rules = Counter(a.rule_id for a in alerts if a.rule_id)
    hours = Counter(a.time.hour for a in alerts if a.time)
    techniques: list[str] = []
    for a in alerts:
        techniques.extend(a.mitre or [])
    technique_counts = Counter(techniques)

    alerts_per_day = len(alerts) / max(days, 1)
    active_days = len({a.time.date() for a in alerts if a.time})
    peak_hours = [h for h, _ in hours.most_common(4)]

    return {
        "alerts_per_day": round(alerts_per_day, 2),
        "active_days": active_days,
        "severity_distribution": dict(severities),
        "top_rules": dict(rules.most_common(10)),
        "peak_hours": peak_hours,
        "top_techniques": dict(technique_counts.most_common(10)),
        "unique_rules": len(rules),
        "unique_sources": len({a.source for a in alerts}),
    }


def _detect_anomalies(alerts: list[Alert], baseline: dict[str, Any]) -> list[dict[str, Any]]:
    """Detect behavioral anomalies against baseline."""
    anomalies: list[dict[str, Any]] = []
    if not alerts or not baseline:
        return anomalies

    now = utcnow()
    recent = [a for a in alerts if a.time and a.time >= now - timedelta(days=1)]
    avg_daily = baseline.get("alerts_per_day", 0)

    if avg_daily > 0 and len(recent) > avg_daily * 3:
        anomalies.append({
            "type": "volume_spike",
            "description": f"Alert volume spike: {len(recent)} alerts in 24h vs {avg_daily:.1f} daily average",
            "score": min(round((len(recent) / avg_daily) * 20, 1), 100),
            "detected_at": now.isoformat(),
        })

    recent_critical = sum(1 for a in recent if a.severity in ("critical", "high"))
    hist_critical_rate = sum(v for k, v in baseline.get("severity_distribution", {}).items() if k in ("critical", "high")) / max(len(alerts), 1)
    if len(recent) > 3 and recent_critical / max(len(recent), 1) > hist_critical_rate * 2 and recent_critical > 2:
        anomalies.append({
            "type": "severity_escalation",
            "description": f"{recent_critical} critical/high alerts in 24h, unusual for this entity",
            "score": min(recent_critical * 15, 100),
            "detected_at": now.isoformat(),
        })

    recent_rules = {a.rule_id for a in recent if a.rule_id}
    known_rules = set(baseline.get("top_rules", {}).keys())
    new_rules = recent_rules - known_rules
    if new_rules and len(new_rules) >= 2:
        anomalies.append({
            "type": "new_behavior",
            "description": f"{len(new_rules)} previously unseen detection rules triggered",
            "score": min(len(new_rules) * 10, 80),
            "detected_at": now.isoformat(),
        })

    peak_hours = set(baseline.get("peak_hours", []))
    if peak_hours and recent:
        off_hours = [a for a in recent if a.time and a.time.hour not in peak_hours]
        if len(off_hours) > len(recent) * 0.5 and len(off_hours) >= 3:
            anomalies.append({
                "type": "unusual_hours",
                "description": f"{len(off_hours)} alerts outside normal activity hours",
                "score": min(len(off_hours) * 8, 60),
                "detected_at": now.isoformat(),
            })

    recent_techniques: list[str] = []
    for a in recent:
        recent_techniques.extend(a.mitre or [])
    known_techniques = set(baseline.get("top_techniques", {}).keys())
    new_techniques = set(recent_techniques) - known_techniques
    if new_techniques and len(new_techniques) >= 2:
        anomalies.append({
            "type": "new_techniques",
            "description": f"{len(new_techniques)} new MITRE techniques observed: {', '.join(list(new_techniques)[:5])}",
            "score": min(len(new_techniques) * 12, 90),
            "detected_at": now.isoformat(),
        })

    return anomalies


def _calculate_risk_score(alerts: list[Alert], anomalies: list[dict[str, Any]]) -> float:
    """Calculate composite risk score (0-100) from alert severity and anomalies."""
    if not alerts:
        return 0.0
    sev_weights = {"critical": 10, "high": 6, "medium": 3, "low": 1, "info": 0}
    now = utcnow()
    recent = [a for a in alerts if a.time and a.time >= now - timedelta(days=7)]

    severity_score = sum(sev_weights.get(a.severity, 0) for a in recent)
    severity_component = min(severity_score / 5, 40)

    volume_component = min(len(recent) / 2, 20)

    anomaly_component = sum(a.get("score", 0) for a in anomalies) / max(len(anomalies), 1) if anomalies else 0
    anomaly_component = min(anomaly_component, 40)

    return min(severity_component + volume_component + anomaly_component, 100)


def get_entity_summary(db: Session, client_id: str | None = None) -> dict[str, Any]:
    """Dashboard summary of entity risk landscape."""
    q = select(EntityProfile)
    if client_id:
        q = q.where(EntityProfile.client_id == client_id)
    profiles = db.execute(q.order_by(EntityProfile.risk_score.desc())).scalars().all()

    by_type: dict[str, int] = Counter(p.entity_type for p in profiles)
    risk_distribution = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for p in profiles:
        if p.risk_score >= 75:
            risk_distribution["critical"] += 1
        elif p.risk_score >= 50:
            risk_distribution["high"] += 1
        elif p.risk_score >= 25:
            risk_distribution["medium"] += 1
        else:
            risk_distribution["low"] += 1

    return {
        "total_entities": len(profiles),
        "by_type": dict(by_type),
        "risk_distribution": risk_distribution,
        "top_risk": [_profile_out(p) for p in profiles[:10]],
        "total_anomalies": sum(len(p.anomalies or []) for p in profiles),
    }


def _profile_out(p: EntityProfile) -> dict[str, Any]:
    return {
        "id": p.id, "entity_type": p.entity_type, "entity_value": p.entity_value,
        "risk_score": p.risk_score, "alert_count": p.alert_count,
        "baseline": p.baseline, "anomalies": p.anomalies,
        "first_seen": p.first_seen.isoformat() if p.first_seen else None,
        "last_seen": p.last_seen.isoformat() if p.last_seen else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
        "client_id": p.client_id,
    }


def list_profiles(db: Session, entity_type: str | None = None, client_id: str | None = None, min_risk: float = 0, limit: int = 100) -> list[dict[str, Any]]:
    q = select(EntityProfile).where(EntityProfile.risk_score >= min_risk)
    if entity_type:
        q = q.where(EntityProfile.entity_type == entity_type)
    if client_id:
        q = q.where(EntityProfile.client_id == client_id)
    profiles = db.execute(q.order_by(EntityProfile.risk_score.desc()).limit(limit)).scalars().all()
    return [_profile_out(p) for p in profiles]


def get_entity_timeline(db: Session, entity_type: str, entity_value: str, days: int = 30) -> list[dict[str, Any]]:
    """Get alert timeline for a specific entity."""
    since = utcnow() - timedelta(days=days)
    field_map = {"user": Alert.username, "host": Alert.host, "ip": Alert.src_ip}
    col = field_map.get(entity_type)
    if col is None:
        return []
    alerts = db.execute(select(Alert).where(col == entity_value, Alert.time >= since).order_by(Alert.time.desc()).limit(200)).scalars().all()
    return [{"id": a.id, "title": a.title, "severity": a.severity, "rule_id": a.rule_id, "mitre": a.mitre,
             "time": a.time.isoformat() if a.time else None, "status": a.status, "host": a.host, "src_ip": a.src_ip, "username": a.username} for a in alerts]
