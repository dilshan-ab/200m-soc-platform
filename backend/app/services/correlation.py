"""Alert correlation engine — groups related alerts into incidents."""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import Alert, CorrelationRule, Incident, utcnow
from ..policy import SEVERITIES, sev_rank

IOC_FIELDS = ("src_ip", "dst_ip", "host", "username", "file_hash")


def _boost_severity(base: str, boost: int) -> str:
    idx = min(sev_rank(base) + boost, len(SEVERITIES) - 1)
    return SEVERITIES[idx]


def _alert_iocs(a: Alert, fields: list[str] | None = None) -> dict[str, str]:
    out: dict[str, str] = {}
    for f in (fields or IOC_FIELDS):
        v = getattr(a, f, "") or ""
        if v:
            out[f] = v
    return out


def _alert_tactics(a: Alert) -> set[str]:
    tactics: set[str] = set()
    for entry in (a.mitre or []):
        if isinstance(entry, dict):
            for t in entry.get("tactics", []):
                tactics.add(t.lower().replace(" ", "-"))
        elif isinstance(entry, str) and entry.startswith("TA"):
            tactics.add(entry)
    return tactics


def correlate_ioc_overlap(
    db: Session,
    rule: CorrelationRule,
    alerts: list[Alert],
) -> list[Incident]:
    cfg = rule.config or {}
    fields: list[str] = cfg.get("fields", list(IOC_FIELDS))
    min_shared: int = cfg.get("min_shared", 2)
    window_minutes: int = cfg.get("window_minutes", 60)

    cutoff = utcnow() - timedelta(minutes=window_minutes)
    recent = [a for a in alerts if a.time and a.time >= cutoff]
    if len(recent) < 2:
        return []

    ioc_to_alerts: dict[tuple[str, str], list[Alert]] = defaultdict(list)
    for a in recent:
        for f, v in _alert_iocs(a, fields).items():
            ioc_to_alerts[(f, v)].append(a)

    # Build groups where alerts share at least min_shared IOC values
    alert_pairs: dict[frozenset[str], dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for (field, val), group in ioc_to_alerts.items():
        if len(group) < 2:
            continue
        for a in group:
            for b in group:
                if a.id < b.id:
                    pair = frozenset([a.id, b.id])
                    alert_pairs[pair][field].add(val)

    # Merge pairs into connected components where each alert pair shares >= min_shared fields
    connected: dict[str, set[str]] = {}
    shared_data: dict[str, dict[str, set[str]]] = defaultdict(lambda: defaultdict(set))
    for pair, fields_map in alert_pairs.items():
        if len(fields_map) >= min_shared:
            ids = list(pair)
            root = None
            for aid in ids:
                if aid in connected:
                    root = aid
                    break
            if root is None:
                root = ids[0]
                connected[root] = set(ids)
            else:
                connected[root].update(ids)
                for aid in ids:
                    if aid != root and aid in connected:
                        connected[root].update(connected.pop(aid))
            for aid in ids:
                connected[aid] = connected[root]
            for f, vals in fields_map.items():
                for v in vals:
                    shared_data[root][f].add(v)

    seen_groups: set[int] = set()
    incidents: list[Incident] = []
    for root, group_ids in connected.items():
        gid = id(group_ids)
        if gid in seen_groups:
            continue
        seen_groups.add(gid)
        if len(group_ids) < 2:
            continue
        group_alerts = [a for a in recent if a.id in group_ids]
        shared = {f: sorted(v) for f, v in shared_data.get(root, {}).items()}
        incidents.append(_build_incident(db, rule, group_alerts, shared))

    return incidents


def correlate_time_window(
    db: Session,
    rule: CorrelationRule,
    alerts: list[Alert],
) -> list[Incident]:
    cfg = rule.config or {}
    window_minutes: int = cfg.get("window_minutes", 15)
    min_alerts: int = cfg.get("min_alerts", 3)
    group_by: list[str] = cfg.get("group_by", ["host", "client_id"])

    cutoff = utcnow() - timedelta(minutes=window_minutes)
    recent = [a for a in alerts if a.time and a.time >= cutoff]

    groups: dict[tuple[str, ...], list[Alert]] = defaultdict(list)
    for a in recent:
        key = tuple(getattr(a, f, "") or "" for f in group_by)
        if all(k == "" for k in key):
            continue
        groups[key].append(a)

    incidents: list[Incident] = []
    for key, group in groups.items():
        if len(group) >= min_alerts:
            shared = {f: [v] for f, v in zip(group_by, key, strict=False) if v}
            incidents.append(_build_incident(db, rule, group, shared))
    return incidents


def correlate_kill_chain(
    db: Session,
    rule: CorrelationRule,
    alerts: list[Alert],
) -> list[Incident]:
    cfg = rule.config or {}
    required_tactics: set[str] = {t.lower().replace(" ", "-") for t in cfg.get("tactics", [])}
    window_minutes: int = cfg.get("window_minutes", 120)
    same_host: bool = cfg.get("same_host", True)

    if not required_tactics:
        return []

    cutoff = utcnow() - timedelta(minutes=window_minutes)
    recent = [a for a in alerts if a.time and a.time >= cutoff]

    if same_host:
        by_host: dict[str, list[Alert]] = defaultdict(list)
        for a in recent:
            if a.host:
                by_host[a.host].append(a)
        groups_iter = by_host.values()
    else:
        groups_iter = [recent]

    incidents: list[Incident] = []
    for group in groups_iter:
        covered: set[str] = set()
        matching: list[Alert] = []
        for a in group:
            tactics = _alert_tactics(a)
            overlap = tactics & required_tactics
            if overlap:
                covered.update(overlap)
                matching.append(a)
        if covered >= required_tactics and len(matching) >= 2:
            shared: dict[str, list[str]] = {"tactics": sorted(covered)}
            if same_host and group:
                shared["host"] = [group[0].host]
            incidents.append(_build_incident(db, rule, matching, shared))
    return incidents


def correlate_threshold(
    db: Session,
    rule: CorrelationRule,
    alerts: list[Alert],
) -> list[Incident]:
    cfg = rule.config or {}
    field: str = cfg.get("field", "rule_id")
    threshold: int = cfg.get("threshold", 10)
    window_minutes: int = cfg.get("window_minutes", 30)
    group_by: list[str] = cfg.get("group_by", ["client_id"])

    cutoff = utcnow() - timedelta(minutes=window_minutes)
    recent = [a for a in alerts if a.time and a.time >= cutoff]

    groups: dict[tuple[str, ...], dict[str, list[Alert]]] = defaultdict(lambda: defaultdict(list))
    for a in recent:
        key = tuple(getattr(a, f, "") or "" for f in group_by)
        val = getattr(a, field, "") or ""
        if val:
            groups[key][val].append(a)

    incidents: list[Incident] = []
    for key, vals in groups.items():
        for val, group in vals.items():
            if len(group) >= threshold:
                shared = {field: [val]}
                shared.update({f: [v] for f, v in zip(group_by, key, strict=False) if v})
                incidents.append(_build_incident(db, rule, group, shared))
    return incidents


STRATEGIES: dict[str, Any] = {
    "ioc_overlap": correlate_ioc_overlap,
    "time_window": correlate_time_window,
    "kill_chain": correlate_kill_chain,
    "threshold": correlate_threshold,
}


def _build_incident(
    db: Session,
    rule: CorrelationRule,
    alerts: list[Alert],
    shared_iocs: dict[str, Any],
) -> Incident:
    alert_ids = sorted({a.id for a in alerts})
    times = [a.time for a in alerts if a.time]
    max_sev = max(alerts, key=lambda a: sev_rank(a.severity)).severity
    boosted = _boost_severity(max_sev, rule.severity_boost)

    # Collect MITRE tactics across all alerts
    all_tactics: set[str] = set()
    for a in alerts:
        all_tactics.update(_alert_tactics(a))

    # Summarize the shared IOCs into a readable name
    ioc_summary = ", ".join(f"{f}={vs[0]}" for f, vs in list(shared_iocs.items())[:3] if vs)
    name = f"[{rule.strategy}] {rule.name}: {ioc_summary}" if ioc_summary else f"[{rule.strategy}] {rule.name}"

    inc = Incident(
        name=name[:300],
        description=f"Auto-correlated by rule '{rule.name}' ({rule.strategy}). {len(alert_ids)} alerts share: {ioc_summary}.",
        severity=boosted,
        rule_id=rule.id,
        rule_name=rule.name,
        strategy=rule.strategy,
        alert_ids=alert_ids,
        shared_iocs={k: list(v) if isinstance(v, set) else v for k, v in shared_iocs.items()},
        kill_chain_stages=sorted(all_tactics),
        alert_count=len(alert_ids),
        first_alert_time=min(times) if times else None,
        last_alert_time=max(times) if times else None,
        client_id=alerts[0].client_id if alerts else None,
    )
    return inc


def run_correlation(db: Session, client_id: str | None = None) -> list[Incident]:
    """Run all enabled rules against recent un-correlated alerts, return new incidents."""
    qy = select(CorrelationRule).where(CorrelationRule.enabled.is_(True))
    if client_id:
        qy = qy.where((CorrelationRule.client_id == client_id) | CorrelationRule.client_id.is_(None))
    rules = list(db.execute(qy).scalars())
    if not rules:
        return []

    # Fetch existing incident alert IDs to avoid duplicates
    existing = db.execute(select(Incident.alert_ids).where(Incident.status.in_(["open", "investigating"]))).scalars().all()
    already_correlated: set[str] = set()
    for ids in existing:
        already_correlated.update(ids or [])

    max_window = max(
        (r.config or {}).get("window_minutes", 120) for r in rules
    )
    cutoff = utcnow() - timedelta(minutes=max_window)
    alerts = list(db.execute(
        select(Alert)
        .where(Alert.time >= cutoff, Alert.status.in_(["new", "acknowledged", "investigating"]))
        .order_by(Alert.time.desc())
        .limit(1000)
    ).scalars())

    # Filter out already-correlated alerts
    alerts = [a for a in alerts if a.id not in already_correlated]
    if not alerts:
        return []

    new_incidents: list[Incident] = []
    for rule in rules:
        fn = STRATEGIES.get(rule.strategy)
        if not fn:
            continue
        incidents = fn(db, rule, alerts)
        for inc in incidents:
            db.add(inc)
            new_incidents.append(inc)

    return new_incidents
