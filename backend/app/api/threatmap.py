"""Threat map API – geo-aggregated alert source IPs."""
from __future__ import annotations

from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import case, func, select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import Principal, require
from ..models import Alert, utcnow
from ..services import geoip

router = APIRouter(prefix="/api/threat-map", tags=["threat-map"])

SOC_LOCATION = {"lat": 6.9271, "lng": 79.8612, "label": "SOC HQ – Colombo"}
SEVERITIES = ("info", "low", "medium", "high", "critical")
SEVERITY_RANK = {severity: rank for rank, severity in enumerate(SEVERITIES)}


@router.get("")
def threat_map_data(
    p: Principal = Depends(require("alerts.read")),
    db: Session = Depends(get_db),
    days: int = Query(default=7, ge=1, le=90),
) -> dict[str, Any]:
    cutoff = utcnow() - timedelta(days=days)

    rows = (
        db.execute(
            select(
                Alert.src_ip,
                func.count().label("cnt"),
                func.max(case(SEVERITY_RANK, value=Alert.severity, else_=0)).label("max_sev_rank"),
                func.max(Alert.time).label("last_seen"),
            )
            .where(p.scope(Alert.client_id))
            .where(Alert.time >= cutoff)
            .where(Alert.src_ip != "")
            .group_by(Alert.src_ip)
            .order_by(func.count().desc())
            .limit(500)
        )
        .all()
    )

    geo_cache: dict[str, dict | None] = {}
    arcs: list[dict[str, Any]] = []
    by_country: dict[str, dict[str, Any]] = {}

    for src_ip, cnt, max_sev_rank, last_seen in rows:
        max_sev = SEVERITIES[max_sev_rank]
        if src_ip not in geo_cache:
            geo_cache[src_ip] = geoip.lookup(src_ip)
        geo = geo_cache[src_ip]
        if geo is None:
            continue

        arcs.append({
            "srcLat": geo["lat"],
            "srcLng": geo["lng"],
            "dstLat": SOC_LOCATION["lat"],
            "dstLng": SOC_LOCATION["lng"],
            "severity": max_sev,
            "count": cnt,
            "ip": src_ip,
            "country": geo["country"],
            "country_name": geo["country_name"],
            "city": geo["city"],
            "last_seen": last_seen.isoformat() + "Z" if last_seen else None,
        })

        cc = geo["country"]
        if cc not in by_country:
            by_country[cc] = {
                "country": cc,
                "country_name": geo["country_name"],
                "lat": geo["lat"],
                "lng": geo["lng"],
                "count": 0,
                "max_severity": "info",
                "ips": [],
            }
        by_country[cc]["count"] += cnt
        if max_sev_rank > SEVERITY_RANK[by_country[cc]["max_severity"]]:
            by_country[cc]["max_severity"] = max_sev
        if len(by_country[cc]["ips"]) < 5:
            by_country[cc]["ips"].append(src_ip)

    total_threats = sum(a["count"] for a in arcs)
    countries_sorted = sorted(by_country.values(), key=lambda c: c["count"], reverse=True)

    return {
        "soc": SOC_LOCATION,
        "arcs": arcs,
        "countries": countries_sorted,
        "total_threats": total_threats,
        "unique_sources": len(arcs),
        "unique_countries": len(by_country),
        "days": days,
    }
