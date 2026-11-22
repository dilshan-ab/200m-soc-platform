"""Custom enrichment engine: local IOC lookup, rule matching, reputation scoring, auto-learning."""
from __future__ import annotations

import fnmatch
import ipaddress
import re
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    CaseObservable,
    EnrichmentRule,
    ThreatIndicator,
    utcnow,
)

VERDICT_WEIGHT = {"unknown": 0, "benign": -1, "suspicious": 1, "malicious": 2}


def local_lookup(db: Session, indicator: str, itype: str) -> dict[str, Any]:
    """Check the local ThreatIndicator database for a match."""
    row = db.execute(
        select(ThreatIndicator).where(
            ThreatIndicator.type == itype,
            ThreatIndicator.value == indicator,
            ThreatIndicator.revoked.is_(False),
        )
    ).scalars().first()
    if row is None:
        return {"matched": False, "verdict": "unknown"}
    row.sightings += 1
    row.last_seen = utcnow()
    return {
        "matched": True,
        "verdict": row.verdict,
        "confidence": row.confidence,
        "labels": row.labels,
        "source": row.source,
        "sightings": row.sightings,
        "first_seen": row.first_seen.isoformat() if row.first_seen else None,
        "last_seen": row.last_seen.isoformat() if row.last_seen else None,
        "stix_id": row.stix_id,
    }


def _match_cidr(indicator: str, pattern: str) -> bool:
    try:
        addr = ipaddress.ip_address(indicator)
    except ValueError:
        return False
    for cidr in pattern.split(","):
        cidr = cidr.strip()
        if not cidr:
            continue
        try:
            if addr in ipaddress.ip_network(cidr, strict=False):
                return True
        except ValueError:
            continue
    return False


def _match_domain_pattern(indicator: str, pattern: str) -> bool:
    indicator_lower = indicator.lower()
    for pat in pattern.split(","):
        pat = pat.strip().lower()
        if not pat:
            continue
        if fnmatch.fnmatch(indicator_lower, pat):
            return True
    return False


def _match_hash_list(indicator: str, pattern: str) -> bool:
    indicator_lower = indicator.lower()
    return indicator_lower in {h.strip().lower() for h in pattern.split(",") if h.strip()}


def _match_regex(indicator: str, pattern: str) -> bool:
    try:
        return bool(re.search(pattern, indicator, re.IGNORECASE))
    except re.error:
        return False


_MATCHERS = {
    "cidr": _match_cidr,
    "domain_pattern": _match_domain_pattern,
    "hash_list": _match_hash_list,
    "regex": _match_regex,
}


def rule_match(db: Session, indicator: str, itype: str) -> list[dict[str, Any]]:
    """Evaluate all enabled enrichment rules against an indicator."""
    rules = db.execute(
        select(EnrichmentRule).where(
            EnrichmentRule.enabled.is_(True),
            EnrichmentRule.indicator_type.in_([itype, "any"]),
        )
    ).scalars().all()
    hits: list[dict[str, Any]] = []
    for rule in rules:
        matcher = _MATCHERS.get(rule.rule_type)
        if matcher and matcher(indicator, rule.pattern):
            rule.hit_count += 1
            rule.last_hit_at = utcnow()
            hits.append({
                "rule_id": rule.id,
                "rule_name": rule.name,
                "verdict": rule.verdict,
                "confidence": rule.confidence,
                "tags": rule.tags,
            })
    return hits


def compute_reputation(
    local_result: dict[str, Any],
    rule_hits: list[dict[str, Any]],
    external_results: dict[str, Any],
) -> dict[str, Any]:
    """Aggregate verdicts from all sources into a reputation score (0-100)."""
    verdicts: list[tuple[str, int]] = []

    if local_result.get("matched"):
        verdicts.append((local_result["verdict"], local_result.get("confidence", 50)))

    for hit in rule_hits:
        verdicts.append((hit["verdict"], hit["confidence"]))

    for data in external_results.values():
        if isinstance(data, dict) and not data.get("error"):
            v = data.get("verdict", "unknown")
            confidence = 60
            if "abuse_score" in data:
                confidence = min(100, data["abuse_score"])
            elif "stats" in data:
                stats = data["stats"]
                total = sum(stats.values()) if isinstance(stats, dict) else 1
                if total > 0 and isinstance(stats, dict):
                    confidence = min(100, int((stats.get("malicious", 0) / total) * 100))
            elif "pulse_count" in data:
                confidence = min(100, data["pulse_count"] * 10)
            elif "matches" in data:
                confidence = min(100, data["matches"] * 20)
            verdicts.append((v, confidence))

    if not verdicts:
        return {"score": 0, "verdict": "unknown", "confidence": 0, "sources": 0}

    total_weight = 0
    weighted_score = 0.0
    for v, conf in verdicts:
        w = VERDICT_WEIGHT.get(v, 0)
        total_weight += conf
        weighted_score += w * conf

    if total_weight == 0:
        score = 0
    else:
        raw = weighted_score / total_weight
        score = int(max(0, min(100, (raw + 1) * 50)))

    max_verdict = "unknown"
    max_w = -2
    for v, _ in verdicts:
        w = VERDICT_WEIGHT.get(v, 0)
        if w > max_w:
            max_w = w
            max_verdict = v

    avg_confidence = int(total_weight / len(verdicts))

    return {
        "score": score,
        "verdict": max_verdict,
        "confidence": avg_confidence,
        "sources": len(verdicts),
    }


def enrich_local(db: Session, indicator: str, itype: str) -> dict[str, Any]:
    """Full local enrichment: DB lookup + rule matching + reputation stub."""
    local = local_lookup(db, indicator, itype)
    rules = rule_match(db, indicator, itype)
    return {
        "local_intel": local,
        "rule_matches": rules,
        "tags": list({t for hit in rules for t in hit.get("tags", [])}),
    }


def learn_from_case(db: Session, case_id: str, verdict: str, actor_id: str) -> int:
    """Auto-create/update ThreatIndicators from confirmed case observables."""
    if verdict not in ("true_positive", "false_positive"):
        return 0
    ioc_verdict = "malicious" if verdict == "true_positive" else "benign"
    observables = db.execute(
        select(CaseObservable).where(CaseObservable.case_id == case_id)
    ).scalars().all()
    updated = 0
    for obs in observables:
        if obs.type not in ("ip", "domain", "hash", "url", "email"):
            continue
        existing = db.execute(
            select(ThreatIndicator).where(
                ThreatIndicator.type == obs.type,
                ThreatIndicator.value == obs.value,
            )
        ).scalars().first()
        if existing:
            existing.verdict = ioc_verdict
            existing.confidence = max(existing.confidence, 80)
            existing.sightings += 1
            existing.last_seen = utcnow()
        else:
            ind = ThreatIndicator(
                type=obs.type,
                value=obs.value,
                verdict=ioc_verdict,
                confidence=80,
                source=f"case:{case_id}",
                labels=["auto-learned"],
                created_by=actor_id,
            )
            db.add(ind)
        obs.verdict = ioc_verdict
        updated += 1
    return updated


def bulk_lookup(db: Session, indicators: list[dict[str, str]]) -> list[dict[str, Any]]:
    """Quick reputation check for multiple indicators against local DB only."""
    results = []
    for item in indicators[:100]:
        value = item.get("value", "").strip()
        itype = item.get("type", "")
        if not value or not itype:
            continue
        local = local_lookup(db, value, itype)
        rules = rule_match(db, value, itype)
        rep = compute_reputation(local, rules, {})
        results.append({
            "indicator": value,
            "type": itype,
            "reputation": rep,
            "local_match": local.get("matched", False),
            "rule_hits": len(rules),
        })
    return results
