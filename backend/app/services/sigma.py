"""Sigma rule import: parse https://github.com/SigmaHQ/sigma YAML into structured fields.

This does not convert rules into a query against any particular log engine — the platform has
no log-indexing engine of its own (see README "known limits"). What it does do: catalogue rules,
extract their MITRE ATT&CK technique tags, and surface detection coverage per technique alongside
the alerts the platform already has (see app/api/mitre.py for the alert side of that view).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

import yaml

STATUSES = {"stable", "test", "experimental", "deprecated", "unsupported"}
LEVELS = {"informational", "low", "medium", "high", "critical"}
_TECH_TAG = re.compile(r"attack\.t(\d{4}(?:\.\d{3})?)", re.IGNORECASE)


@dataclass
class ParsedRule:
    sigma_id: str
    title: str
    description: str
    status: str
    level: str
    log_source: dict[str, Any]
    technique_ids: list[str]
    tags: list[str]
    references: list[str]
    false_positives: list[str]
    raw_yaml: str


@dataclass
class ImportResult:
    parsed: list[ParsedRule] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # human-readable reasons


def _as_str_list(v: Any) -> list[str]:
    if v is None:
        return []
    if isinstance(v, str):
        return [v]
    if isinstance(v, list):
        return [str(x) for x in v]
    return [str(v)]


def _technique_ids(tags: list[str]) -> list[str]:
    out: list[str] = []
    for t in tags:
        m = _TECH_TAG.search(t)
        if m:
            out.append(f"T{m.group(1).upper()}")
    return sorted(set(out))


def parse_document(doc: dict[str, Any], raw_yaml: str) -> ParsedRule:
    title = str(doc.get("title", "")).strip()
    if not title:
        raise ValueError("missing required field 'title'")
    status = str(doc.get("status", "experimental")).lower()
    if status not in STATUSES:
        status = "experimental"
    level = str(doc.get("level", "medium")).lower()
    if level not in LEVELS:
        level = "medium"
    logsource = doc.get("logsource") or {}
    if not isinstance(logsource, dict):
        logsource = {}
    tags = _as_str_list(doc.get("tags"))
    return ParsedRule(
        sigma_id=str(doc.get("id", "")),
        title=title[:300],
        description=str(doc.get("description", ""))[:4000],
        status=status,
        level=level,
        log_source={k: v for k, v in logsource.items() if k in ("product", "service", "category", "definition")},
        technique_ids=_technique_ids(tags),
        tags=tags,
        references=_as_str_list(doc.get("references")),
        false_positives=_as_str_list(doc.get("falsepositives")),
        raw_yaml=raw_yaml,
    )


def parse_yaml(text: str) -> ImportResult:
    """Parse one or more Sigma rules from a YAML string (supports `---`-separated multi-document files)."""
    result = ImportResult()
    try:
        docs = list(yaml.safe_load_all(text))
    except yaml.YAMLError as e:
        result.skipped.append(f"invalid YAML: {e}")
        return result
    if len(docs) <= 1:
        # A single-document file still gets the original text verbatim as its raw_yaml.
        for doc in docs:
            if not isinstance(doc, dict):
                continue
            try:
                result.parsed.append(parse_document(doc, text))
            except ValueError as e:
                result.skipped.append(f"{doc.get('title', '(untitled)')}: {e}")
        return result
    for doc in docs:
        if not isinstance(doc, dict) or doc.get("action") == "global":
            continue  # Sigma collections may ship a shared "action: global" backreference document
        try:
            result.parsed.append(parse_document(doc, yaml.safe_dump(doc, sort_keys=False)))
        except ValueError as e:
            result.skipped.append(f"{doc.get('title', '(untitled)')}: {e}")
    return result
