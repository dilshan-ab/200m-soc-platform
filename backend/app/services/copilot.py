"""AI Analyst Copilot: alert analysis, triage suggestions, case summaries, response recommendations."""
from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import get_settings
from ..models import Alert, Case, CaseObservable, utcnow

log = logging.getLogger(__name__)


class CopilotError(Exception):
    pass


def _call_llm(system_prompt: str, user_prompt: str) -> str:
    """Call the configured LLM provider and return the text response."""
    cfg = get_settings()
    if cfg.llm_provider == "none" or not cfg.llm_api_key:
        raise CopilotError("AI copilot not configured. Set SOC_LLM_PROVIDER and SOC_LLM_API_KEY.")

    if cfg.llm_provider == "anthropic":
        return _call_anthropic(cfg, system_prompt, user_prompt)
    elif cfg.llm_provider == "openai":
        return _call_openai(cfg, system_prompt, user_prompt)
    raise CopilotError(f"Unknown LLM provider: {cfg.llm_provider}")


def _call_anthropic(cfg: Any, system_prompt: str, user_prompt: str) -> str:
    import httpx

    resp = httpx.post(
        "https://api.anthropic.com/v1/messages",
        headers={"x-api-key": cfg.llm_api_key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
        json={"model": cfg.llm_model, "max_tokens": cfg.llm_max_tokens, "temperature": cfg.llm_temperature,
              "system": system_prompt, "messages": [{"role": "user", "content": user_prompt}]},
        timeout=60,
    )
    if resp.status_code != 200:
        raise CopilotError(f"Anthropic API error {resp.status_code}: {resp.text[:300]}")
    data = resp.json()
    return data.get("content", [{}])[0].get("text", "")


def _call_openai(cfg: Any, system_prompt: str, user_prompt: str) -> str:
    import httpx

    resp = httpx.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {cfg.llm_api_key}", "Content-Type": "application/json"},
        json={"model": cfg.llm_model, "max_tokens": cfg.llm_max_tokens, "temperature": cfg.llm_temperature,
              "messages": [{"role": "system", "content": system_prompt}, {"role": "user", "content": user_prompt}]},
        timeout=60,
    )
    if resp.status_code != 200:
        raise CopilotError(f"OpenAI API error {resp.status_code}: {resp.text[:300]}")
    data = resp.json()
    return data.get("choices", [{}])[0].get("message", {}).get("content", "")


SYSTEM_PROMPT = """You are a SOC Analyst AI Copilot integrated into a Security Operations Center platform.
Your role is to help analysts investigate security alerts and incidents more efficiently.

When analyzing alerts, provide:
1. A concise assessment of the threat level and what the alert indicates
2. Potential attack techniques and tactics (reference MITRE ATT&CK where applicable)
3. Specific investigation steps the analyst should take
4. Recommended response actions
5. Whether this is likely a true positive, false positive, or needs more investigation

Be precise, actionable, and reference specific IOCs (IPs, hashes, domains) from the alert data.
Format your response in clear sections with markdown headers."""


def analyze_alert(db: Session, alert_id: str) -> dict[str, Any]:
    """Analyze a single alert and return AI-generated insights."""
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise CopilotError("Alert not found")

    context = _build_alert_context(alert)
    prompt = f"""Analyze this security alert and provide your assessment:

{context}

Provide:
1. **Threat Assessment**: What does this alert indicate? How serious is it?
2. **MITRE ATT&CK**: What techniques/tactics might be involved?
3. **Investigation Steps**: What should the analyst check next?
4. **Recommended Actions**: What response actions should be taken?
5. **Verdict**: True positive, false positive, or needs investigation?"""

    response = _call_llm(SYSTEM_PROMPT, prompt)
    return {"alert_id": alert_id, "analysis": response, "model": get_settings().llm_model, "generated_at": utcnow().isoformat()}


def triage_alert(db: Session, alert_id: str) -> dict[str, Any]:
    """Quick triage: severity assessment, priority, and recommended status."""
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise CopilotError("Alert not found")

    context = _build_alert_context(alert)
    prompt = f"""Quickly triage this security alert. Respond ONLY in valid JSON with these fields:
- "severity_suggestion": one of "info", "low", "medium", "high", "critical"
- "priority": 1-5 (1=highest)
- "verdict": one of "true_positive", "false_positive", "needs_investigation"
- "confidence": 0.0-1.0
- "summary": one sentence summary
- "recommended_status": one of "new", "acknowledged", "investigating", "resolved", "false_positive"
- "reasoning": brief explanation

Alert data:
{context}"""

    triage_system = "You are a SOC triage AI. Respond ONLY in valid JSON. No markdown, no explanation outside the JSON."
    response = _call_llm(triage_system, prompt)
    try:
        parsed = json.loads(response.strip().removeprefix("```json").removesuffix("```").strip())
    except json.JSONDecodeError:
        parsed = {"summary": response[:500], "confidence": 0.0, "verdict": "needs_investigation"}
    parsed["alert_id"] = alert_id
    parsed["generated_at"] = utcnow().isoformat()
    return parsed


def summarize_case(db: Session, case_id: str) -> dict[str, Any]:
    """Generate an executive summary of a case."""
    case = db.get(Case, case_id)
    if case is None:
        raise CopilotError("Case not found")

    alerts = db.execute(select(Alert).where(Alert.case_id == case_id).limit(20)).scalars().all()
    observables = db.execute(select(CaseObservable).where(CaseObservable.case_id == case_id)).scalars().all()

    context = f"""Case #{case.number}: {case.title}
Severity: {case.severity} | Status: {case.status} | TLP: {case.tlp}
Description: {case.description[:2000]}

Timeline ({len(case.timeline)} events):
{chr(10).join(f'- [{e.kind}] {e.actor}: {e.message[:200]}' for e in (case.timeline or [])[-15:])}

Observables ({len(observables)}):
{chr(10).join(f'- {o.type}: {o.value} (verdict: {o.verdict})' for o in observables)}

Linked Alerts ({len(alerts)}):
{chr(10).join(f'- [{a.severity}] {a.title[:150]} (rule: {a.rule_id}, host: {a.host}, src: {a.src_ip})' for a in alerts[:10])}

Tasks: {', '.join(f'{t.title} ({t.status})' for t in (case.tasks or []))}"""

    prompt = f"""Summarize this security investigation case for an executive audience:

{context}

Provide:
1. **Executive Summary**: 2-3 sentence overview
2. **Key Findings**: The most important discoveries
3. **Impact Assessment**: What was affected and potential business impact
4. **Current Status**: Where the investigation stands
5. **Recommended Next Steps**: Priority actions"""

    response = _call_llm(SYSTEM_PROMPT, prompt)
    return {"case_id": case_id, "summary": response, "model": get_settings().llm_model, "generated_at": utcnow().isoformat()}


def suggest_response(db: Session, alert_id: str) -> dict[str, Any]:
    """Suggest specific incident response actions for an alert."""
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise CopilotError("Alert not found")

    context = _build_alert_context(alert)
    prompt = f"""Based on this security alert, suggest specific incident response actions.

{context}

Respond ONLY in valid JSON with a "actions" array, each action having:
- "action": the action to take (e.g., "block_ip", "isolate_host", "disable_account", "collect_logs", "escalate")
- "target": the specific target (IP, hostname, username, etc.)
- "priority": "immediate", "urgent", "standard"
- "reason": why this action is recommended
- "automated": true if this can be automated, false if manual review needed"""

    resp_system = "You are a SOC response advisor. Respond ONLY in valid JSON. No markdown outside JSON."
    response = _call_llm(resp_system, prompt)
    try:
        parsed = json.loads(response.strip().removeprefix("```json").removesuffix("```").strip())
    except json.JSONDecodeError:
        parsed = {"actions": [], "raw": response[:500]}
    parsed["alert_id"] = alert_id
    parsed["generated_at"] = utcnow().isoformat()
    return parsed


def explain_alert(db: Session, alert_id: str) -> dict[str, Any]:
    """Explain an alert in plain language for junior analysts."""
    alert = db.get(Alert, alert_id)
    if alert is None:
        raise CopilotError("Alert not found")

    context = _build_alert_context(alert)
    prompt = f"""Explain this security alert in plain language suitable for a junior SOC analyst who is still learning.

{context}

Cover:
1. What happened in simple terms
2. Why this matters from a security perspective
3. What the analyst should look for to determine if this is a real attack
4. Common false positive scenarios for this type of alert
5. Key terms or concepts the analyst should understand"""

    response = _call_llm(SYSTEM_PROMPT, prompt)
    return {"alert_id": alert_id, "explanation": response, "model": get_settings().llm_model, "generated_at": utcnow().isoformat()}


def _build_alert_context(alert: Alert) -> str:
    """Build a structured context string from an alert for LLM consumption."""
    enrichment_summary = ""
    if alert.enrichment:
        for indicator, data in alert.enrichment.items():
            if isinstance(data, dict):
                verdict = data.get("verdict", "unknown")
                sources = data.get("sources", [])
                enrichment_summary += f"\n  {indicator}: verdict={verdict}, sources={', '.join(sources)}"

    return f"""Title: {alert.title}
Severity: {alert.severity}
Status: {alert.status}
Source: {alert.source}
Rule ID: {alert.rule_id}
Category: {alert.category}
Time: {alert.time.isoformat() if alert.time else 'unknown'}
Host: {alert.host}
Source IP: {alert.src_ip}
Destination IP: {alert.dst_ip}
Username: {alert.username}
File Hash: {alert.file_hash}
MITRE Techniques: {', '.join(alert.mitre or [])}
Description: {alert.description[:3000]}
Alert Count (dedup): {alert.count}
Enrichment: {enrichment_summary or 'none'}
Raw Data (excerpt): {json.dumps(alert.raw, default=str)[:2000] if alert.raw else 'none'}"""
