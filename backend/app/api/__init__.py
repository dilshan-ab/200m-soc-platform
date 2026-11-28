from __future__ import annotations

from fastapi import FastAPI


def register_routers(app: FastAPI) -> None:
    from . import (
        admin,
        alerts,
        analysts,
        approvals,
        assets,
        auth,
        cases,
        clients,
        copilot,
        correlation,
        enrichment_engine,
        evidence,
        handoff,
        integrations,
        intel,
        log_search,
        mitre,
        notebooks,
        ops,
        platform,
        playbooks,
        response,
        scheduled_jobs,
        sigma,
        simulation,
        soar_metrics,
        taxii,
        threat_intel,
        threatmap,
        ueba,
        uptime,
        vulns,
        warroom,
        webhooks,
    )

    for m in (auth, alerts, cases, response, approvals, assets, vulns, intel, integrations, webhooks, admin, ops, platform, threatmap, mitre, analysts, sigma,
              playbooks, correlation, ueba, copilot, simulation, notebooks, threat_intel, taxii, handoff, warroom, clients, soar_metrics, enrichment_engine, log_search, evidence, scheduled_jobs, uptime):
        app.include_router(m.router)
