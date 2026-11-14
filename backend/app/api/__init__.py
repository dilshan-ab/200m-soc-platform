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
        handoff,
        integrations,
        intel,
        mitre,
        notebooks,
        ops,
        platform,
        playbooks,
        response,
        sigma,
        simulation,
        taxii,
        threat_intel,
        threatmap,
        ueba,
        vulns,
        warroom,
        webhooks,
    )

    for m in (auth, alerts, cases, response, approvals, assets, vulns, intel, integrations, webhooks, admin, ops, platform, threatmap, mitre, analysts, sigma,
              playbooks, correlation, ueba, copilot, simulation, notebooks, threat_intel, taxii, handoff, warroom, clients):
        app.include_router(m.router)
