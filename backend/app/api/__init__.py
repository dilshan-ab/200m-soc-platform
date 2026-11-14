from __future__ import annotations

from fastapi import FastAPI


def register_routers(app: FastAPI) -> None:
    from . import admin, alerts, analysts, approvals, assets, auth, cases, correlation, integrations, intel, mitre, ops, playbooks, platform, response, sigma, threatmap, vulns, webhooks

    for m in (auth, alerts, cases, response, approvals, assets, vulns, intel, integrations, webhooks, admin, ops, platform, threatmap, mitre, analysts, sigma, playbooks, correlation):
        app.include_router(m.router)
