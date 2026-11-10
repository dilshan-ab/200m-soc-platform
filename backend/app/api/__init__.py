from __future__ import annotations

from fastapi import FastAPI


def register_routers(app: FastAPI) -> None:
    from . import admin, alerts, analysts, approvals, assets, auth, cases, integrations, intel, mitre, ops, platform, response, sigma, threatmap, vulns, webhooks

    for m in (auth, alerts, cases, response, approvals, assets, vulns, intel, integrations, webhooks, admin, ops, platform, threatmap, mitre, analysts, sigma):
        app.include_router(m.router)
