"""FastAPI application factory."""
from __future__ import annotations

import logging
import uuid
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from .config import get_settings
from .db import create_all

log = logging.getLogger("soc")

SECURITY_HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
}


def create_app() -> FastAPI:
    s = get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI):  # noqa: ANN202
        if s.environment != "production":
            create_all()  # production uses Alembic migrations
        from .db import session_scope
        from .policy import set_role_overrides
        from .services.settings_svc import get_setting as _gs
        with session_scope() as db:
            overrides = _gs(db, "role_permissions")
            if overrides:
                set_role_overrides(overrides)
        from .services.geoip import init as geoip_init
        geoip_init()
        from .workers.runner import start_workers, stop_workers

        start_workers(app)
        yield
        stop_workers(app)

    app = FastAPI(
        title="SOC Operations Platform API", version="1.0.0", lifespan=lifespan,
        docs_url=None if s.environment == "production" else "/api/docs",
        redoc_url=None, openapi_url=None if s.environment == "production" else "/api/openapi.json",
    )
    app.add_middleware(
        CORSMiddleware, allow_origins=s.allowed_origins, allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"], allow_headers=["Content-Type", "X-CSRF-Token", "Authorization"],
    )

    @app.middleware("http")
    async def hardening(request: Request, call_next):  # noqa: ANN202
        request.state.correlation_id = request.headers.get("x-request-id", "")[:64] or uuid.uuid4().hex
        try:
            resp = await call_next(request)
        except Exception:  # pragma: no cover - last-resort handler
            log.exception("unhandled error cid=%s", request.state.correlation_id)
            resp = JSONResponse({"detail": "internal error", "correlation_id": request.state.correlation_id}, status_code=500)
        for k, v in SECURITY_HEADERS.items():
            if request.url.path.startswith("/api/docs") and k == "Content-Security-Policy":
                continue
            resp.headers.setdefault(k, v)
        if s.cookie_secure:
            resp.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
        resp.headers["X-Request-ID"] = request.state.correlation_id
        return resp

    from .api import register_routers

    register_routers(app)

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> dict:
        return {"status": "ok"}

    return app
