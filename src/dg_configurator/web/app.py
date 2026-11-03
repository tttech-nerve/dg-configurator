# SPDX-License-Identifier: MIT
# Copyright (c) 2026 TTTech Industrial Automation AG
"""FastAPI application factory for dg-configurator's web UI."""

import importlib.resources
from dataclasses import dataclass, field

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .api import router
from .security import BodySizeLimitMiddleware, SecurityHeadersMiddleware

_DEFAULT_MAX_UPLOAD_BYTES = 50 * 1024 * 1024


@dataclass
class ServerSettings:
    """Runtime settings for the web server."""

    host: str = "127.0.0.1"
    port: int = 8080
    allowed_hosts: list[str] = field(default_factory=lambda: ["localhost", "127.0.0.1"])
    max_upload_bytes: int = _DEFAULT_MAX_UPLOAD_BYTES


def create_app(settings: ServerSettings | None = None) -> FastAPI:
    """Build the FastAPI app: API routes, static SPA, health check, and security middleware."""
    settings = settings or ServerSettings()
    app = FastAPI(title="dg-configurator", docs_url=None, redoc_url=None, openapi_url="/api/openapi.json")
    app.state.settings = settings

    # the last middleware added is the outermost one, so every response (also 400/413) gets the security headers
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_upload_bytes)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
    app.add_middleware(SecurityHeadersMiddleware)

    app.include_router(router, prefix="/api")

    @app.exception_handler(RequestValidationError)
    async def validation_error_handler(_request: Request, exc: RequestValidationError) -> JSONResponse:
        # the default 422 body echoes the offending input, which may be a passphrase
        detail = [{"loc": list(error["loc"]), "msg": error["msg"], "type": error["type"]} for error in exc.errors()]
        return JSONResponse(status_code=422, content={"detail": detail})

    @app.get("/healthz")
    def healthz() -> dict[str, str]:
        return {"status": "ok"}

    static_dir = importlib.resources.files("dg_configurator.web") / "static"
    app.mount("/", StaticFiles(directory=str(static_dir), html=True), name="static")
    return app
