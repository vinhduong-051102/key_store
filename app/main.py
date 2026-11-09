from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from . import api, api_access, dashboard
from .config import get_settings
from .db import init_db


def create_app() -> FastAPI:
    settings = get_settings()
    init_db()

    app = FastAPI(title="KeyVault", version="1.0.0", docs_url="/api/docs", redoc_url=None,
                  openapi_url="/api/openapi.json")
    app.add_middleware(SessionMiddleware, secret_key=settings.session_secret, session_cookie="kv_session",
                       max_age=settings.session_max_age, same_site="strict", https_only=settings.cookie_secure)

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        h = response.headers
        h["X-Content-Type-Options"] = "nosniff"
        h["X-Frame-Options"] = "DENY"
        h["Referrer-Policy"] = "no-referrer"
        if not request.url.path.startswith("/api/docs"):
            h["Content-Security-Policy"] = ("default-src 'self'; img-src 'self' data:; style-src 'self'; "
                                            "script-src 'self'; frame-ancestors 'none'; form-action 'self'")
        if request.url.path.startswith(("/dashboard", "/api/v1")):
            h["Cache-Control"] = "no-store"
        return response

    app.mount("/static", StaticFiles(directory=str(Path(__file__).parent / "static")), name="static")
    app.include_router(api.router)
    app.include_router(api_access.router)
    app.include_router(dashboard.router)

    @app.exception_handler(dashboard.NotAuthenticated)
    async def _not_auth(request: Request, exc: dashboard.NotAuthenticated):
        return RedirectResponse("/dashboard/login", status_code=303)

    @app.get("/", include_in_schema=False)
    def root():
        return RedirectResponse("/dashboard", status_code=303)

    @app.get("/healthz", include_in_schema=False)
    def healthz():
        return {"status": "ok"}

    return app


app = create_app()
