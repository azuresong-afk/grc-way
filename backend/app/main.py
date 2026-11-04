"""Точка входа API «Аттестации»."""

import secrets

from fastapi import FastAPI

from app import __version__
from app.api import (
    audit_log,
    auth,
    bdu,
    classification,
    evidence,
    health,
    manifest,
    measures,
    objects,
    projects,
    refs,
    refs_sync,
    scanner_import,
    summary,
    szi,
    threat_models,
    threat_refs,
    users,
)
from app.core.config import get_settings
from app.core.security import LoginThrottle, TokenSigner


def create_app() -> FastAPI:
    settings = get_settings()
    if not settings.dev_mode and len(settings.secret_key) < 32:
        raise RuntimeError("GRC_SECRET_KEY не задан или короче 32 символов")

    app = FastAPI(
        title="Аттестация API",
        version=__version__,
        # Документация API доступна только в режиме разработки.
        docs_url="/docs" if settings.dev_mode else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.dev_mode else None,
    )
    # В режиме разработки без ключа — случайный: токены живут до перезапуска.
    secret = settings.secret_key or secrets.token_hex(32)
    app.state.signer = TokenSigner(secret, settings.token_ttl_minutes * 60)
    app.state.throttle = LoginThrottle(settings.login_max_failures, settings.login_lockout_seconds)

    for module in (
        health,
        manifest,
        auth,
        users,
        audit_log,
        projects,
        objects,
        classification,
        measures,
        refs,
        threat_refs,
        bdu,
        szi,
        threat_models,
        refs_sync,
        scanner_import,
        evidence,
        summary,
    ):
        app.include_router(module.router)
    return app
