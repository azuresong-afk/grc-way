"""Точка входа API «Аттестации»."""

from fastapi import FastAPI

from app import __version__
from app.api import health, manifest
from app.core.config import get_settings


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
    app.include_router(health.router)
    app.include_router(manifest.router)
    return app
