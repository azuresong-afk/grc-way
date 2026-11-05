"""Точка входа API «Аттестации»."""

import secrets
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from sqlalchemy.orm import sessionmaker

from app import __version__, platform_events
from app.api import (
    audit_log,
    auth,
    bdu,
    classification,
    documents,
    evidence,
    health,
    manifest,
    measures,
    nonconformities,
    object_vulns,
    objects,
    platform,
    projects,
    ref_documents,
    refs,
    refs_sync,
    scanner_import,
    summary,
    szi,
    threat_models,
    threat_refs,
    users,
    vuln_criticality,
    vuln_inventory,
)
from app.core.config import get_settings
from app.core.security import LoginThrottle, TokenSigner
from app.db.session import get_engine
from app.integrations.platform.tokens import JwksCache
from app.request_ctx import request_method


def create_app() -> FastAPI:
    settings = get_settings()
    if not settings.dev_mode and len(settings.secret_key) < 32:
        raise RuntimeError("GRC_SECRET_KEY не задан или короче 32 символов")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        # Доставка outbox «Платформе» (задача 3.5): только когда заданы адрес и секрет.
        worker = None
        if settings.outbox_enabled and settings.outbox_worker:
            factory = sessionmaker(bind=get_engine(), expire_on_commit=False)
            worker = platform_events.OutboxWorker(factory, settings.outbox_poll_seconds)
            worker.start()
        app.state.outbox_worker = worker
        yield
        if worker is not None:
            worker.stop()

    app = FastAPI(
        lifespan=lifespan,
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
    # Режим platform: открытые ключи платформы (кэш 10 мин, перечитывание по неизвестному kid).
    app.state.jwks = JwksCache(settings.jwks_url, timeout=settings.platform_timeout_seconds)

    @app.middleware("http")
    async def remember_method(request: Request, call_next):  # type: ignore[no-untyped-def]
        # Общие проверки (архивный проект платформы — только чтение) знают, меняет ли запрос данные.
        token = request_method.set(request.method)
        try:
            return await call_next(request)
        finally:
            request_method.reset(token)

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
        vuln_criticality,
        vuln_inventory,
        object_vulns,
        ref_documents,
        bdu,
        szi,
        threat_models,
        refs_sync,
        scanner_import,
        evidence,
        documents,
        nonconformities,
        summary,
        platform,
    ):
        app.include_router(module.router)
    return app
