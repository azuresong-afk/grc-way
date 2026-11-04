import os
from collections.abc import Iterator

import pytest

# Юнит-тесты работают на SQLite в режиме разработки; PostgreSQL — в docker compose и CI.
os.environ.setdefault("GRC_DEV_MODE", "1")
os.environ.setdefault("GRC_DATABASE_URL", "sqlite+pysqlite:///:memory:")

from pathlib import Path

from alembic import command
from alembic.config import Config
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

BACKEND = Path(__file__).resolve().parents[1]
PASSWORD = "correct-horse-battery"  # noqa: S105 — тестовый пароль


def _reset_caches() -> None:
    from app.core.config import get_settings
    from app.db.session import get_engine

    get_settings.cache_clear()
    get_engine.cache_clear()


@pytest.fixture
def db_url(tmp_path, monkeypatch) -> Iterator[str]:
    url = f"sqlite+pysqlite:///{tmp_path / 'test.db'}"
    monkeypatch.setenv("GRC_DATABASE_URL", url)
    monkeypatch.setenv("GRC_SECRET_KEY", "t" * 40)
    _reset_caches()
    cfg = Config(str(BACKEND / "alembic.ini"))
    cfg.set_main_option("script_location", str(BACKEND / "alembic"))
    cfg.set_main_option("sqlalchemy.url", url)
    command.upgrade(cfg, "head")
    yield url
    _reset_caches()


@pytest.fixture
def session(db_url) -> Iterator[Session]:
    from app.db.session import get_engine

    with Session(get_engine()) as s:
        yield s


@pytest.fixture
def client(db_url) -> TestClient:
    from app.main import create_app

    return TestClient(create_app())


@pytest.fixture
def make_user(session):
    from app.core.security import hash_password
    from app.db.models import User

    def make(username: str, *roles: str, display_name: str | None = None) -> User:
        u = User(
            username=username,
            display_name=display_name or username.title(),
            password_hash=hash_password(PASSWORD),
        )
        u.set_roles(set(roles))
        session.add(u)
        session.commit()
        return u

    return make


@pytest.fixture
def login(client):
    def do(username: str, password: str = PASSWORD) -> dict[str, str]:
        r = client.post("/auth/token", json={"username": username, "password": password})
        assert r.status_code == 200, r.text
        return {"Authorization": f"Bearer {r.json()['access_token']}"}

    return do
