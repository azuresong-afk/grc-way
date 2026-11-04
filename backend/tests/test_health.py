import pytest
from fastapi.testclient import TestClient

from app.main import create_app


def test_live_and_ready():
    client = TestClient(create_app())
    assert client.get("/health/live").json() == {"status": "ok"}
    r = client.get("/health/ready")
    assert r.status_code == 200
    assert r.json()["db"] == "ok"


def test_manifest_matches_platform_contract():
    data = TestClient(create_app()).get("/manifest").json()
    assert data["id"] == "grc"
    assert data["title"] == "Аттестация"
    assert data["base_path"] == "/grc/"
    assert data["api_base"] == "/api/grc/"
    assert data["health_url"] == "/api/grc/health/ready"
    assert set(data["roles"]) == {"methodologist", "assessor", "viewer", "admin"}
    for item in data["nav"]:
        assert item["path"].startswith("/grc/")


def test_refuses_to_start_without_secret(monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setenv("GRC_DEV_MODE", "0")
    monkeypatch.setenv("GRC_SECRET_KEY", "")
    get_settings.cache_clear()
    try:
        with pytest.raises(RuntimeError, match="GRC_SECRET_KEY"):
            create_app()
    finally:
        get_settings.cache_clear()
