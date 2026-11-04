"""Объекты проекта: описание, сегменты, хосты, синхронизация с активами «Сканера»."""

import copy
import json

import httpx
import pytest
from sqlalchemy import select

from app.core.config import Settings
from app.db.models import AuditRecord, ObjectHost
from app.integrations.scanner.client import (
    FIXTURES,
    FixtureScannerClient,
    LiveScannerClient,
    ScannerError,
    _parse_assets,
    get_scanner_client,
)

ASSETS = json.loads((FIXTURES / "engagement_assets.json").read_text(encoding="utf-8"))


class FakeScanner:
    mode = "fixture"
    source = "тестовый «Сканер»"

    def __init__(self):
        self.payload = copy.deepcopy(ASSETS)
        self.error: ScannerError | None = None
        self.calls: list[int] = []

    def assets(self, engagement_id):
        self.calls.append(engagement_id)
        if self.error:
            raise self.error
        return _parse_assets(self.payload, engagement_id)


@pytest.fixture
def scanner(client):
    fake = FakeScanner()
    client.app.dependency_overrides[get_scanner_client] = lambda: fake
    yield fake
    client.app.dependency_overrides.clear()


@pytest.fixture
def setup(client, make_user, login):
    make_user("meth", "methodologist", display_name="Иванова А. А.")
    make_user("expert", "assessor", display_name="Сидоров С. С.")
    make_user("outsider", "methodologist")
    h = login("meth")
    c = client.post("/customers", headers=h, json={"name": "ГБУ «Центр»"}).json()
    p = client.post(
        "/projects",
        headers=h,
        json={"customer_id": c["id"], "name": "Аттестация ГИС", "scanner_engagement_id": 7},
    ).json()
    expert_id = client.get("/directory/users", headers=h).json()
    ids = [u["id"] for u in expert_id if u["display_name"] != "Outsider"]
    r = client.put(f"/projects/{p['id']}/members", headers=h, json={"user_ids": ids})
    assert r.status_code == 200, r.text
    return h, p


def _object(client, h, project_id, **extra):
    body = {"kind": "gis", "name": "ГИС «Учёт»", **extra}
    r = client.post(f"/projects/{project_id}/objects", headers=h, json=body)
    assert r.status_code == 201, r.text
    return r.json()


def test_create_object_defaults_regime_and_audits(client, setup, session):
    h, p = setup
    o = _object(
        client,
        h,
        p["id"],
        purpose="Учёт обращений граждан",
        internet=True,
        responsible=[{"name": "Петров П. П.", "role": "Администратор безопасности"}],
        interconnections=[{"system": "СМЭВ", "direction": "both"}],
    )
    assert o["regime"] == "117"
    assert o["status"] == "active"
    assert o["host_count"] == 0
    assert o["scanner_engagement_id"] == 7
    assert o["responsible"][0]["name"] == "Петров П. П."
    ispdn = _object(client, h, p["id"], kind="ispdn", name="ИСПДн «Кадры»")
    assert ispdn["regime"] == "21"
    other = _object(client, h, p["id"], kind="other", name="Портал")
    assert other["regime"] is None

    r = client.get(f"/projects/{p['id']}/objects", headers=h, params={"kind": "gis"})
    assert r.headers["X-Total-Count"] == "1"
    assert r.json()[0]["name"] == "ГИС «Учёт»"
    actions = session.scalars(select(AuditRecord.action)).all()
    assert actions.count("object.create") == 3


def test_regime_required_for_regulated_kinds(client, setup):
    h, p = setup
    r = client.post(
        f"/projects/{p['id']}/objects",
        headers=h,
        json={"kind": "kii", "name": "АСУ ТП", "regime": None},
    )
    assert r.status_code == 422
    assert "режим" in r.json()["detail"]


def test_kind_change_moves_default_regime(client, setup):
    h, p = setup
    o = _object(client, h, p["id"])
    r = client.patch(f"/objects/{o['id']}", headers=h, json={"kind": "kii"})
    assert r.status_code == 200
    assert r.json()["regime"] == "239"


def test_permissions_and_visibility(client, setup, login):
    h, p = setup
    o = _object(client, h, p["id"])
    he = login("expert")
    assert client.get(f"/objects/{o['id']}", headers=he).status_code == 200
    r = client.patch(f"/objects/{o['id']}", headers=he, json={"name": "x"})
    assert r.status_code == 403
    r = client.post(f"/projects/{p['id']}/objects", headers=he, json={"kind": "gis", "name": "x"})
    assert r.status_code == 403
    # Не участник проекта не видит объект, даже зная его id.
    ho = login("outsider")
    assert client.get(f"/objects/{o['id']}", headers=ho).status_code == 404
    assert client.get(f"/projects/{p['id']}/objects", headers=ho).status_code == 404


def test_segments_put_rename_and_remove_unassigns_hosts(client, setup):
    h, p = setup
    o = _object(client, h, p["id"])
    r = client.put(
        f"/objects/{o['id']}/segments",
        headers=h,
        json={"items": [{"name": "ЛВС"}, {"name": "ДМЗ", "scanner_group": "ДМЗ"}]},
    )
    assert r.status_code == 200, r.text
    lvs, dmz = r.json()
    r = client.put(
        f"/objects/{o['id']}/hosts",
        headers=h,
        json={
            "items": [
                {"address": "10.0.0.1", "segment_id": lvs["id"]},
                {"address": "10.0.0.2", "segment_id": dmz["id"]},
            ]
        },
    )
    assert r.status_code == 200, r.text
    r = client.put(
        f"/objects/{o['id']}/segments",
        headers=h,
        json={"items": [{"id": lvs["id"], "name": "ЛВС офиса"}]},
    )
    assert [s["name"] for s in r.json()] == ["ЛВС офиса"]
    assert r.json()[0]["host_count"] == 1
    hosts = client.get(f"/objects/{o['id']}/hosts", headers=h).json()
    assert {x["address"]: x["segment_id"] for x in hosts} == {
        "10.0.0.1": lvs["id"],
        "10.0.0.2": None,
    }
    dup = client.put(
        f"/objects/{o['id']}/segments",
        headers=h,
        json={"items": [{"name": "А"}, {"name": "а"}]},
    )
    assert dup.status_code == 422


def test_hosts_put_validates_and_normalizes(client, setup, session):
    h, p = setup
    o = _object(client, h, p["id"])
    bad = client.put(
        f"/objects/{o['id']}/hosts", headers=h, json={"items": [{"address": "srv-01"}]}
    )
    assert bad.status_code == 422
    dup = client.put(
        f"/objects/{o['id']}/hosts",
        headers=h,
        json={"items": [{"address": "10.0.0.1"}, {"address": " 10.0.0.1 "}]},
    )
    assert dup.status_code == 422
    assert "дважды" in dup.json()["detail"]
    r = client.put(
        f"/objects/{o['id']}/hosts",
        headers=h,
        json={
            "items": [
                {"address": "10.0.0.10", "hostname": "db", "role": "СУБД"},
                {"address": "10.0.0.9"},
                {"address": "2001:DB8::1"},
            ]
        },
    )
    assert r.status_code == 200, r.text
    assert [x["address"] for x in r.json()] == ["10.0.0.9", "10.0.0.10", "2001:db8::1"]
    assert all(x["source"] == "manual" for x in r.json())
    rec = session.scalars(select(AuditRecord).where(AuditRecord.action == "object.hosts")).one()
    assert rec.details["added"]["count"] == 3


def test_sync_adds_selected_assets_with_segments_by_group(client, setup, scanner):
    h, p = setup
    o = _object(client, h, p["id"])
    r = client.get(f"/objects/{o['id']}/scanner/assets", headers=h)
    assert r.status_code == 200, r.text
    assets = r.json()
    assert scanner.calls == [7]
    assert len(assets["assets"]) == 12
    gis = [a["address"] for a in assets["assets"] if "Бухгалтерия" not in a["groups"]]
    assert len(gis) == 10

    r = client.post(
        f"/objects/{o['id']}/hosts/sync-from-scanner", headers=h, json={"addresses": gis}
    )
    assert r.status_code == 200, r.text
    res = r.json()
    assert len(res["added"]) == 10
    assert sorted(res["segments_created"]) == ["АРМ пользователей", "ДМЗ", "Серверный сегмент"]
    db = next(x for x in res["hosts"] if x["address"] == "10.10.1.10")
    assert db["source"] == "scanner"
    assert db["hostname"] == "srv-db01.uchet.local"
    assert db["os"] == "Astra Linux SE 1.8"
    assert db["scanner_asset_id"] == 1
    assert db["segment_id"] is not None

    obj = client.get(f"/objects/{o['id']}", headers=h).json()
    assert obj["host_count"] == 10
    assert obj["scanner_synced_at"] is not None
    assert {s["name"]: s["host_count"] for s in obj["segments"]} == {
        "Серверный сегмент": 4,
        "ДМЗ": 2,
        "АРМ пользователей": 4,
    }
    marked = client.get(f"/objects/{o['id']}/scanner/assets", headers=h).json()["assets"]
    assert sum(a["in_object"] for a in marked) == 10


def test_sync_matches_manual_host_by_address_and_flags_missing(client, setup, scanner, session):
    h, p = setup
    o = _object(client, h, p["id"])
    client.put(
        f"/objects/{o['id']}/hosts",
        headers=h,
        json={"items": [{"address": "10.10.1.10", "hostname": "БД", "role": "СУБД"}]},
    )
    client.post(
        f"/objects/{o['id']}/hosts/sync-from-scanner",
        headers=h,
        json={"addresses": ["10.10.2.5"], "segments_from_groups": False},
    )
    hosts = {x["address"]: x for x in client.get(f"/objects/{o['id']}/hosts", headers=h).json()}
    manual = hosts["10.10.1.10"]
    # Ручной хост связан с активом, но его имя и роль — наши.
    assert manual["source"] == "manual"
    assert manual["scanner_asset_id"] == 1
    assert manual["hostname"] == "БД"
    assert manual["role"] == "СУБД"
    assert manual["os"] == "Astra Linux SE 1.8"
    assert hosts["10.10.2.5"]["segment_id"] is None

    # Актив пропал из «Сканера»: хост остаётся, но помечен.
    scanner.payload = [a for a in scanner.payload if a["address"] != "10.10.2.5"]
    r = client.post(f"/objects/{o['id']}/hosts/sync-from-scanner", headers=h, json={})
    assert r.status_code == 200
    assert r.json()["missing"] == ["10.10.2.5"]
    assert r.json()["updated"] == ["10.10.1.10"]
    gone = next(x for x in r.json()["hosts"] if x["address"] == "10.10.2.5")
    assert gone["scanner_missing"] is True
    assert session.scalar(select(ObjectHost).where(ObjectHost.address == "10.10.2.5"))


def test_put_hosts_keeps_scanner_fields(client, setup, scanner):
    h, p = setup
    o = _object(client, h, p["id"])
    client.post(
        f"/objects/{o['id']}/hosts/sync-from-scanner",
        headers=h,
        json={"addresses": ["10.10.1.10"]},
    )
    r = client.put(
        f"/objects/{o['id']}/hosts",
        headers=h,
        json={"items": [{"address": "10.10.1.10", "role": "СУБД"}, {"address": "10.9.9.9"}]},
    )
    hosts = {x["address"]: x for x in r.json()}
    assert hosts["10.10.1.10"]["source"] == "scanner"
    assert hosts["10.10.1.10"]["os"] == "Astra Linux SE 1.8"
    assert hosts["10.10.1.10"]["segment_id"] is None  # сегмент снят вместе с запросом
    assert hosts["10.9.9.9"]["source"] == "manual"


def test_same_address_in_other_object_is_shown(client, setup, scanner):
    h, p = setup
    a = _object(client, h, p["id"], name="ГИС А")
    b = _object(client, h, p["id"], name="ГИС Б")
    client.put(f"/objects/{a['id']}/hosts", headers=h, json={"items": [{"address": "10.10.1.10"}]})
    assets = client.get(f"/objects/{b['id']}/scanner/assets", headers=h).json()["assets"]
    db = next(x for x in assets if x["address"] == "10.10.1.10")
    assert db["other_objects"] == ["ГИС А"]
    assert db["in_object"] is False


def test_sync_rejects_unknown_address_and_unlinked_project(client, setup, scanner):
    h, p = setup
    o = _object(client, h, p["id"])
    r = client.post(
        f"/objects/{o['id']}/hosts/sync-from-scanner",
        headers=h,
        json={"addresses": ["192.0.2.1"]},
    )
    assert r.status_code == 422
    client.patch(f"/projects/{p['id']}", headers=h, json={"scanner_engagement_id": None})
    r = client.get(f"/objects/{o['id']}/scanner/assets", headers=h)
    assert r.status_code == 409
    assert r.headers["X-Error-Code"] == "scanner_not_linked"


def test_sync_scanner_error_is_reported_and_audited(client, setup, scanner, session):
    h, p = setup
    o = _object(client, h, p["id"])
    scanner.error = ScannerError("«Сканер» не ответил за 20 с")
    r = client.post(f"/objects/{o['id']}/hosts/sync-from-scanner", headers=h, json={})
    assert r.status_code == 502
    assert r.json()["detail"] == "«Сканер» не ответил за 20 с"
    rec = session.scalars(
        select(AuditRecord).where(AuditRecord.action == "object.hosts.sync")
    ).one()
    assert rec.result == "error"


def test_archived_object_and_project_are_read_only(client, setup):
    h, p = setup
    o = _object(client, h, p["id"])
    r = client.patch(f"/objects/{o['id']}", headers=h, json={"status": "archived"})
    assert r.json()["status"] == "archived"
    r = client.put(f"/objects/{o['id']}/hosts", headers=h, json={"items": [{"address": "1.1.1.1"}]})
    assert r.status_code == 409
    r = client.patch(f"/objects/{o['id']}", headers=h, json={"status": "active"})
    assert r.status_code == 200
    client.patch(f"/projects/{p['id']}", headers=h, json={"status": "archived"})
    r = client.post(f"/projects/{p['id']}/objects", headers=h, json={"kind": "gis", "name": "x"})
    assert r.status_code == 409
    r = client.patch(f"/objects/{o['id']}", headers=h, json={"name": "Новое"})
    assert r.status_code == 409


def test_fixture_client_returns_demo_assets():
    assets = FixtureScannerClient().assets(42)
    assert len(assets) == 12
    assert {a.engagement_id for a in assets} == {42}
    assert assets[0].groups[0].name == "Серверный сегмент"


def _live(handler):
    s = Settings(scanner_mode="live", scanner_url="http://s", scanner_token="static")  # noqa: S106
    return LiveScannerClient(s, transport=httpx.MockTransport(handler))


def test_live_client_reads_assets_and_maps_404():
    def ok(req: httpx.Request) -> httpx.Response:
        assert req.url.path == "/engagements/7/assets"
        assert req.headers["Authorization"] == "Bearer static"
        return httpx.Response(200, json=ASSETS[:2])

    assets = _live(ok).assets(7)
    assert [a.address for a in assets] == ["10.10.1.10", "10.10.1.11"]

    with pytest.raises(ScannerError) as e:
        _live(lambda req: httpx.Response(404, json={"detail": "engagement not found"})).assets(7)
    assert e.value.code == "scanner_not_found"
    assert "№7" in str(e.value)

    with pytest.raises(ScannerError) as e:
        _live(lambda req: httpx.Response(200, json=[{"id": "x"}])).assets(7)
    assert e.value.code == "scanner_bad_response"
