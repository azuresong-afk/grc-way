"""Обновление справочника мер из API «Сканера»: адаптер, экран разницы, применение."""

import copy
import json
import shutil
from pathlib import Path

import httpx
import pytest
import yaml
from sqlalchemy import select

from app.core.config import Settings
from app.db.models import AuditRecord, RefCheck, RefGroup, RefMeasure, RefProfile, RefRevision
from app.integrations.scanner.client import (
    FIXTURES,
    FixtureScannerClient,
    LiveScannerClient,
    ScannerError,
    get_scanner_client,
)
from app.refs.loader import load_reference

REFERENCE = Path(__file__).resolve().parents[2] / "reference"
BASE = json.loads((FIXTURES / "compliance_profiles.json").read_text(encoding="utf-8"))


def _controls(payload, pid):
    return next(p for p in payload if p["id"] == pid)["controls"]


class FakeScanner:
    """Подмена клиента: отдаёт заданный ответ GET /compliance/profiles."""

    mode = "fixture"
    source = "тестовый «Сканер»"

    def __init__(self, payload=None, error: ScannerError | None = None):
        self.payload = copy.deepcopy(payload if payload is not None else BASE)
        self.error = error

    def compliance_profiles(self):
        if self.error:
            raise self.error
        from app.integrations.scanner.client import _parse_profiles

        return _parse_profiles(self.payload)


@pytest.fixture
def ref_dir(tmp_path) -> Path:
    shutil.copytree(REFERENCE / "profiles", tmp_path / "profiles")
    return tmp_path


@pytest.fixture
def scanner(client, session, ref_dir):
    load_reference(session, ref_dir)
    fake = FakeScanner()
    client.app.dependency_overrides[get_scanner_client] = lambda: fake
    return fake


@pytest.fixture
def admin(make_user, login):
    make_user("admin", "admin", display_name="Админ")
    return login("admin")


# --- адаптер ---------------------------------------------------------------


def test_fixture_matches_reference_profiles():
    """Фикстура — тот же каталог «Сканера» (коммит 01e035a), что и reference/profiles."""
    profiles = FixtureScannerClient().compliance_profiles()
    assert [p.id for p in profiles] == [
        "fstec-117",
        "fstec-21",
        "fstec-239",
        "cis-controls-v8",
        "cis-benchmark",
    ]
    assert sum(len(p.controls) for p in profiles) == 362
    p117 = profiles[0]
    iaf1 = next(c for c in p117.controls if c.id == "ИАФ.1")
    assert iaf1.group == "ИАФ" and "К2" in iaf1.levels and iaf1.checks
    assert all(cid in p117.checks for c in p117.controls for cid in c.checks)


def _live(handler, **over) -> LiveScannerClient:
    s = Settings(
        scanner_mode="live",
        scanner_url="http://scanner:8000/",
        scanner_username="grc-svc",
        scanner_password="pw-123456789012",  # noqa: S106 — тестовый пароль
        **over,
    )
    return LiveScannerClient(s, transport=httpx.MockTransport(handler))


def test_live_client_logs_in_and_reads_profiles():
    seen = []

    def handler(req: httpx.Request) -> httpx.Response:
        seen.append((req.method, req.url.path, req.headers.get("authorization")))
        if req.url.path == "/auth/token":
            assert json.loads(req.content) == {"username": "grc-svc", "password": "pw-123456789012"}
            return httpx.Response(200, json={"access_token": "tok", "expires_in": 60})
        return httpx.Response(200, json=BASE)

    profiles = _live(handler).compliance_profiles()
    assert len(profiles) == 5
    assert seen == [
        ("POST", "/auth/token", None),
        ("GET", "/compliance/profiles", "Bearer tok"),
    ]


def test_live_client_relogins_once_on_expired_token():
    tokens = iter(["old", "new"])
    calls = []

    def handler(req):
        if req.url.path == "/auth/token":
            return httpx.Response(200, json={"access_token": next(tokens), "expires_in": 60})
        calls.append(req.headers["authorization"])
        if req.headers["authorization"] == "Bearer old":
            return httpx.Response(401, json={"detail": "expired"})
        return httpx.Response(200, json=BASE)

    assert len(_live(handler).compliance_profiles()) == 5
    assert calls == ["Bearer old", "Bearer new"]


@pytest.mark.parametrize(
    ("handler", "code", "text"),
    [
        (lambda r: httpx.Response(401, json={}), "scanner_auth", "учётные данные"),
        (
            lambda r: (
                httpx.Response(200, json={"access_token": "t"})
                if r.url.path == "/auth/token"
                else httpx.Response(403, json={})
            ),
            "scanner_auth",
            "auditor",
        ),
        (
            lambda r: (
                httpx.Response(200, json={"access_token": "t"})
                if r.url.path == "/auth/token"
                else httpx.Response(200, json=[{"id": "x"}])
            ),
            "scanner_bad_response",
            "неожиданный ответ",
        ),
        (
            lambda r: (
                httpx.Response(200, json={"access_token": "t"})
                if r.url.path == "/auth/token"
                else httpx.Response(500, text="boom")
            ),
            "scanner_unavailable",
            "500",
        ),
    ],
)
def test_live_client_errors_are_readable(handler, code, text):
    with pytest.raises(ScannerError) as e:
        _live(handler).compliance_profiles()
    assert e.value.code == code and text in str(e.value)
    assert "pw-123456789012" not in str(e.value)


def test_live_client_network_error_and_missing_config():
    def boom(req):
        raise httpx.ConnectError("refused")

    with pytest.raises(ScannerError, match="Не удалось связаться"):
        _live(boom).compliance_profiles()
    with pytest.raises(ScannerError) as e:
        LiveScannerClient(Settings(scanner_mode="live")).compliance_profiles()
    assert e.value.code == "scanner_not_configured"


def test_live_client_uses_static_token_without_login():
    def handler(req):
        assert req.url.path == "/compliance/profiles"
        assert req.headers["authorization"] == "Bearer static"
        return httpx.Response(200, json=BASE)

    s = Settings(scanner_mode="live", scanner_url="http://s", scanner_token="static")  # noqa: S106
    assert LiveScannerClient(s, transport=httpx.MockTransport(handler)).compliance_profiles()


def test_bad_payload_rejected():
    dup = copy.deepcopy(BASE)
    dup[0]["controls"].append(dict(dup[0]["controls"][0]))
    with pytest.raises(ScannerError, match="повторяющиеся меры"):
        FakeScanner(dup).compliance_profiles()
    stray = copy.deepcopy(BASE)
    stray[0]["controls"][0]["group"] = "НЕТ"
    with pytest.raises(ScannerError, match="неизвестные группы"):
        FakeScanner(stray).compliance_profiles()


# --- экран разницы ---------------------------------------------------------


def test_same_catalog_gives_empty_diff(client, admin, scanner, session):
    r = client.post("/refs/profiles/scanner-diff", headers=admin)
    assert r.status_code == 201, r.text
    d = r.json()
    assert d["items"] == [] and d["summary"]["unchanged"] == 362
    assert d["summary"]["has_changes"] is False and d["status"] == "applied"
    src = client.get("/refs/scanner-source", headers=admin).json()
    assert src["last_synced_at"] and src["pending_diff_id"] is None


def _changed_payload():
    p = copy.deepcopy(BASE)
    c117 = _controls(p, "fstec-117")
    iaf1 = next(c for c in c117 if c["id"] == "ИАФ.1")
    iaf1["title"] = "Идентификация и аутентификация пользователей (ред.)"
    iaf1["levels"] = ["К1"]
    c117[:] = [c for c in c117 if c["id"] != "ИАФ.4"]
    c117.append(
        {
            "id": "ИАФ.9",
            "title": "Новая мера",
            "group": "ИАФ",
            "levels": ["К1"],
            "checks": ["new_check"],
            "manual": False,
        }
    )
    p[0]["checks"]["new_check"] = {"title": "Новая проверка", "platform": "linux"}
    p[0]["title"] = "Приказ ФСТЭК России №117 (ГИС), ред. 2"
    return p


def test_diff_shows_added_changed_removed(client, admin, scanner, session):
    scanner.payload = _changed_payload()
    d = client.post("/refs/profiles/scanner-diff", headers=admin).json()
    by_key = {i["key"]: i for i in d["items"]}
    assert set(by_key) == {"fstec-117:ИАФ.1", "fstec-117:ИАФ.4", "fstec-117:ИАФ.9"}
    upd = by_key["fstec-117:ИАФ.1"]
    assert upd["action"] == "update" and upd["default"] and not upd["conflict"]
    assert {f["field"] for f in upd["fields"]} == {"title", "levels"}
    lv = next(f for f in upd["fields"] if f["field"] == "levels")
    assert lv["before"] == ["К1", "К2", "К3"] and lv["after"] == ["К1"]
    assert by_key["fstec-117:ИАФ.4"]["action"] == "remove"
    assert by_key["fstec-117:ИАФ.9"]["action"] == "add"
    s = d["summary"]
    assert (s["add"], s["update"], s["remove"], s["conflict"]) == (1, 1, 1, 0)
    assert s["checks_added"] == 1 and s["profiles_changed"] == 1
    p117 = d["profiles"][0]
    assert p117["fields"][0]["field"] == "title"
    # Сравнение ничего не меняет.
    session.expire_all()
    assert session.get(RefMeasure, ("fstec-117", "ИАФ.1")).revision == 1
    assert session.get(RefMeasure, ("fstec-117", "ИАФ.9")) is None


def test_apply_writes_revisions_and_audit(client, admin, scanner, session):
    scanner.payload = _changed_payload()
    d = client.post("/refs/profiles/scanner-diff", headers=admin).json()
    r = client.post("/refs/profiles/scanner-apply", headers=admin, json={"diff_id": d["id"]})
    assert r.status_code == 200, r.text
    out = r.json()
    assert out["status"] == "applied" and out["applied_by_name"] == "Админ"
    assert out["applied"]["added"] == 1 and out["applied"]["updated"] == 1
    assert out["applied"]["removed"] == 1

    session.expire_all()
    m = session.get(RefMeasure, ("fstec-117", "ИАФ.1"))
    assert m.title.endswith("(ред.)") and m.levels == ["К1"] and m.revision == 2
    assert m.origin == "scanner" and m.verified_at is None
    new = session.get(RefMeasure, ("fstec-117", "ИАФ.9"))
    assert new.origin == "scanner" and new.verified_at is None and new.checks == ["new_check"]
    assert session.get(RefMeasure, ("fstec-117", "ИАФ.4")) is None
    assert session.get(RefCheck, "new_check").title == "Новая проверка"
    assert session.get(RefProfile, "fstec-117").title.endswith("ред. 2")
    assert session.get(RefProfile, "fstec-117").scanner_synced_at is not None
    revs = session.scalars(select(RefRevision).order_by(RefRevision.id)).all()
    assert {r.entity_key for r in revs} == {"fstec-117:ИАФ.1", "fstec-117:ИАФ.4"}
    removed = next(r for r in revs if r.entity_key == "fstec-117:ИАФ.4")
    assert removed.comment.startswith("Удалена") and removed.changed_by_name == "Админ"
    actions = session.scalars(select(AuditRecord.action).order_by(AuditRecord.id)).all()
    assert actions[-2:] == ["refs.scanner.diff", "refs.scanner.apply"]

    # Повторное применение и повторное сравнение.
    again = client.post("/refs/profiles/scanner-apply", headers=admin, json={"diff_id": d["id"]})
    assert again.status_code == 409
    d2 = client.post("/refs/profiles/scanner-diff", headers=admin).json()
    assert d2["items"] == []


def test_restart_does_not_roll_back_sync(client, admin, scanner, session, ref_dir):
    scanner.payload = _changed_payload()
    d = client.post("/refs/profiles/scanner-diff", headers=admin).json()
    client.post("/refs/profiles/scanner-apply", headers=admin, json={"diff_id": d["id"]})
    session.expire_all()
    load_reference(session, ref_dir)  # как при перезапуске контейнера
    session.expire_all()
    assert session.get(RefMeasure, ("fstec-117", "ИАФ.1")).title.endswith("(ред.)")
    assert session.get(RefMeasure, ("fstec-117", "ИАФ.4")) is None
    assert session.get(RefCheck, "new_check") is not None


def test_local_edit_is_conflict_and_needs_explicit_choice(client, admin, scanner, session):
    client.patch(
        "/refs/measures/fstec-117/ИАФ.1",
        headers=admin,
        json={"title": "Своя формулировка", "comment": "по тексту приказа"},
    )
    scanner.payload = _changed_payload()
    d = client.post("/refs/profiles/scanner-diff", headers=admin).json()
    item = next(i for i in d["items"] if i["key"] == "fstec-117:ИАФ.1")
    assert item["conflict"] and not item["default"] and item["origin"] == "local"
    assert d["summary"]["conflict"] == 1

    # По умолчанию конфликт не применяется.
    out = client.post(
        "/refs/profiles/scanner-apply", headers=admin, json={"diff_id": d["id"]}
    ).json()
    assert out["applied"]["skipped"] == 1 and out["applied"]["conflicts_applied"] == 0
    session.expire_all()
    assert session.get(RefMeasure, ("fstec-117", "ИАФ.1")).title == "Своя формулировка"

    # Явный выбор — правка из интерфейса заменяется версией «Сканера», остаётся в истории.
    d2 = client.post("/refs/profiles/scanner-diff", headers=admin).json()
    assert [i["key"] for i in d2["items"]] == ["fstec-117:ИАФ.1"]
    out = client.post(
        "/refs/profiles/scanner-apply",
        headers=admin,
        json={"diff_id": d2["id"], "selected": ["fstec-117:ИАФ.1"]},
    ).json()
    assert out["applied"]["conflicts_applied"] == 1
    session.expire_all()
    m = session.get(RefMeasure, ("fstec-117", "ИАФ.1"))
    assert m.origin == "scanner" and m.revision == 3
    last = session.scalars(
        select(RefRevision)
        .where(RefRevision.entity_key == "fstec-117:ИАФ.1")
        .order_by(RefRevision.id.desc())
    ).first()
    assert last.data["title"] == "Своя формулировка"


def test_selection_skips_unchecked_items(client, admin, scanner, session):
    scanner.payload = _changed_payload()
    d = client.post("/refs/profiles/scanner-diff", headers=admin).json()
    out = client.post(
        "/refs/profiles/scanner-apply",
        headers=admin,
        json={"diff_id": d["id"], "selected": ["fstec-117:ИАФ.9"]},
    ).json()
    assert (out["applied"]["added"], out["applied"]["skipped"]) == (1, 2)
    session.expire_all()
    assert session.get(RefMeasure, ("fstec-117", "ИАФ.4")) is not None
    bad = client.post(
        "/refs/profiles/scanner-apply",
        headers=admin,
        json={"diff_id": d["id"], "selected": ["fstec-117:НЕТ"]},
    )
    assert bad.status_code == 409  # уже применено


def test_unknown_selection_rejected(client, admin, scanner):
    scanner.payload = _changed_payload()
    d = client.post("/refs/profiles/scanner-diff", headers=admin).json()
    bad = client.post(
        "/refs/profiles/scanner-apply",
        headers=admin,
        json={"diff_id": d["id"], "selected": ["fstec-117:НЕТ"]},
    )
    assert bad.status_code == 422


def test_stale_diff_is_rejected(client, admin, make_user, login, scanner, session):
    scanner.payload = _changed_payload()
    d = client.post("/refs/profiles/scanner-diff", headers=admin).json()
    # Пока админ смотрел разницу, методист сверил меру из сравнения.
    make_user("m", "methodologist")
    r = client.post(
        "/refs/measures/fstec-117/ИАФ.1/verify", headers=login("m"), json={"revision": 1}
    )
    assert r.status_code == 200
    stale = client.post("/refs/profiles/scanner-apply", headers=admin, json={"diff_id": d["id"]})
    assert stale.status_code == 409 and "Сравните" in stale.json()["detail"]

    # Новое сравнение отмечает сверенную меру и вытесняет старое.
    d2 = client.post("/refs/profiles/scanner-diff", headers=admin).json()
    assert next(i for i in d2["items"] if i["key"] == "fstec-117:ИАФ.1")["verified"]
    assert d2["summary"]["verified_affected"] == 1
    old = client.get(f"/refs/scanner-diffs/{d['id']}", headers=admin).json()
    assert old["status"] == "superseded"
    assert (
        client.post(
            "/refs/profiles/scanner-apply", headers=admin, json={"diff_id": d["id"]}
        ).status_code
        == 409
    )
    assert [x["id"] for x in client.get("/refs/scanner-diffs", headers=admin).json()] == [
        d2["id"],
        d["id"],
    ]


def test_new_profile_and_groups(client, admin, scanner, session):
    p = copy.deepcopy(BASE)
    p.append(
        {
            "id": "gost-57580",
            "title": "ГОСТ Р 57580.1",
            "short": "ГОСТ 57580",
            "document": None,
            "url": None,
            "level_label": "Уровень",
            "levels": ["1", "2", "3"],
            "default_level": "2",
            "dynamic": None,
            "groups": [{"code": "УЗП", "title": "Управление защитой"}],
            "controls": [
                {"id": "УЗП.1", "title": "Мера", "group": "УЗП", "levels": ["1"], "checks": []}
            ],
            "checks": {},
        }
    )
    # Группа ИАФ переименована.
    grp = p[0]["groups"][1]
    assert grp["code"] == "ИАФ"
    old_title, grp["title"] = grp["title"], "Идентификация (ред.)"
    scanner.payload = p
    d = client.post("/refs/profiles/scanner-diff", headers=admin).json()
    assert d["summary"]["profiles_new"] == 1 and d["summary"]["add"] == 1
    assert d["profiles"][0]["groups"] == [
        {"code": "ИАФ", "action": "update", "before": old_title, "after": "Идентификация (ред.)"}
    ]
    client.post("/refs/profiles/scanner-apply", headers=admin, json={"diff_id": d["id"]})
    session.expire_all()
    assert session.get(RefProfile, "gost-57580").levels == ["1", "2", "3"]
    assert session.get(RefGroup, ("fstec-117", "ИАФ")).title == "Идентификация (ред.)"
    profiles = client.get("/refs/profiles", headers=admin).json()
    assert profiles[-1]["id"] == "gost-57580" and profiles[-1]["total"] == 1


def test_missing_profile_is_reported_not_deleted(client, admin, scanner, session):
    scanner.payload = [x for x in BASE if x["id"] != "fstec-239"]
    d = client.post("/refs/profiles/scanner-diff", headers=admin).json()
    missing = [x for x in d["profiles"] if x["status"] == "missing"]
    assert [x["id"] for x in missing] == ["fstec-239"]
    assert d["summary"]["profiles_missing"] == 1 and d["summary"]["remove"] == 0


def test_permissions_and_scanner_errors(client, admin, make_user, login, scanner, session):
    make_user("m", "methodologist")
    hm = login("m")
    assert client.post("/refs/profiles/scanner-diff", headers=hm).status_code == 403
    assert client.get("/refs/scanner-diffs", headers=hm).status_code == 200

    scanner.error = ScannerError("Не удалось связаться со «Сканером»: ConnectError")
    r = client.post("/refs/profiles/scanner-diff", headers=admin)
    assert r.status_code == 502 and "Сканер" in r.json()["detail"]
    err = session.scalars(
        select(AuditRecord).where(AuditRecord.action == "refs.scanner.diff")
    ).one()
    assert err.result == "error"


def test_yaml_file_change_still_applies_after_sync(client, admin, scanner, session, ref_dir):
    """Новая версия YAML в репозитории (другой хэш) по-прежнему загружается."""
    path = ref_dir / "profiles" / "fstec-117.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    data["groups"][1]["controls"][1]["title"] = "Из нового файла"
    path.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    report = load_reference(session, ref_dir)
    assert report.updated == 1
