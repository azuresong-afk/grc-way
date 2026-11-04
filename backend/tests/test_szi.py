"""СЗИ (задача 2.5): разбор реестра, сравнение и применение, СЗИ объекта, сроки, сводка."""

import shutil
from datetime import date, timedelta
from pathlib import Path

import pytest
from sqlalchemy import select

from app.db.models import AuditRecord, SziCert
from app.domain import szi
from app.integrations.bdu.xlsx import write_xlsx
from app.integrations.szi.sample import HEADER, registry_csv, registry_xlsx
from app.refs.loader import load_reference

REFERENCE = Path(__file__).resolve().parents[2] / "reference"
XLSX = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
GIS_K2 = {
    "damage_confidentiality": "medium",
    "damage_integrity": "low",
    "damage_availability": "low",
    "scale": "regional",
}


@pytest.fixture
def szi_dir(tmp_path, monkeypatch):
    from app.core.config import get_settings

    d = tmp_path / "szi"
    monkeypatch.setenv("GRC_SZI_DIR", str(d))
    get_settings.cache_clear()
    return d


def _file(tmp_path: Path, data: bytes, name: str) -> Path:
    p = tmp_path / name
    p.write_bytes(data)
    return p


# ---------- Разбор ----------


def test_value_helpers():
    assert szi.cert_number("№ 4512") == "4512"
    assert szi.cert_number("4512.0") == "4512"
    assert szi.cert_number("  ") is None
    assert szi.cert_number("0") is None
    assert szi.trust_level("Требования доверия(4), Требования к МЭ") == 4
    assert szi.trust_level("соответствует 2 уровню доверия") == 2
    assert szi.trust_level("УД 5, профиль") == 5
    assert szi.trust_level("Требования к СВТ(5)") is None
    assert szi.profiles("МЭ(А4. ИТ.МЭ.А4.ПЗ), САВЗ ИТ.САВЗ.Б4.ПЗ ИТ.МЭ.А4.ПЗ") == [
        "ИТ.МЭ.А4.ПЗ",
        "ИТ.САВЗ.Б4.ПЗ",
    ]
    assert szi.cert_status("Действие сертификата приостановлено") == "suspended"
    assert szi.cert_status("действие прекращено") == "terminated"
    assert szi.cert_status(None) == "active"
    assert szi.date_in("до 14.06.2027") == date(2027, 6, 14)
    assert szi.date_in("бессрочно") is None


def test_parse_xlsx_and_csv_give_same_records(tmp_path):
    today = date(2026, 11, 4)
    x = szi.parse_file(_file(tmp_path, registry_xlsx(1, today), "r.xlsx"), "xlsx")
    c = szi.parse_file(_file(tmp_path, registry_csv(1, today), "r.csv"), "csv")
    assert x.header_row == 3 and c.header_row == 2
    assert x.version == c.version == date(2026, 10, 5) and x.version_source == "title"
    assert not x.missing
    assert set(x.rows) == set(c.rows) == {"9901", "9902", "9903", "9904", "9905", "9906"}
    for k in x.rows:
        assert x.rows[k]["_hash"] == c.rows[k]["_hash"]
    r = x.rows["9902"]
    assert r["valid_to"] == today + timedelta(days=45)
    assert r["trust_level"] == 4 and r["profiles"] == ["ИТ.САВЗ.Б4.ПЗ", "ИТ.САВЗ.В4.ПЗ"]
    assert x.rows["9906"]["support_until"] == today - timedelta(days=60)
    # UTF-8 с BOM и запятой как разделителем тоже читается.
    rows = [HEADER, ["7", "01.02.2020", "01.02.2030", "Средство, версия 1", "УД 4"]]
    import csv
    import io

    buf = io.StringIO()
    csv.writer(buf).writerows(rows)
    p = szi.parse_file(_file(tmp_path, b"\xef\xbb\xbf" + buf.getvalue().encode(), "u.csv"), "csv")
    assert p.rows["7"]["name"] == "Средство, версия 1" and p.rows["7"]["trust_level"] == 4


def test_parse_rejects_and_skips(tmp_path):
    with pytest.raises(szi.SziFormatError, match="заголовков"):
        szi.parse_file(_file(tmp_path, write_xlsx([["a", "b"], ["1", "2"]]), "a.xlsx"), "xlsx")
    data = write_xlsx(
        [
            ["№ сертификата", "Наименование средства (шифр)"],
            ["", "без номера"],
            ["12", ""],
            ["13", "есть"],
            ["13", "повтор"],
        ]
    )
    p = szi.parse_file(_file(tmp_path, data, "b.xlsx"), "xlsx")
    assert list(p.rows) == ["13"] and p.rows["13"]["name"] == "повтор"
    assert p.skipped_count == 2 and p.duplicates == 1 and p.no_date == 1
    assert "Срок действия сертификата" in p.missing
    with pytest.raises(szi.SziFormatError, match="нет ни одной"):
        szi.parse_file(
            _file(tmp_path, write_xlsx([["№ сертификата", "Наименование средства"]]), "c.xlsx"),
            "xlsx",
        )


def test_cert_state_rules():
    today = date(2026, 11, 4)
    kw = {"manual_trust": None, "today": today, "expiry_days": 90}

    def st(**k):
        return szi.cert_state(**{**kw, **k}).state

    assert st(number=None, manual_valid_to=None, entry=None, registry_loaded=True) == "uncertified"
    assert (
        st(
            number="1",
            manual_valid_to=today + timedelta(days=200),
            entry=None,
            registry_loaded=False,
        )
        == "valid"
    )
    assert (
        st(
            number="1",
            manual_valid_to=today + timedelta(days=200),
            entry=None,
            registry_loaded=True,
        )
        == "not_found"
    )
    assert st(number="1", manual_valid_to=None, entry=None, registry_loaded=False) == "no_date"
    assert (
        st(number="1", manual_valid_to=today - timedelta(days=1), entry=None, registry_loaded=True)
        == "expired"
    )
    e = SziCert(
        cert_number="1", name="x", valid_to=today + timedelta(days=90), cert_status="active"
    )
    s = szi.cert_state(
        **kw, number="1", manual_valid_to=date(2030, 1, 1), entry=e, registry_loaded=True
    )
    assert s.state == "expiring" and s.valid_to_source == "registry" and s.days_left == 90
    assert "расходится с реестром" in s.notes[0]
    e.cert_status = "suspended"
    assert st(number="1", manual_valid_to=None, entry=e, registry_loaded=True) == "suspended"
    e.cert_status, e.valid_to, e.withdrawn_at = "active", date(2030, 1, 1), szi.utcnow()
    assert st(number="1", manual_valid_to=None, entry=e, registry_loaded=True) == "withdrawn"


# ---------- API ----------


@pytest.fixture
def env(client, make_user, login, session, tmp_path, szi_dir):
    shutil.copytree(REFERENCE, tmp_path / "reference")
    load_reference(session, tmp_path / "reference")
    make_user("admin", "admin")
    make_user("meth", "methodologist", display_name="Иванова А. А.")
    make_user("boss", "viewer", "approve", display_name="Смирнов С. С.")
    make_user("exp", "assessor", display_name="Козлов К. К.")
    make_user("viewer", "viewer", display_name="Наблюдатель")
    make_user("outsider", "methodologist")
    h = {u: login(u) for u in ("admin", "meth", "boss", "exp", "viewer", "outsider")}
    c = client.post("/customers", headers=h["meth"], json={"name": "ГБУ «Центр»"}).json()
    p = client.post(
        "/projects", headers=h["meth"], json={"customer_id": c["id"], "name": "Аттестация"}
    ).json()
    users = client.get("/directory/users", headers=h["meth"]).json()
    client.put(
        f"/projects/{p['id']}/members",
        headers=h["meth"],
        json={"user_ids": [u["id"] for u in users if u["display_name"] != "Outsider"]},
    )
    o = client.post(
        f"/projects/{p['id']}/objects", headers=h["meth"], json={"kind": "gis", "name": "ГИС"}
    ).json()
    return h, p, o


def _upload(client, h, data: bytes, name: str = "reestr.xlsx", **form):
    mime = XLSX if name.endswith(".xlsx") else "text/csv"
    return client.post(
        "/szi-registry/imports", headers=h, files={"file": (name, data, mime)}, data=form
    )


def _load_registry(client, h, revision=1):
    r = _upload(client, h["admin"], registry_xlsx(revision))
    assert r.status_code == 201, r.text
    imp = r.json()
    a = client.post(
        f"/szi-registry/imports/{imp['id']}/apply", headers=h["admin"], json={"ack_warnings": True}
    )
    assert a.status_code == 200, a.text
    return a.json()


def _build_measures(client, h, oid):
    c = client.post(f"/objects/{oid}/classifications", headers=h["meth"], json={"inputs": GIS_K2})
    r = client.post(
        f"/classifications/{c.json()['id']}/approve",
        headers=h["boss"],
        json={"acknowledge_unverified": True},
    )
    assert r.status_code == 200, r.text
    r = client.post(f"/objects/{oid}/measures/rebuild", headers=h["meth"], json={"dry_run": False})
    assert r.status_code == 200, r.text


def test_registry_import_diff_and_apply(client, env, session):
    h, _, _ = env
    # Загружать реестр может только администратор (refs.manage).
    assert _upload(client, h["meth"], registry_xlsx(1)).status_code == 403
    bad = _upload(client, h["admin"], b"%PDF-1.4", "r.pdf")
    assert bad.status_code == 422 and "XLSX или CSV" in bad.json()["detail"]
    notreg = _upload(client, h["admin"], write_xlsx([["a"], ["b"]]))
    assert notreg.status_code == 422 and "заголовков" in notreg.json()["detail"]

    r = _upload(client, h["admin"], registry_xlsx(1))
    assert r.status_code == 201, r.text
    imp = r.json()
    assert imp["status"] == "pending" and imp["summary"]["add"] == 6
    assert imp["export_version"] == (date.today() - timedelta(days=30)).isoformat()
    st = client.get("/szi-registry/status", headers=h["viewer"]).json()
    assert st["pending_id"] == imp["id"] and st["active"] == 0
    applied = client.post(
        f"/szi-registry/imports/{imp['id']}/apply", headers=h["admin"], json={}
    ).json()
    assert applied["status"] == "applied" and applied["applied"]["added"] == 6
    again = client.post(f"/szi-registry/imports/{imp['id']}/apply", headers=h["admin"], json={})
    assert again.status_code == 409

    # Вторая версия как CSV: продлён 9902, исключён 9903, добавлен 9907.
    r2 = _upload(client, h["admin"], registry_csv(2), "reestr.csv").json()
    s = r2["summary"]
    assert (s["add"], s["update"], s["withdraw"], s["validity"]) == (1, 1, 1, 1)
    first = r2["items"][0]
    assert first["key"] == "9902" and first["validity"] and "valid_to" in first["fields"]
    codes = [w["code"] for w in r2["warnings"]]
    assert codes == []
    a2 = client.post(f"/szi-registry/imports/{r2['id']}/apply", headers=h["admin"], json={})
    assert a2.json()["applied"] == {
        "added": 1,
        "updated": 1,
        "restored": 0,
        "withdrawn": 1,
        "validity": 1,
    }
    gone = session.get(SziCert, "9903")
    session.refresh(gone)
    assert gone.withdrawn_at is not None

    # Старый файл снова: предупреждение «старше» и возврат исключённого — только с подтверждением.
    r3 = _upload(client, h["admin"], registry_xlsx(1)).json()
    assert "older" in [w["code"] for w in r3["warnings"]] and r3["summary"]["restore"] == 1
    no_ack = client.post(f"/szi-registry/imports/{r3['id']}/apply", headers=h["admin"], json={})
    assert no_ack.status_code == 409

    # Просмотр реестра: поиск, фильтр по сроку, исключённые, карточка.
    lst = client.get("/szi-registry", headers=h["viewer"], params={"q": "АВЗ"})
    assert [c["cert_number"] for c in lst.json()] == ["9902"]
    assert (
        client.get("/szi-registry", headers=h["viewer"], params={"q": "№9901"}).json()[0][
            "cert_number"
        ]
        == "9901"
    )
    wd = client.get("/szi-registry", headers=h["viewer"], params={"withdrawn": True}).json()
    assert [c["cert_number"] for c in wd] == ["9903"]
    card = client.get("/szi-registry/9906", headers=h["viewer"]).json()
    assert card["trust_level"] == 2 and card["profiles"] == ["ИТ.ОС.А2.ПЗ"]
    assert client.get("/szi-registry/1", headers=h["viewer"]).status_code == 404

    actions = set(session.scalars(select(AuditRecord.action)))
    assert {"szi.import.diff", "szi.import.apply", "szi.import.rejected"} <= actions


def test_object_szi_states_measures_and_summary(client, env, session):
    h, p, o = env
    oid = o["id"]
    url = f"/objects/{oid}/szi"
    # Без набора мер привязать меру нельзя.
    r = client.post(
        url, headers=h["meth"], json={"name": "МЭ", "kind": "fw", "measure_ids": ["ЗИС.1"]}
    )
    assert r.status_code == 422 and "набор мер" in r.json()["detail"]
    _build_measures(client, h, oid)
    measures = {
        m["measure_id"] for m in client.get(f"/objects/{oid}/measures", headers=h["meth"]).json()
    }
    mid = sorted(measures)[0]

    # Реестр ещё не загружен: срок — введённый вручную, сверить не с чем.
    r = client.post(
        url,
        headers=h["meth"],
        json={
            "name": "Пример-МЭ",
            "kind": "fw",
            "cert_number": "№ 9901",
            "cert_valid_to": (date.today() + timedelta(days=30)).isoformat(),
            "measure_ids": [mid, mid],
        },
    )
    assert r.status_code == 201, r.text
    fw = r.json()
    assert fw["cert_number"] == "9901" and fw["measure_ids"] == [mid]
    assert fw["state"] == "expiring" and fw["registry_match"] == "not_loaded"
    assert fw["valid_to_source"] == "manual"

    _load_registry(client, h)
    for name, number, kind in [
        ("Пример-АВЗ", "9902", "av"),
        ("Пример-НСД", "9903", "nsd"),
        ("Пример-ОС", "9906", "os"),
        ("Самописный фильтр", None, "other"),
        ("Неизвестный МЭ", "12345", "fw"),
    ]:
        body = {"name": name, "kind": kind, "cert_number": number, "measure_ids": [mid]}
        assert client.post(url, headers=h["meth"], json=body).status_code == 201
    out = client.get(url, headers=h["viewer"]).json()
    by = {i["name"]: i for i in out["items"]}
    # Срок из реестра важнее введённого: 9901 действует ещё ~700 дней.
    assert by["Пример-МЭ"]["state"] == "valid" and by["Пример-МЭ"]["valid_to_source"] == "registry"
    assert "расходится с реестром" in by["Пример-МЭ"]["notes"][0]
    assert by["Пример-МЭ"]["effective_trust_level"] == 4
    assert by["Пример-АВЗ"]["state"] == "expiring" and by["Пример-АВЗ"]["days_left"] == 45
    assert by["Пример-НСД"]["state"] == "expired" and by["Пример-НСД"]["level"] == "bad"
    assert by["Пример-ОС"]["support_ended"] and by["Пример-ОС"]["trust_level"] == 2
    assert by["Самописный фильтр"]["state"] == "uncertified"
    assert by["Неизвестный МЭ"]["state"] == "not_found"
    assert out["counts"] == {"total": 6, "bad": 1, "expiring": 1, "check": 1, "uncertified": 1}
    # Сначала худшие.
    assert out["items"][0]["name"] == "Пример-НСД"

    # Шторка меры: только СЗИ, закрывающие эту меру.
    assert len(client.get(url, headers=h["exp"], params={"measure_id": mid}).json()["items"]) == 6
    assert client.get(url, headers=h["exp"], params={"measure_id": "НЕТ.1"}).json()["items"] == []

    # Вторая версия реестра: 9903 исключён (истёкший остаётся истёкшим), 9902 продлён.
    _load_registry(client, h, 2)
    by = {i["name"]: i for i in client.get(url, headers=h["viewer"]).json()["items"]}
    assert by["Пример-АВЗ"]["state"] == "valid"
    assert (
        by["Пример-НСД"]["state"] == "expired" and by["Пример-НСД"]["registry_match"] == "withdrawn"
    )

    # Правка: другая мера не из набора — отказ; снятие привязки и сертификата — можно.
    nsd = by["Пример-НСД"]["id"]
    bad = client.patch(f"/object-szi/{nsd}", headers=h["meth"], json={"measure_ids": ["НЕТ.1"]})
    assert bad.status_code == 422
    ok = client.patch(
        f"/object-szi/{nsd}", headers=h["meth"], json={"cert_number": "9904", "measure_ids": []}
    )
    assert ok.status_code == 200 and ok.json()["state"] == "valid" and ok.json()["measures"] == []
    assert (
        client.patch(f"/object-szi/{nsd}", headers=h["meth"], json={"name": None}).status_code
        == 422
    )
    assert (
        client.patch(
            f"/object-szi/{nsd}", headers=h["meth"], json={"cert_number": "абв"}
        ).status_code
        == 422
    )

    # Права: эксперт и наблюдатель только смотрят; чужой проект не виден.
    assert client.post(url, headers=h["exp"], json={"name": "x"}).status_code == 403
    assert client.delete(f"/object-szi/{nsd}", headers=h["viewer"]).status_code == 403
    assert client.get(url, headers=h["outsider"]).status_code == 404
    assert client.patch(f"/object-szi/{nsd}", headers=h["outsider"], json={}).status_code == 404

    # Сводка проекта: истёкшие и истекающие сертификаты.
    sm = client.get(f"/projects/{p['id']}/summary", headers=h["viewer"]).json()
    assert sm["kpi"]["szi"] == {"total": 6, "bad": 0, "expiring": 0, "check": 1, "uncertified": 1}
    assert sm["kpi"]["szi_expiry_days"] == 90
    assert sm["objects"][0]["szi"]["total"] == 6

    assert client.delete(f"/object-szi/{nsd}", headers=h["meth"]).status_code == 204
    assert len(client.get(url, headers=h["viewer"]).json()["items"]) == 5
    actions = [a for a in session.scalars(select(AuditRecord.action)) if a.startswith("szi.")]
    assert {"szi.create", "szi.update", "szi.delete"} <= set(actions)


def test_archived_object_szi_read_only(client, env):
    h, _, o = env
    client.patch(f"/objects/{o['id']}", headers=h["meth"], json={"status": "archived"})
    r = client.post(f"/objects/{o['id']}/szi", headers=h["meth"], json={"name": "x"})
    assert r.status_code == 409
