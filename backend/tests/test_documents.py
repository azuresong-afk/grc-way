"""Движок документов (задача 3.1): каталог, карта полей, DOCX, водяной знак, PDF, API."""

import io
import shutil
import zipfile
from pathlib import Path

import pytest
from sqlalchemy import select

from app.db.models import AuditRecord, GeneratedDocument
from app.docs_gen import catalog, fieldmap, render
from app.refs.loader import load_reference

ROOT = Path(__file__).resolve().parents[2]
REFERENCE = ROOT / "reference"
TEMPLATES = ROOT / "templates" / "docx"
GIS_K2 = {
    "damage_confidentiality": "medium",
    "damage_integrity": "low",
    "damage_availability": "low",
    "scale": "regional",
}
HAS_SOFFICE = shutil.which("soffice") is not None


def _xml(docx: bytes) -> str:
    with zipfile.ZipFile(io.BytesIO(docx)) as z:
        return "".join(
            z.read(n).decode() for n in z.namelist() if n.startswith("word/") and n.endswith(".xml")
        )


# ---------- Каталог и шаблоны ----------


def _sample_context() -> dict:
    """Контекст с полным набором ключей (как из context.build)."""
    return {
        "customer": {"name": "ГБУ", "inn": None, "ogrn": None, "address": None},
        "project": {"name": "П", "contract_ref": None, "period_from": None, "period_to": None},
        "object": {
            "name": "ГИС",
            "kind": "gis",
            "kind_title": "ГИС",
            "regime": "117",
            "regime_title": "№117",
            "purpose": None,
            "boundaries": "",
            "internet_title": "нет",
            "responsible": [],
            "interconnections": [],
        },
        "classification": {},
        "segments": [],
        "hosts": [
            {
                "address": "10.0.0.1",
                "hostname": "a",
                "role": None,
                "os": "Astra",
                "segment": None,
                "source_title": "вручную",
                "internet_title": None,
            },
            {
                "address": "10.0.0.2",
                "hostname": None,
                "role": None,
                "os": "Astra",
                "segment": None,
                "source_title": "вручную",
                "internet_title": None,
            },
        ],
        "szi": [],
        "unverified": [],
    }


def test_catalog_fields_and_templates_match():
    docs = catalog.load(REFERENCE)
    assert "tech-passport" in docs
    ctx = _sample_context()
    for doc in docs.values():
        tpl = TEMPLATES / doc.template
        assert tpl.is_file(), f"нет шаблона {doc.template}"
        # Шаблон использует только то, что есть в контексте.
        assert render.template_variables(tpl) <= set(ctx) | {"doc", "empty"}
        for f in doc.fields:
            head = f.key.split("[]")[0].split(".")[0]
            assert head in ctx, f"{doc.code}: {f.key} нет в контексте"


def test_catalog_rejects_mistakes():
    good = {"key": "object.name", "title": "Т", "source": "И", "tab": "description"}
    with pytest.raises(catalog.CatalogError, match="вкладка"):
        catalog.parse({"documents": [{"code": "a", "title": "A", "template": "a.docx",
                                      "fields": [good | {"tab": "nowhere"}]}]})  # fmt: skip
    with pytest.raises(catalog.CatalogError, match="не описан список"):
        catalog.parse({"documents": [{"code": "a", "title": "A", "template": "a.docx",
                                      "fields": [good | {"key": "hosts[].os"}]}]})  # fmt: skip
    with pytest.raises(catalog.CatalogError, match="дважды"):
        catalog.parse({"documents": [{"code": "a", "title": "A", "template": "a.docx",
                                      "fields": [good, good]}]})  # fmt: skip


def test_field_map_and_placeholders():
    doc = catalog.load(REFERENCE)["tech-passport"]
    ctx = _sample_context()
    states = {s.key: s for s in fieldmap.field_map(ctx, doc)}
    assert states["object.name"].state == "filled" and states["object.name"].value == "ГИС"
    assert states["object.purpose"].state == "empty" and states["object.purpose"].required
    assert states["object.boundaries"].state == "empty"
    assert states["hosts"].state == "filled" and states["hosts"].value == "2 шт."
    assert states["hosts[].hostname"].state == "partial"
    assert (states["hosts[].hostname"].missing, states["hosts[].hostname"].total) == (1, 2)
    assert states["hosts[].hostname"].missing_examples == ["10.0.0.2"]
    assert states["hosts[].role"].state == "empty"
    assert states["szi[].cert_number"].state == "na"
    c = fieldmap.counts(list(states.values()))
    assert c["total"] == len(doc.fields) and c["required_empty"] >= 4

    filled = fieldmap.fill_placeholders(ctx, doc)
    assert filled["object"]["purpose"] == "[не заполнено: Назначение]"
    assert filled["classification"]["result_label"].startswith("[не заполнено")
    assert filled["hosts"][1]["hostname"] == fieldmap.MISSING_ITEM
    assert filled["hosts"][0]["hostname"] == "a"
    assert filled["szi"] == [] and filled["empty"]["szi"].startswith("[не заполнено")
    assert filled["empty"]["object"]["responsible"].startswith("[не заполнено")
    assert ctx["object"]["purpose"] is None  # исходный контекст не меняется


def test_render_escapes_values_and_adds_watermark():
    doc = catalog.load(REFERENCE)["tech-passport"]
    ctx = _sample_context()
    ctx["object"]["purpose"] = "<w:p>опасно</w:p> & {{ 7*7 }}\nвторая строка"
    filled = fieldmap.fill_placeholders(ctx, doc)
    filled["doc"] = {"title": doc.title, "version": 1, "generated": "05.11.2026",
                     "status_title": "Проект"}  # fmt: skip
    xml = _xml(render.render(TEMPLATES / doc.template, filled, watermark=True))
    assert "&lt;w:p&gt;опасно&lt;/w:p&gt; &amp; {{ 7*7 }}" in xml
    assert "<w:br/>" in xml  # перевод строки — разрыв строки, а не склейка
    assert 'string="ПРОЕКТ"' in xml and "PowerPlusWaterMarkObject" in xml
    assert "[не заполнено: Границы объекта]" in xml and "{%" not in xml
    plain = _xml(render.render(TEMPLATES / doc.template, filled, watermark=False))
    assert "PowerPlusWaterMarkObject" not in plain


# ---------- API ----------


@pytest.fixture
def docs_dir(tmp_path, monkeypatch):
    from app.core.config import get_settings

    d = tmp_path / "documents"
    monkeypatch.setenv("GRC_DOCUMENTS_DIR", str(d))
    monkeypatch.setenv("GRC_PDF_CONVERTER", "none")
    get_settings.cache_clear()
    return d


@pytest.fixture
def env(client, make_user, login, session, tmp_path, docs_dir):
    shutil.copytree(REFERENCE / "classification", tmp_path / "ref" / "classification")
    (tmp_path / "ref" / "profiles").mkdir()
    load_reference(session, tmp_path / "ref")
    make_user("meth", "methodologist", display_name="Иванова А. А.")
    make_user("boss", "viewer", "approve", display_name="Смирнов С. С.")
    make_user("expert", "assessor", display_name="Эксперт")
    make_user("viewer", "viewer", display_name="Наблюдатель")
    h = {u: login(u) for u in ("meth", "boss", "expert", "viewer")}
    c = client.post(
        "/customers", headers=h["meth"], json={"name": "ГБУ «Центр»", "inn": "7701234567"}
    ).json()
    p = client.post(
        "/projects", headers=h["meth"], json={"customer_id": c["id"], "name": "Аттестация"}
    ).json()
    users = client.get("/directory/users", headers=h["meth"]).json()
    client.put(
        f"/projects/{p['id']}/members",
        headers=h["meth"],
        json={"user_ids": [u["id"] for u in users]},
    )
    o = client.post(
        f"/projects/{p['id']}/objects",
        headers=h["meth"],
        json={"kind": "gis", "name": "ГИС «Услуги»", "purpose": "Приём заявлений <b>"},
    ).json()
    r = client.put(
        f"/objects/{o['id']}/hosts",
        headers=h["meth"],
        json={
            "items": [
                {"address": "10.0.0.1", "hostname": "web", "role": "Веб-сервер"},
                {"address": "10.0.0.2"},
            ]
        },
    )
    assert r.status_code == 200, r.text
    return h, o, p


def _gen(client, h, oid):
    r = client.post(f"/objects/{oid}/documents", headers=h, json={"type": "tech-passport"})
    assert r.status_code == 201, r.text
    return r.json()


def test_list_shows_map_before_generation(client, env):
    h, o, _ = env
    r = client.get(f"/objects/{o['id']}/documents", headers=h["meth"])
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["can_edit"] and body["sees_drafts"] and body["pdf_available"] is False
    (t,) = body["types"]
    assert t["code"] == "tech-passport" and t["template_found"]
    assert t["latest"] is None and t["changed"] and t["counts"]["required_empty"] > 0
    assert t["watermark_reasons"] == ["Документ не утверждён"]

    d = client.get(f"/objects/{o['id']}/documents/types/tech-passport", headers=h["meth"]).json()
    f = {x["key"]: x for x in d["fields"]}
    assert f["object.purpose"]["state"] == "filled"
    assert (
        f["object.boundaries"]["state"] == "empty"
        and f["object.boundaries"]["tab"] == "description"
    )
    assert f["hosts[].os"]["state"] == "empty" and f["hosts[].os"]["missing"] == 2
    assert f["hosts[].role"]["missing_examples"] == ["10.0.0.2"]
    assert f["customer.inn"]["value"] == "7701234567"
    assert client.get(
        f"/objects/{o['id']}/documents/types/nope", headers=h["meth"]
    ).status_code == 404  # fmt: skip


def test_generate_versions_and_download(client, env, session, docs_dir):
    h, o, _ = env
    d1 = _gen(client, h["meth"], o["id"])
    assert d1["created"] and d1["version"] == 1 and d1["status"] == "draft"
    assert d1["watermark"] and d1["status_title"] == "Проект"
    assert d1["pdf_size"] is None and "LibreOffice" in d1["pdf_error"]
    assert (
        docs_dir / session.get(GeneratedDocument, __import__("uuid").UUID(d1["id"])).docx_sha256
    ).is_file()

    # Те же данные — та же версия, без дубля.
    again = _gen(client, h["meth"], o["id"])
    assert not again["created"] and again["id"] == d1["id"]

    # Данные изменились — новая версия; первая сохранила свою карту.
    r = client.patch(f"/objects/{o['id']}", headers=h["meth"], json={"boundaries": "Здание 1"})
    assert r.status_code == 200, r.text
    lst = client.get(f"/objects/{o['id']}/documents", headers=h["meth"]).json()["types"][0]
    assert lst["changed"] and lst["latest"]["version"] == 1
    d2 = _gen(client, h["meth"], o["id"])
    assert d2["created"] and d2["version"] == 2
    f1 = {
        x["key"]: x
        for x in client.get(f"/documents/{d1['id']}", headers=h["meth"]).json()["fields"]
    }
    f2 = {x["key"]: x for x in d2["fields"]}
    assert (
        f1["object.boundaries"]["state"] == "empty" and f2["object.boundaries"]["state"] == "filled"
    )
    lst = client.get(f"/objects/{o['id']}/documents", headers=h["meth"]).json()["types"][0]
    assert not lst["changed"] and [v["version"] for v in lst["versions"]] == [2, 1]

    r = client.get(f"/documents/{d2['id']}/file?format=docx", headers=h["expert"])
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/vnd.openxmlformats")
    assert "attachment" in r.headers["content-disposition"]
    assert r.headers["x-content-type-options"] == "nosniff"
    xml = _xml(r.content)
    assert "ГИС «Услуги»" in xml and "Здание 1" in xml and "Приём заявлений &lt;b&gt;" in xml
    assert "[не заполнено: Средства защиты информации]" in xml
    assert 'string="ПРОЕКТ"' in xml
    assert (
        client.get(f"/documents/{d2['id']}/file?format=pdf", headers=h["meth"]).status_code == 404
    )

    actions = session.scalars(
        select(AuditRecord.action).where(AuditRecord.action.like("documents.%"))
    ).all()
    assert actions.count("documents.generate") == 2 and "documents.download" in actions


def test_permissions_and_drafts(client, env):
    h, o, _ = env
    d = _gen(client, h["meth"], o["id"])
    # Эксперт видит проекты, но не формирует.
    assert client.get(f"/documents/{d['id']}", headers=h["expert"]).status_code == 200
    r = client.post(
        f"/objects/{o['id']}/documents", headers=h["expert"], json={"type": "tech-passport"}
    )
    assert r.status_code == 403
    # Наблюдатель — только утверждённые: проектов не видит.
    body = client.get(f"/objects/{o['id']}/documents", headers=h["viewer"]).json()
    assert not body["sees_drafts"] and body["types"][0]["versions"] == []
    assert client.get(f"/documents/{d['id']}", headers=h["viewer"]).status_code == 404
    assert client.get(f"/documents/{d['id']}/file", headers=h["viewer"]).status_code == 404
    # Утверждающий видит проекты (ему их согласовывать в 3.3).
    assert client.get(f"/documents/{d['id']}", headers=h["boss"]).status_code == 200


def test_unverified_classification_goes_to_document(client, env):
    h, o, _ = env
    c = client.post(
        f"/objects/{o['id']}/classifications", headers=h["meth"], json={"inputs": GIS_K2}
    ).json()
    r = client.post(
        f"/classifications/{c['id']}/approve",
        headers=h["boss"],
        json={"acknowledge_unverified": True},
    )
    assert r.status_code == 200, r.text
    d = _gen(client, h["meth"], o["id"])
    f = {x["key"]: x for x in d["fields"]}
    assert f["classification.result_label"]["state"] == "filled"
    assert d["unverified"] and "Таблица классификации" in d["unverified"][0]["title"]
    assert d["watermark_reasons"] == [
        "Документ не утверждён",
        "Использованы записи справочников, не сверенные методистом",
    ]
    xml = _xml(client.get(f"/documents/{d['id']}/file", headers=h["meth"]).content)
    assert "не сверенные методистом" in xml and r.json()["result_label"] in xml


def test_archived_object_is_read_only(client, env):
    h, o, _ = env
    client.patch(f"/objects/{o['id']}", headers=h["meth"], json={"status": "archived"})
    r = client.post(
        f"/objects/{o['id']}/documents", headers=h["meth"], json={"type": "tech-passport"}
    )
    assert r.status_code == 409


@pytest.mark.skipif(not HAS_SOFFICE, reason="LibreOffice не установлен")
def test_pdf_with_libreoffice(client, env, monkeypatch):
    from app.core.config import get_settings

    monkeypatch.setenv("GRC_PDF_CONVERTER", "soffice")
    get_settings.cache_clear()
    h, o, _ = env
    d = _gen(client, h["meth"], o["id"])
    assert d["pdf_error"] is None and d["pdf_size"] > 1000
    r = client.get(f"/documents/{d['id']}/file?format=pdf", headers=h["meth"])
    assert r.status_code == 200 and r.content.startswith(b"%PDF")
    assert r.headers["content-type"] == "application/pdf"
